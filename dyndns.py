#!/usr/bin/env -S uv run --script
# /// script
# requires-python = "==3.12.*"
# dependencies = [
#    "loguru",
#    "requests",
# ]
# [tool.uv]
# exclude-newer = "2025-05-16T00:00:00Z"
# ///

import argparse
import os
import socket
from dataclasses import dataclass
import sys
from typing import Optional, List, Tuple

import requests
from loguru import logger


@dataclass
class NetcupCredentials:
    api_key: str
    api_password: str
    customer_number: int


@dataclass
class DomainRecord:
    fqdn: str
    domain: str
    hostname: str
    record_type: str = "A"
    priority: int = 10


class NetcupDynDNS:
    API_URL = "https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON"

    def __init__(self, creds: NetcupCredentials, records: List[DomainRecord]):
        self.creds = creds
        self.records = records
        self.session_id: Optional[str] = None
        self.dns_records_cache: dict[str, List[dict]] = {}

    def get_public_ip(self) -> str:
        logger.debug("Fetching public IP")
        r = requests.get("https://wtfismyip.com/text", timeout=10)
        r.raise_for_status()
        ip = r.text.strip()
        logger.info(f"Current public IP: {ip}")
        return ip

    def resolve_dns_ip(self, fqdn: str) -> Optional[str]:
        try:
            ip = socket.gethostbyname(fqdn)
            logger.debug(f"Resolved {fqdn} to {ip}")
            return ip
        except socket.gaierror:
            logger.warning(f"Failed to resolve DNS for {fqdn}")
            return None

    def login(self) -> None:
        logger.debug("Logging in to Netcup API")
        data = {
            "action": "login",
            "param": {
                "apikey": self.creds.api_key,
                "apipassword": self.creds.api_password,
                "customernumber": str(self.creds.customer_number),
            },
        }
        r = requests.post(self.API_URL, json=data)
        r.raise_for_status()
        self.session_id = r.json()["responsedata"]["apisessionid"]
        logger.info("Login successful")

    def logout(self) -> None:
        if not self.session_id:
            return
        logger.debug("Logging out from Netcup API")
        data = {
            "action": "logout",
            "param": {
                "apikey": self.creds.api_key,
                "apisessionid": self.session_id,
                "customernumber": str(self.creds.customer_number),
            },
        }
        requests.post(self.API_URL, json=data)
        logger.info("Logout successful")

    def get_dns_record_id(
        self, domain: str, hostname: str, record_type: str
    ) -> Optional[int]:
        if domain not in self.dns_records_cache:
            logger.debug(f"Fetching DNS records for domain: {domain}")
            data = {
                "action": "infoDnsRecords",
                "param": {
                    "apikey": self.creds.api_key,
                    "apisessionid": self.session_id,
                    "customernumber": str(self.creds.customer_number),
                    "domainname": domain,
                },
            }
            r = requests.post(self.API_URL, json=data)
            r.raise_for_status()
            self.dns_records_cache[domain] = r.json()["responsedata"]["dnsrecords"]
        else:
            logger.debug(f"Using cached DNS records for domain: {domain}")
        records = self.dns_records_cache[domain]
        for record in records:
            if record["hostname"] == hostname and record["type"] == record_type:
                logger.debug(f"Found record ID {record['id']} for {hostname}.{domain}")
                return int(record["id"])

        logger.warning(f"No DNS record found for {hostname}.{domain}")
        return None

    def update_dns_record(
        self, record: DomainRecord, record_id: int, new_ip: str
    ) -> None:
        logger.info(
            f"Updating DNS record {record.hostname}.{record.domain} to {new_ip}"
        )
        data = {
            "action": "updateDnsRecords",
            "param": {
                "apikey": self.creds.api_key,
                "apisessionid": self.session_id,
                "customernumber": str(self.creds.customer_number),
                "clientrequestid": "",
                "domainname": record.domain,
                "dnsrecordset": {
                    "dnsrecords": [
                        {
                            "id": record_id,
                            "hostname": record.hostname,
                            "type": record.record_type,
                            "priority": str(record.priority),
                            "destination": new_ip,
                            "deleterecord": False,
                            "state": "yes",
                        }
                    ]
                },
            },
        }
        r = requests.post(self.API_URL, json=data)
        r.raise_for_status()
        logger.info(
            f"DNS record {record.hostname}.{record.domain} updated successfully"
        )

    def run(self) -> None:
        try:
            current_ip = self.get_public_ip()
            self.login()
            for record in self.records:
                dns_ip = self.resolve_dns_ip(record.fqdn)
                if dns_ip == current_ip:
                    logger.info(f"{record.fqdn} IP is up-to-date ({current_ip})")
                    continue
                record_id = self.get_dns_record_id(
                    record.domain, record.hostname, record.record_type
                )
                if record_id is not None:
                    self.update_dns_record(record, record_id, current_ip)
                else:
                    logger.error(
                        f"Skipping update: DNS record ID not found for {record.fqdn}"
                    )
        except requests.RequestException as e:
            logger.error(f"HTTP error occurred: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        finally:
            self.logout()


def extract_hostname_and_domain(fqdn: str) -> Tuple[str, str]:
    parts = fqdn.split(".")
    if len(parts) < 2:
        logger.error(f"Invalid domain name: {fqdn}")
        raise ValueError(f"Invalid domain: {fqdn}")
    domain = ".".join(parts[-2:])
    hostname = ".".join(parts[:-2]) if len(parts) > 2 else "@"
    return hostname, domain


def parse_args():
    parser = argparse.ArgumentParser(
        description="Update Netcup DNS A records for multiple (sub)domains."
    )
    parser.add_argument(
        "-d",
        "--fqdns",
        nargs="+",
        required=True,
        help="List of domains or subdomains (FQDNs)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times)",
    )
    return parser.parse_args()


def get_env_credentials() -> NetcupCredentials:
    logger.debug("Retrieving Netcup credentials from environment variables")
    try:
        return NetcupCredentials(
            api_key=os.environ["NETCUP_APIKEY"],
            api_password=os.environ["NETCUP_APIPASSWORD"],
            customer_number=int(os.environ["NETCUP_CUSTOMERNUMBER"]),
        )
    except KeyError as e:
        logger.error(f"Missing required environment variable: {e.args[0]}")
        raise SystemExit(1)


if __name__ == "__main__":
    args = parse_args()

    logger.remove()
    if args.verbose == 0:
        logger.add(sys.stderr, level="INFO")
    elif args.verbose == 1:
        logger.add(sys.stderr, level="DEBUG")
    else:
        logger.add(sys.stderr, level="TRACE")

    logger.info("Starting Netcup DynDNS update script")

    creds = get_env_credentials()
    records = []
    for fqdn in args.fqdns:
        try:
            hostname, domain = extract_hostname_and_domain(fqdn)
            records.append(DomainRecord(fqdn=fqdn, domain=domain, hostname=hostname))
        except ValueError as e:
            logger.error(e)
    if not records:
        logger.error("No valid domains to update. Exiting.")
        raise SystemExit(1)
    ddns = NetcupDynDNS(creds, records)
    ddns.run()
