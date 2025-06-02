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
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

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


def getIPAddress(ip6: bool = False) -> str | None:
    if ip6:
        url = "https://ipv6.wtfismyip.com/json"
    else:
        url = "https://ipv4.wtfismyip.com/json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch data from {url}: {e}")
        raise SystemExit(1)

    return data.get("YourFuckingIPAddress", None)


class NetcupDynDNS:
    API_URL = "https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON"

    def __init__(
        self, creds: NetcupCredentials, records: List[DomainRecord], ip6: bool = False
    ):
        self.creds = creds
        self.records = records
        self.session_id: Optional[str] = None
        self.dns_records_cache: dict[str, List[dict]] = {}
        self.ip6 = ip6

    def get_public_ip(self) -> str:
        logger.debug("Fetching public IP")
        ip = getIPAddress(ip6=self.ip6)
        if ip is None:
            logger.error("Failed to retrieve public IP address")
            raise SystemExit(1)
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
        data = r.json()
        if data["status"] == "error":
            logger.error(f"Login failed: {data['longmessage']}")
            raise SystemExit(1)
        try:
            self.session_id = data["responsedata"]["apisessionid"]
        except KeyError:
            logger.error(f"Login failed: Invalid API response: {data}")
            raise SystemExit(1)
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

    def run(self, dry_run: bool = False) -> None:
        try:
            current_ip = self.get_public_ip()
            self.login()
            for record in self.records:
                if " " in record.fqdn:
                    logger.error(f"Invalid FQDN with spaces: {record.fqdn}")
                    continue

                dns_ip = self.resolve_dns_ip(record.fqdn)
                if dns_ip == current_ip:
                    logger.info(f"{record.fqdn} IP is up-to-date ({current_ip})")
                    continue
                else:
                    logger.debug(
                        f"{record.fqdn} IP mismatch: DNS {dns_ip}, current {current_ip}"
                    )
                record_id = self.get_dns_record_id(
                    record.domain, record.hostname, record.record_type
                )
                if record_id is not None:
                    if dry_run:
                        logger.info(
                            f"Dry run: Would update {record.fqdn} to {current_ip}"
                        )
                    else:
                        logger.debug(f"Updating DNS record for {record.fqdn}")
                        self.update_dns_record(record, record_id, current_ip)
                else:
                    logger.error(
                        f"Skipping update: DNS record ID not found for {record.fqdn}"
                    )
        except requests.RequestException as e:
            logger.error(f"HTTP error occurred: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise e
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
        "-n",
        "--dry-run",
        action="store_true",
        help="Perform a dry run without making changes",
        default=False,
    )
    parser.add_argument(
        "-6",
        "--ipv6",
        action="store_true",
        help="Use IPv6 as the public IP source",
        default=False,
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
    fqdns = args.fqdns
    parsed_fqdns = []
    for fqdn in fqdns:
        parsed_fqdns.extend(fqdn.split())
    for fqdn in parsed_fqdns:
        try:
            hostname, domain = extract_hostname_and_domain(fqdn)
            records.append(
                DomainRecord(
                    fqdn=fqdn,
                    domain=domain,
                    hostname=hostname,
                    record_type="AAAA" if args.ipv6 else "A",
                )
            )
        except ValueError as e:
            logger.error(e)
    if not records:
        logger.error("No valid domains to update. Exiting.")
        raise SystemExit(1)
    logger.info(f"Prepared {len(records)} records for update")
    ddns = NetcupDynDNS(creds, records, ip6=args.ipv6)
    ddns.run(dry_run=args.dry_run)
