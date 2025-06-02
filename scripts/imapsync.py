#!/usr/bin/env -S uv run --script
# /// script
# requires-python = "==3.12.*"
# dependencies = [
#   "polars",
#   "loguru",
# ]
# [tool.uv]
# exclude-newer = "2025-05-16T00:00:00Z"
# ///

import argparse
import shutil
import subprocess
from dataclasses import dataclass
from functools import partial
from typing import List

import polars as pl
from loguru import logger


def verify_dependencies(use_docker: bool):
    if use_docker:
        return
    if not shutil.which("imapsync"):
        raise RuntimeError(
            "imapsync not found in PATH. Use --use-docker if you want to run it via Docker."
        )


@dataclass
class IMAPCredential:
    email: str
    password: str
    host: str
    target_email: str
    target_password: str
    target_host: str


def read_config(path: str) -> List[IMAPCredential]:
    read_fn = pl.read_excel
    if path.endswith(".csv"):
        read_fn = pl.read_csv
    elif path.endswith((".xlsx", ".xls")):
        read_fn = pl.read_excel
    elif path.endswith(".tsv"):
        read_fn = partial(pl.read_csv, separator="\t")
    else:
        logger.error("Unsupported file format. Please provide a CSV or Excel file.")
        return []
    try:
        df = read_fn(path).select(
            [
                "email",
                "password",
                "host",
                "target_email",
                "target_password",
                "target_host",
            ]
        )
        return [IMAPCredential(**row) for row in df.iter_rows(named=True)]
    except Exception as e:
        logger.error(f"Failed to read config: {e}")
        return []


def sync_inbox(creds: IMAPCredential, dry_run: bool, use_docker: bool):
    try:
        cmd = [
            "imapsync",
            "--host1",
            creds.host,
            "--user1",
            creds.email,
            "--password1",
            creds.password,
            "--host2",
            creds.target_host,
            "--user2",
            creds.target_email,
            "--password2",
            creds.target_password,
            "--automap",
            "--syncinternaldates",
            "--nofoldersizes",
            "--noreleasecheck",
        ]
        if dry_run:
            cmd.append("--dry")

        if use_docker:
            cmd = [
                "docker",
                "run",
                "--rm",
                "gilleslamiral/imapsync",
            ] + cmd
        subprocess.run(cmd, check=True)
        logger.info(
            f"{'Dry-run: ' if dry_run else ''}Synced {creds.email} → {creds.target_email} successfully."
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Sync failed for {creds.email} → {creds.target_email}: {e}")
        raise e
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        raise e


def main():
    parser = argparse.ArgumentParser(description="IMAP Sync Script")
    parser.add_argument("config", help="Path to Excel config file")
    parser.add_argument(
        "-n", "--dry-run", action="store_true", help="Perform a dry run"
    )
    parser.add_argument(
        "-d",
        "--use-docker",
        action="store_true",
        help="Run imapsync via Docker",
        default=False,
    )
    args = parser.parse_args()

    logger.add("imap_sync.log", rotation="1 MB")
    verify_dependencies(use_docker=args.use_docker)
    creds_list = read_config(args.config)
    for creds in creds_list:
        try:
            sync_inbox(creds, dry_run=args.dry_run, use_docker=args.use_docker)
        except Exception as e:
            logger.error(f"Error processing {creds.email}")
            raise e


if __name__ == "__main__":
    main()
