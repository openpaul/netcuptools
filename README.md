# Infra Utility Scripts

Lightweight Python CLI tools for DNS updates and mailbox syncing. Built for automation using `uv`, `loguru`, and standard Python tooling.

## Structure

```txt
.
├── configs/
│ └── emailsexample.csv # Example config file for imapsync
└── scripts/
├── dyndns.py # Dynamic DNS updater for Netcup API
└── imapsync.py # IMAP inbox migration via imapsync
```

## Requirements

- Python 3.12
- `uv`
- Docker (optional for imapsync)
- External tool: `imapsync` (if not using Docker)

## Installation

Install uv from astal: [docs.astral.sh/uv/getting-started/installation/](https://docs.astral.sh/uv/getting-started/installation/)

## Usage:

### dyndns.py

Update DNS A/AAAA records via Netcup's API.

```sh
./scripts/dyndns.py --help
```

### Environment variables

```bash
export NETCUP_APIKEY="..."
export NETCUP_APIPASSWORD="..."
export NETCUP_CUSTOMERNUMBER="..."
```

### imapsync.py

Sync one or multiple mailboxes using imapsync.
Usage

```sh
./scripts/imapsync.py --help
```

#### Config file

Supports .csv, .tsv, or Excel. Must include these columns:

```txt
email,password,host,target_email,target_password,target_host
```

See example: `configs/emailsexample.csv`

## Logging

Scripts use loguru for structured logs. imap_sync.log is created automatically for imapsync runs.

## License

MIT
