#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="netcup-dyndns.service"
TIMER_NAME="netcup-dyndns.timer"
ENV_NAME="netcup-dyndns.env"
SYSTEMD_DIR="/etc/systemd/system"
ENV_DEST="/etc"
SCRIPT_REL_PATH="scripts/dyndns.py"
SERVICE_SRC="$REPO_ROOT/systemd/$SERVICE_NAME"
TIMER_SRC="$REPO_ROOT/systemd/$TIMER_NAME"
ENV_SRC="$REPO_ROOT/systemd/$ENV_NAME"
SCRIPT_PATH="$REPO_ROOT/$SCRIPT_REL_PATH"

print_error() {
    echo "Error: $1" >&2
}

for f in "$SERVICE_SRC" "$TIMER_SRC" "$ENV_SRC" "$SCRIPT_PATH"; do
    if [[ ! -f "$f" ]]; then
        print_error "Required file missing: $f"
        exit 1
    fi
done

if [[ ! -x "$SCRIPT_PATH" ]]; then
    echo "Making $SCRIPT_REL_PATH executable"
    chmod +x "$SCRIPT_PATH"
fi

TEMP_SERVICE="$(mktemp)"
sed "s|/path/to/netcup_dyndns.py|$SCRIPT_PATH|g" "$SERVICE_SRC" > "$TEMP_SERVICE"

echo "Installing $SERVICE_NAME to $SYSTEMD_DIR"
sudo cp "$TEMP_SERVICE" "$SYSTEMD_DIR/$SERVICE_NAME"
rm "$TEMP_SERVICE"

echo "Installing $TIMER_NAME to $SYSTEMD_DIR"
sudo cp "$TIMER_SRC" "$SYSTEMD_DIR/$TIMER_NAME"

echo "Installing $ENV_NAME to $ENV_DEST"
sudo cp "$ENV_SRC" "$ENV_DEST/$ENV_NAME"
sudo chmod 600 "$ENV_DEST/$ENV_NAME"

echo "Reloading systemd daemon"
sudo systemctl daemon-reload

echo "Enabling $SERVICE_NAME and $TIMER_NAME"
sudo systemctl enable "$SERVICE_NAME" "$TIMER_NAME"

read -rp "Start timer now? [y/N]: " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
    sudo systemctl start "$TIMER_NAME"
    echo "$TIMER_NAME started."
else
    echo "You can start the timer later with:"
    echo "  sudo systemctl start $TIMER_NAME"
fi
