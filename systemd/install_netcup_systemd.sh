#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="netcup-dyndns.service"
ENV_NAME="netcup-dyndns.env"
SYSTEMD_DIR="/etc/systemd/system"
ENV_DEST="/etc"
SCRIPT_REL_PATH="scripts/dyndns.py"
SERVICE_SRC="$REPO_ROOT/systemd/$SERVICE_NAME"
ENV_SRC="$REPO_ROOT/systemd/$ENV_NAME"
SCRIPT_PATH="$REPO_ROOT/$SCRIPT_REL_PATH"

print_error() {
    echo "Error: $1" >&2
}

# Check required files
for f in "$SERVICE_SRC" "$ENV_SRC" "$SCRIPT_PATH"; do
    if [[ ! -f "$f" ]]; then
        print_error "Required file missing: $f"
        exit 1
    fi
done

# Make script executable
if [[ ! -x "$SCRIPT_PATH" ]]; then
    echo "Making $SCRIPT_REL_PATH executable"
    chmod +x "$SCRIPT_PATH"
fi

# Replace placeholder path in systemd service file
TEMP_SERVICE="$(mktemp)"
sed "s|/path/to/netcup_dyndns.py|$SCRIPT_PATH|g" "$SERVICE_SRC" > "$TEMP_SERVICE"

echo "Installing $SERVICE_NAME to $SYSTEMD_DIR"
sudo cp "$TEMP_SERVICE" "$SYSTEMD_DIR/$SERVICE_NAME"
rm "$TEMP_SERVICE"

echo "Installing $ENV_NAME to $ENV_DEST"
sudo cp "$ENV_SRC" "$ENV_DEST/$ENV_NAME"
sudo chmod 600 "$ENV_DEST/$ENV_NAME"

echo "Reloading systemd daemon"
sudo systemctl daemon-reload

echo "Enabling $SERVICE_NAME"
sudo systemctl enable "$SERVICE_NAME"

read -rp "Do you want to start $SERVICE_NAME now? [y/N]: " answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    sudo systemctl start "$SERVICE_NAME"
    echo "$SERVICE_NAME started."
else
    echo "You can start the service later with:"
    echo "  sudo systemctl start $SERVICE_NAME"
fi
