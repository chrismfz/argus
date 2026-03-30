#!/usr/bin/env bash
# =============================================================================
#  Argus — Install / Update Script
#  Usage:
#    Fresh install : curl -fsSL https://raw.githubusercontent.com/chrismfz/argus/main/install.sh | bash
#    Local run     : ./install.sh
#    Update only   : ./install.sh --update
# =============================================================================
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/chrismfz/argus.git"
INSTALL_DIR="/opt/argus"
SERVICE_NAME="argus"
SERVICE_SRC="etc/systemd/system/argus.service"
SERVICE_DST="/etc/systemd/system/argus.service"
BINARY="bin/argus"
BACKUP_DIR="/opt/argus-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}${BOLD}[argus]${RESET} $*"; }
ok()      { echo -e "${GREEN}${BOLD}[  ok  ]${RESET} $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[ warn ]${RESET} $*"; }
die()     { echo -e "${RED}${BOLD}[ fail ]${RESET} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}━━━ $* ━━━${RESET}"; }

# ── Root check ────────────────────────────────────────────────────────────────
section "Privilege check"
[[ $EUID -eq 0 ]] || die "This script must be run as root (sudo ./install.sh)"
ok "Running as root"

# ── Dependency check ──────────────────────────────────────────────────────────
section "Dependency check"
MISSING=()
for cmd in git make go; do
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd → $(command -v "$cmd")"
    else
        warn "$cmd not found"
        MISSING+=("$cmd")
    fi
done
[[ ${#MISSING[@]} -eq 0 ]] || die "Missing dependencies: ${MISSING[*]}. Install them and re-run."

# ── Determine mode: clone vs in-repo vs update ────────────────────────────────
section "Repository detection"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IN_REPO=false
IS_INSTALL_DIR=false

# Are we already sitting inside a git repo that looks like argus?
if git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree &>/dev/null 2>&1; then
    REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
    if [[ -f "$REPO_ROOT/go.mod" ]] && grep -q "^module.*argus" "$REPO_ROOT/go.mod" 2>/dev/null; then
        IN_REPO=true
        info "Running from inside the Argus repo: $REPO_ROOT"
    fi
fi

# Is the install dir already present and a valid git repo?
if [[ -d "$INSTALL_DIR/.git" ]]; then
    IS_INSTALL_DIR=true
    info "Existing installation found at $INSTALL_DIR"
fi

# ── Backup helper ─────────────────────────────────────────────────────────────
backup_config() {
    local src="$INSTALL_DIR/etc"
    if [[ ! -d "$src" ]]; then
        warn "No etc/ directory to back up — skipping config backup"
        return
    fi
    mkdir -p "$BACKUP_DIR"
    local archive="$BACKUP_DIR/config_${TIMESTAMP}.tar.gz"
    tar -czf "$archive" -C "$INSTALL_DIR" etc/
    ok "Config backed up → $archive"
}

backup_binary() {
    local bin="$INSTALL_DIR/$BINARY"
    if [[ -f "$bin" ]]; then
        mkdir -p "$BACKUP_DIR"
        local dest="$BACKUP_DIR/argus_${TIMESTAMP}"
        cp "$bin" "$dest"
        ok "Previous binary backed up → $dest"
    fi
}

# ── Prune old backups (keep last 5) ───────────────────────────────────────────
prune_backups() {
    if [[ ! -d "$BACKUP_DIR" ]]; then return; fi
    local count
    count=$(find "$BACKUP_DIR" -maxdepth 1 -name 'config_*.tar.gz' | wc -l)
    if (( count > 5 )); then
        find "$BACKUP_DIR" -maxdepth 1 -name 'config_*.tar.gz' \
            | sort | head -n $(( count - 5 )) | xargs rm -f
        ok "Pruned old config backups (kept last 5)"
    fi
    count=$(find "$BACKUP_DIR" -maxdepth 1 -name 'argus_*' | wc -l)
    if (( count > 5 )); then
        find "$BACKUP_DIR" -maxdepth 1 -name 'argus_*' \
            | sort | head -n $(( count - 5 )) | xargs rm -f
        ok "Pruned old binary backups (kept last 5)"
    fi
}

# ── Service helpers ───────────────────────────────────────────────────────────
WAS_RUNNING=false

service_stop_if_running() {
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        WAS_RUNNING=true
        info "Stopping $SERVICE_NAME service..."
        systemctl stop "$SERVICE_NAME"
        ok "$SERVICE_NAME stopped"
    else
        info "$SERVICE_NAME is not currently running"
    fi
}

service_install_unit() {
    if [[ ! -f "$INSTALL_DIR/$SERVICE_SRC" ]]; then
        warn "Service file not found at $INSTALL_DIR/$SERVICE_SRC — skipping unit install"
        return
    fi
    cp "$INSTALL_DIR/$SERVICE_SRC" "$SERVICE_DST"
    chmod 644 "$SERVICE_DST"
    systemctl daemon-reload
    ok "Systemd unit installed → $SERVICE_DST (daemon reloaded)"
}

service_enable_start() {
    # Ensure the binary is executable
    chmod 755 "$INSTALL_DIR/$BINARY"
    ok "chmod 755 → $INSTALL_DIR/$BINARY"

    # Ensure log directory exists (service unit uses append:/var/log/argus/*)
    if [[ ! -d /var/log/argus ]]; then
        mkdir -p /var/log/argus
        chmod 750 /var/log/argus
        ok "Created /var/log/argus"
    fi

    systemctl enable "$SERVICE_NAME" &>/dev/null
    if $WAS_RUNNING; then
        info "Restarting $SERVICE_NAME (was running before update)..."
        systemctl restart "$SERVICE_NAME"
    else
        info "Starting $SERVICE_NAME..."
        systemctl start "$SERVICE_NAME"
    fi
}

service_health_check() {
    info "Waiting for service to stabilise..."
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "$SERVICE_NAME is running ✓"
        systemctl status "$SERVICE_NAME" --no-pager -l | grep -E 'Active:|Main PID:' | sed 's/^/         /'
    else
        die "$SERVICE_NAME failed to start. Check: journalctl -u $SERVICE_NAME -n 50 --no-pager"
    fi
}

# =============================================================================
#  PHASE 1 — Get the source
# =============================================================================
section "Source acquisition"

if $IS_INSTALL_DIR; then
    # ── Update path: pull latest ───────────────────────────────────────────────
    backup_config
    backup_binary
    prune_backups

    info "Pulling latest changes in $INSTALL_DIR..."
    cd "$INSTALL_DIR"
    git fetch origin

    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse '@{u}')
    if [[ "$LOCAL" == "$REMOTE" ]]; then
        warn "Already up-to-date ($(git rev-parse --short HEAD))"
        # Still continue — user may want to rebuild / reinstall unit
    else
        git pull --ff-only
        ok "Updated to $(git rev-parse --short HEAD)"
    fi

elif $IN_REPO; then
    # ── Running from a checked-out clone (not /opt/argus) ─────────────────────
    if [[ "$REPO_ROOT" != "$INSTALL_DIR" ]]; then
        info "Syncing repo from $REPO_ROOT → $INSTALL_DIR"
        mkdir -p "$(dirname "$INSTALL_DIR")"

        # Preserve existing config before we overwrite
        if [[ -d "$INSTALL_DIR/etc" ]]; then
            backup_config
        fi
        backup_binary
        prune_backups

        rsync -a --exclude='.git' --exclude='bin/' "$REPO_ROOT/" "$INSTALL_DIR/"
        ok "Files synced to $INSTALL_DIR"
        cd "$INSTALL_DIR"
    else
        ok "Script is already running from $INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi

else
    # ── Fresh install: clone ───────────────────────────────────────────────────
    info "No existing installation found — cloning $REPO_URL"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone "$REPO_URL" "$INSTALL_DIR"
    ok "Cloned into $INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# =============================================================================
#  PHASE 2 — Build
# =============================================================================
section "Build"

cd "$INSTALL_DIR"
info "Running: make build"
if make build; then
    ok "Build succeeded → $INSTALL_DIR/$BINARY"
else
    # Try to roll back binary if we backed one up
    LAST_BACKUP=$(find "$BACKUP_DIR" -maxdepth 1 -name 'argus_*' | sort | tail -1 2>/dev/null || true)
    if [[ -n "$LAST_BACKUP" ]]; then
        warn "Build failed — restoring previous binary from $LAST_BACKUP"
        cp "$LAST_BACKUP" "$INSTALL_DIR/$BINARY"
        chmod +x "$INSTALL_DIR/$BINARY"
    fi
    die "make build failed. Fix errors and re-run. Previous binary restored (if available)."
fi

# =============================================================================
#  PHASE 3 — Service management
# =============================================================================
section "Service"

service_stop_if_running
service_install_unit
service_enable_start
service_health_check

# =============================================================================
#  Done
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}${BOLD}  Argus installed/updated successfully ✓${RESET}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  Install dir : $INSTALL_DIR"
echo -e "  Binary      : $INSTALL_DIR/$BINARY"
echo -e "  Service     : $SERVICE_NAME (systemd)"
echo -e "  Backups     : $BACKUP_DIR"
echo ""
echo -e "  Useful commands:"
echo -e "    journalctl -u $SERVICE_NAME -f"
echo -e "    systemctl status $SERVICE_NAME"
echo ""
