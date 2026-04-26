#!/usr/bin/env bash
# Project Wharf Launcher Script
# Minimal launcher to start the Project Wharf application

set -euo pipefail

REPO_DIR="/var/mnt/eclipse/repos/project-wharf"
PID_FILE="/tmp/project-wharf.pid"
LOG_FILE="/tmp/project-wharf.log"
MODE="${1:---auto}"

log() {
  echo "[ProjectWharf] $1"
}

err() {
  echo "[ProjectWharf] ERROR: $1" >&2
}

is_running() {
  [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

start_server() {
  if is_running; then
    log "Project Wharf is already running (PID: $(cat "$PID_FILE"))"
    return 0
  fi
  
  log "Starting Project Wharf..."
  
  cd "$REPO_DIR"
  
  # Build if not already built
  if [ ! -f "target/release/wharf" ]; then
    log "Building Project Wharf (this may take a while)..."
    cargo build --release --bin wharf
  fi
  
  # Start the application
  nohup ./target/release/wharf >"$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  
  log "Project Wharf started (PID: $!)"
  log "Log file: $LOG_FILE"
  
  # Wait a bit for the server to start
  sleep 2
  
  if ! is_running; then
    err "Project Wharf failed to start"
    err "Check log: $LOG_FILE"
    return 1
  fi
  
  return 0
}

stop_server() {
  if ! is_running; then
    log "Project Wharf is not running"
    return 0
  fi
  
  log "Stopping Project Wharf..."
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
  rm -f "$PID_FILE"
  log "Project Wharf stopped"
}

status_server() {
  if is_running; then
    log "Project Wharf is running (PID: $(cat "$PID_FILE"))"
    return 0
  else
    log "Project Wharf is not running"
    return 1
  fi
}

case "$MODE" in
  --start)      start_server ;;
  --stop)       stop_server ;;
  --status)     status_server ;;
  --auto|*)     start_server ;;
esac
