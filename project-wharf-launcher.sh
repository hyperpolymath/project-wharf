#!/usr/bin/env bash
# Project Wharf Launcher Script
# Minimal launcher to start the Project Wharf application

set -euo pipefail

REPO_DIR="/var/mnt/eclipse/repos/project-wharf"
# Per-user XDG state, not /tmp: a world-writable /tmp path with a predictable
# name lets another local user pre-create the pid file and choose which
# process `stop` kills (CWE-377). Matches launch-scaffolder main's generator
# (standards/launcher-standard_praxis.deed :pid-file-pattern/:log-file-pattern).
case "${XDG_RUNTIME_DIR:-}" in
  /*) _pid_root=$XDG_RUNTIME_DIR ;;
  *)
    case "${XDG_STATE_HOME:-}" in
      /*) _pid_root=$XDG_STATE_HOME ;;
      *) _pid_root=$HOME/.local/state ;;
    esac
    ;;
esac
case "${XDG_STATE_HOME:-}" in
  /*) _state_root=$XDG_STATE_HOME ;;
  *) _state_root=$HOME/.local/state ;;
esac
PID_FILE="${_pid_root}/launch-scaffolder/project-wharf/server.pid"
LOG_FILE="${_state_root}/launch-scaffolder/project-wharf/server.log"
for _d in "$(dirname "$PID_FILE")" "$(dirname "$LOG_FILE")"; do
  mkdir -p "$_d"
  chmod 0700 "$_d"
done
unset _d
MODE="${1:---auto}"

# Write a launcher message to standard output with the [ProjectWharf] prefix.
# Arguments:
#   $1: Message to print.
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
