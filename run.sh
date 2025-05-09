#!/bin/bash

# Paths to binaries
BIN_DIR="."
TELNET="$BIN_DIR/telnet_pit"
UPNP="$BIN_DIR/upnp_pit"
MQTT="$BIN_DIR/mqtt_pit"
EXPORTER="$BIN_DIR/prometheus_exporter"

PID_DIR="./pids"
mkdir -p "$PID_DIR"

# Defaults
START_ALL=true
INCLUDE_SERVERS=()
PORT=""
DELAY=""
CONFIGS=()

# Parse CLI arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        start|stop|status|restart) ACTION=$1 ;;
        --only=*) IFS=',' read -r -a INCLUDE_SERVERS <<< "${1#*=}"; START_ALL=false ;;
        --port=*) PORT="${1#*=}" ;;
        --delay=*) DELAY="${1#*=}" ;;
        --config=*) CONFIGS+=("${1#*=}") ;;
        *) echo "Unknown option: $1" && exit 1 ;;
    esac
    shift
done

# Check if a server is included
should_start() {
    local name=$1
    if $START_ALL; then
        return 0
    fi
    for server in "${INCLUDE_SERVERS[@]}"; do
        [[ "$server" == "$name" ]] && return 0
    done
    return 1
}

# Start a server
start_server() {
    local name=$1
    local binary=$2
    local pidfile="$PID_DIR/$name.pid"
    local args=""

    # Example of per-server config
    case "$name" in
        telnet)
            [[ -n "$PORT" ]] && args+=" --port=$PORT"
            [[ -n "$DELAY" ]] && args+=" --delay=$DELAY"
            ;;
        mqtt)
            [[ -n "$DELAY" ]] && args+=" --mqtt-delay=$DELAY"
            ;;
        upnp)
            ;;
        exporter)
            ;;
    esac

    echo "Starting $name with args: $args"
    $binary $args & echo $! > "$pidfile"
}

start() {
    echo "Starting selected servers..."
    should_start telnet   && start_server telnet "$TELNET"
    should_start upnp     && start_server upnp "$UPNP"
    should_start mqtt     && start_server mqtt "$MQTT"
    should_start exporter && start_server exporter "$EXPORTER"
    echo "Done."
}

stop() {
    echo "Stopping servers..."
    for pidfile in "$PID_DIR"/*.pid; do
        [ -f "$pidfile" ] || continue
        pid=$(cat "$pidfile")
        kill "$pid" 2>/dev/null && echo "Stopped $(basename "$pidfile" .pid)"
        rm -f "$pidfile"
    done
}

status() {
    echo "Status of servers:"
    for pidfile in "$PID_DIR"/*.pid; do
        name=$(basename "$pidfile" .pid)
        pid=$(cat "$pidfile")
        if ps -p "$pid" > /dev/null; then
            echo "$name: running (pid $pid)"
        else
            echo "$name: not running"
        fi
    done
}

case "$ACTION" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    restart) stop; start ;;
    *) echo "Usage: $0 {start|stop|restart|status} [--only=telnet,mqtt] [--port=XXXX] [--delay=Y]"; exit 1 ;;
esac
