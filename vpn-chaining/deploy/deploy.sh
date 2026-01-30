#!/bin/sh
set -eu

RECREATE=false
DEBUG=false
INVENTORY="./inventory.env"

show_help() {
  cat <<'EOF'
vpn-chaining deploy

Usage:
  ./deploy.sh [options] [inventory.env]

Options:
  --recreate   Force recreate containers (otherwise no-recreate by default)
  --debug      Show full stdout from remote/local compose builds
  --help       Show this help and exit

Notes:
  - Default inventory: ./inventory.env
  - If CLIENT_HOST is local/localhost/127.0.0.1, client runs locally.
  - Uses docker compose if available, falls back to docker-compose.
  - Only touches containers in vpn-chaining-* projects.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --recreate) RECREATE=true ;;
    --debug) DEBUG=true ;;
    --help) show_help; exit 0 ;;
    *) INVENTORY="$arg" ;;
  esac
done
if [ ! -f "$INVENTORY" ]; then
  echo "[ERROR] Inventory file not found: $INVENTORY" >&2
  exit 1
fi

. "$INVENTORY"

require_var() {
  name="$1"
  value="$(eval "printf '%s' \"\${$name:-}\"")"
  if [ -z "$value" ]; then
    echo "[ERROR] Missing required variable: $name" >&2
    exit 1
  fi
}

require_var SSH_USER
require_var SSH_PORT
require_var BASE_DIR
require_var CLIENT_HOST
require_var NODE_A_HOST
require_var NODE_B_HOST
require_var NODE_C_HOST
require_var NODE_A_PUBLIC_IP
require_var NODE_B_PUBLIC_IP
require_var NODE_C_PUBLIC_IP
require_var HOP_A_EXPECTED
require_var HOP_B_EXPECTED
require_var HOP_C_EXPECTED

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
LOCAL_CLIENT=false
case "$CLIENT_HOST" in
  local|localhost|127.0.0.1) LOCAL_CLIENT=true ;;
esac

COLOR_RED="$(printf '\033[0;31m')"
COLOR_GREEN="$(printf '\033[0;32m')"
COLOR_YELLOW="$(printf '\033[0;33m')"
COLOR_RESET="$(printf '\033[0m')"

print_ok() {
  printf "%sOK%s\n" "$COLOR_GREEN" "$COLOR_RESET"
}

print_no() {
  printf "%sNO%s\n" "$COLOR_RED" "$COLOR_RESET"
}

run_cmd() {
  label="$1"
  cmd="$2"
  if [ "$DEBUG" = true ]; then
    sh -c "$cmd"
    return $?
  fi
  tmp="$(mktemp)"
  if sh -c "$cmd" >"$tmp" 2>&1; then
    rm -f "$tmp"
    return 0
  fi
  echo "[ERROR] ${label} failed"
  cat "$tmp"
  rm -f "$tmp"
  return 1
}

spinner_wait() {
  label="$1"
  check_cmd="$2"
  tries="${3:-30}"
  i=0
  while [ "$tries" -gt 0 ]; do
    if sh -c "$check_cmd" >/dev/null 2>&1; then
      printf "\r%s... " "$label"
      print_ok
      return 0
    fi
    case $((i % 4)) in
      0) spin='|' ;;
      1) spin='/' ;;
      2) spin='-' ;;
      3) spin='\\' ;;
    esac
    printf "\r%s... %s" "$label" "$spin"
    i=$((i + 1))
    tries=$((tries - 1))
    sleep 1
  done
  printf "\r%s... " "$label"
  print_no
  return 1
}

sync_dir() {
  host="$1"
  echo "[deploy] Syncing to $host:$BASE_DIR"
  ssh -p "$SSH_PORT" "$SSH_USER@$host" "mkdir -p '$BASE_DIR'"
  rsync -az --delete --exclude 'shared/keys/' --exclude 'data/' \
    -e "ssh -p $SSH_PORT" "$ROOT_DIR/" "$SSH_USER@$host:$BASE_DIR/"
}

write_env() {
  host="$1"
  envfile="$2"
  ssh -p "$SSH_PORT" "$SSH_USER@$host" "cat > '$BASE_DIR/.env' <<EOF
NODE_A_ENDPOINT=${NODE_A_PUBLIC_IP}:51820
NODE_B_ENDPOINT=${NODE_B_PUBLIC_IP}:51821
NODE_C_ENDPOINT=${NODE_C_PUBLIC_IP}:51822
CLIENT_SUBNET=10.10.0.0/24
ROLE_CLIENT_ADDR=10.10.0.2/24
ROLE_NODE_A_CLIENT_ADDR=10.10.0.1/24
ROLE_NODE_A_AB_ADDR=10.20.0.1/24
ROLE_NODE_B_AB_ADDR=10.20.0.2/24
ROLE_NODE_B_BC_ADDR=10.30.0.1/24
ROLE_NODE_C_BC_ADDR=10.30.0.2/24
PORT_CLIENT=51820
PORT_AB=51821
PORT_BC=51822
DNS_IP=1.1.1.1
EOF"
  ssh -p "$SSH_PORT" "$SSH_USER@$host" "mkdir -p '$BASE_DIR/shared/keys' '$BASE_DIR/data/node-a' '$BASE_DIR/data/node-b' '$BASE_DIR/data/node-c' '$BASE_DIR/data/client'"
  ssh -p "$SSH_PORT" "$SSH_USER@$host" "cd '$BASE_DIR' && cp '$envfile' docker-compose.yml"
}

compose_up_remote() {
  host="$1"
  project="$2"
  container="$3"
  compose_cmd="$(ssh -p "$SSH_PORT" "$SSH_USER@$host" "if docker compose version >/dev/null 2>&1; then echo 'docker compose'; elif docker-compose version >/dev/null 2>&1; then echo 'docker-compose'; fi")"
  if [ -z "$compose_cmd" ]; then
    echo "[ERROR] No docker compose found on $host" >&2
    exit 1
  fi
  if [ "$RECREATE" = true ]; then
    run_cmd "compose down ($host)" "ssh -p '$SSH_PORT' '$SSH_USER@$host' \"cd '$BASE_DIR' && $compose_cmd -p '$project' --env-file .env -f docker-compose.yml down --remove-orphans\""
  fi
  exists="$(ssh -p "$SSH_PORT" "$SSH_USER@$host" "docker ps -a --format '{{.Names}}' | grep -w '$container' >/dev/null && echo yes || echo no")"
  if [ "$RECREATE" = true ]; then
    run_cmd "compose up ($host)" "ssh -p '$SSH_PORT' '$SSH_USER@$host' \"cd '$BASE_DIR' && $compose_cmd -p '$project' --env-file .env -f docker-compose.yml up -d --build --force-recreate\""
  else
    if [ "$exists" = "yes" ]; then
      run_cmd "compose up ($host)" "ssh -p '$SSH_PORT' '$SSH_USER@$host' \"cd '$BASE_DIR' && $compose_cmd -p '$project' --env-file .env -f docker-compose.yml up -d --no-recreate --no-build\""
    else
      run_cmd "compose up ($host)" "ssh -p '$SSH_PORT' '$SSH_USER@$host' \"cd '$BASE_DIR' && $compose_cmd -p '$project' --env-file .env -f docker-compose.yml up -d --build\""
    fi
  fi
}

sync_dir "$NODE_C_HOST"
sync_dir "$NODE_B_HOST"
sync_dir "$NODE_A_HOST"
if [ "$LOCAL_CLIENT" = false ]; then
  sync_dir "$CLIENT_HOST"
fi

write_env "$NODE_C_HOST" "compose.node-c.yml"
write_env "$NODE_B_HOST" "compose.node-b.yml"
write_env "$NODE_A_HOST" "compose.node-a.yml"
if [ "$LOCAL_CLIENT" = false ]; then
  write_env "$CLIENT_HOST" "compose.client.yml"
fi

compose_up_remote "$NODE_C_HOST" "vpn-chaining-node-c" "node-c"
compose_up_remote "$NODE_B_HOST" "vpn-chaining-node-b" "node-b"
compose_up_remote "$NODE_A_HOST" "vpn-chaining-node-a" "node-a"
if [ "$LOCAL_CLIENT" = false ]; then
  compose_up_remote "$CLIENT_HOST" "vpn-chaining-client" "vpn-client"
else
  echo "[deploy] Local client detected, running on this host"
  cat > "$ROOT_DIR/.env.client" <<EOF
NODE_A_ENDPOINT=${NODE_A_PUBLIC_IP}:51820
NODE_B_ENDPOINT=${NODE_B_PUBLIC_IP}:51821
NODE_C_ENDPOINT=${NODE_C_PUBLIC_IP}:51822
CLIENT_SUBNET=10.10.0.0/24
ROLE_CLIENT_ADDR=10.10.0.2/24
PORT_CLIENT=51820
DNS_IP=1.1.1.1
EOF
  if docker compose version >/dev/null 2>&1; then
    compose_cmd="docker compose"
  else
    compose_cmd="docker-compose"
  fi
  if [ "$RECREATE" = true ]; then
    run_cmd "compose down (local client)" "$compose_cmd -p 'vpn-chaining-client' --env-file '$ROOT_DIR/.env.client' -f '$ROOT_DIR/compose.client.yml' down --remove-orphans"
  fi
  if [ "$RECREATE" = true ]; then
    run_cmd "compose up (local client)" "$compose_cmd -p 'vpn-chaining-client' --env-file '$ROOT_DIR/.env.client' -f '$ROOT_DIR/compose.client.yml' up -d --build --force-recreate"
  else
    if docker ps -a --format '{{.Names}}' | grep -w "vpn-client" >/dev/null 2>&1; then
      run_cmd "compose up (local client)" "$compose_cmd -p 'vpn-chaining-client' --env-file '$ROOT_DIR/.env.client' -f '$ROOT_DIR/compose.client.yml' up -d --no-recreate --no-build"
    else
      run_cmd "compose up (local client)" "$compose_cmd -p 'vpn-chaining-client' --env-file '$ROOT_DIR/.env.client' -f '$ROOT_DIR/compose.client.yml' up -d --build"
    fi
  fi
fi

sync_keys() {
  key_dir="$1"
  host="$2"
  if [ "$LOCAL_CLIENT" = true ] && [ "$host" = "$CLIENT_HOST" ]; then
    return 0
  fi
  rsync -az -e "ssh -p $SSH_PORT" "$key_dir/" "$SSH_USER@$host:$BASE_DIR/shared/keys/"
}

collect_pub() {
  host="$1"
  key="$2"
  if [ "$LOCAL_CLIENT" = true ] && [ "$host" = "$CLIENT_HOST" ]; then
    cat "$ROOT_DIR/shared/keys/$key" > "/tmp/vpn-chaining-keys/$key"
  else
    ssh -p "$SSH_PORT" "$SSH_USER@$host" "cat '$BASE_DIR/shared/keys/$key'" > "/tmp/vpn-chaining-keys/$key"
  fi
}

echo "[deploy] Syncing public keys across nodes"
mkdir -p /tmp/vpn-chaining-keys
spinner_wait "node-c pub" "ssh -p '$SSH_PORT' '$SSH_USER@$NODE_C_HOST' \"test -f '$BASE_DIR/shared/keys/node-c_wg-bc.pub'\""
spinner_wait "node-b pub" "ssh -p '$SSH_PORT' '$SSH_USER@$NODE_B_HOST' \"test -f '$BASE_DIR/shared/keys/node-b_wg-ab.pub'\""
spinner_wait "node-b pub2" "ssh -p '$SSH_PORT' '$SSH_USER@$NODE_B_HOST' \"test -f '$BASE_DIR/shared/keys/node-b_wg-bc.pub'\""
spinner_wait "node-a pub" "ssh -p '$SSH_PORT' '$SSH_USER@$NODE_A_HOST' \"test -f '$BASE_DIR/shared/keys/node-a_wg-client.pub'\""
spinner_wait "node-a pub2" "ssh -p '$SSH_PORT' '$SSH_USER@$NODE_A_HOST' \"test -f '$BASE_DIR/shared/keys/node-a_wg-ab.pub'\""
if [ "$LOCAL_CLIENT" = true ]; then
  spinner_wait "client pub" "test -f '$ROOT_DIR/shared/keys/client_wg0.pub'"
else
  spinner_wait "client pub" "ssh -p '$SSH_PORT' '$SSH_USER@$CLIENT_HOST' \"test -f '$BASE_DIR/shared/keys/client_wg0.pub'\""
fi

collect_pub "$NODE_C_HOST" "node-c_wg-bc.pub"
collect_pub "$NODE_B_HOST" "node-b_wg-ab.pub"
collect_pub "$NODE_B_HOST" "node-b_wg-bc.pub"
collect_pub "$NODE_A_HOST" "node-a_wg-client.pub"
collect_pub "$NODE_A_HOST" "node-a_wg-ab.pub"
if [ "$LOCAL_CLIENT" = true ]; then
  collect_pub "$CLIENT_HOST" "client_wg0.pub"
else
  collect_pub "$CLIENT_HOST" "client_wg0.pub"
fi

sync_keys "/tmp/vpn-chaining-keys" "$NODE_C_HOST"
sync_keys "/tmp/vpn-chaining-keys" "$NODE_B_HOST"
sync_keys "/tmp/vpn-chaining-keys" "$NODE_A_HOST"
if [ "$LOCAL_CLIENT" = true ]; then
  rsync -az "/tmp/vpn-chaining-keys/" "$ROOT_DIR/shared/keys/"
else
  sync_keys "/tmp/vpn-chaining-keys" "$CLIENT_HOST"
fi

echo "[deploy] Container status"
spinner_wait "node-c" "ssh -p '$SSH_PORT' '$SSH_USER@$NODE_C_HOST' \"docker inspect -f '{{.State.Running}}' node-c 2>/dev/null | grep true\""
spinner_wait "node-b" "ssh -p '$SSH_PORT' '$SSH_USER@$NODE_B_HOST' \"docker inspect -f '{{.State.Running}}' node-b 2>/dev/null | grep true\""
spinner_wait "node-a" "ssh -p '$SSH_PORT' '$SSH_USER@$NODE_A_HOST' \"docker inspect -f '{{.State.Running}}' node-a 2>/dev/null | grep true\""
if [ "$LOCAL_CLIENT" = false ]; then
  spinner_wait "client" "ssh -p '$SSH_PORT' '$SSH_USER@$CLIENT_HOST' \"docker inspect -f '{{.State.Running}}' vpn-client 2>/dev/null | grep true\""
else
  spinner_wait "client" "docker inspect -f '{{.State.Running}}' vpn-client 2>/dev/null | grep true"
fi

echo "[deploy] Basic checks"
if [ "$LOCAL_CLIENT" = false ]; then
  ssh -p "$SSH_PORT" "$SSH_USER@$CLIENT_HOST" "cd '$BASE_DIR' && docker exec -t vpn-client wg show || true"
  ssh -p "$SSH_PORT" "$SSH_USER@$CLIENT_HOST" "cd '$BASE_DIR' && docker exec -t vpn-client ip route || true"
  ssh -p "$SSH_PORT" "$SSH_USER@$CLIENT_HOST" "cd '$BASE_DIR' && docker exec -t vpn-client curl -4 ifconfig.me || true"
  ssh -p "$SSH_PORT" "$SSH_USER@$CLIENT_HOST" "cd '$BASE_DIR' && docker exec -t vpn-client traceroute -4 -n -w 1 -q 1 1.1.1.1" > /tmp/vpn-chaining-trace.txt
else
  docker exec -t vpn-client wg show || true
  docker exec -t vpn-client ip route || true
  docker exec -t vpn-client curl -4 ifconfig.me || true
  docker exec -t vpn-client traceroute -4 -n -w 1 -q 1 1.1.1.1 > /tmp/vpn-chaining-trace.txt
fi

echo "[deploy] Verifying hop order"
if grep -q " 1 ${HOP_A_EXPECTED} " /tmp/vpn-chaining-trace.txt && \
   grep -q " 2 ${HOP_B_EXPECTED} " /tmp/vpn-chaining-trace.txt && \
   grep -q " 3 ${HOP_C_EXPECTED} " /tmp/vpn-chaining-trace.txt; then
  printf "%sHop order OK%s\n" "$COLOR_GREEN" "$COLOR_RESET"
else
  printf "%sHop order FAILED%s\n" "$COLOR_RED" "$COLOR_RESET"
  echo "Traceroute output:"
  cat /tmp/vpn-chaining-trace.txt
  exit 1
fi

