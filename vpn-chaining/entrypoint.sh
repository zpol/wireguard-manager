#!/bin/sh
set -eu

ROLE="${ROLE:-}"
if [ -z "$ROLE" ]; then
  echo "[ERROR] ROLE is required (client|node-a|node-b|node-c)" >&2
  exit 1
fi

WG_DIR="/etc/wireguard"
DATA_DIR="/data"
KEY_DIR="${DATA_DIR}/keys"
SHARED_DIR="/shared/keys"
mkdir -p "$WG_DIR" "$KEY_DIR" "$SHARED_DIR"

log() {
  echo "[vpn-chaining] $*"
}

disable_ipv6() {
  sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.lo.disable_ipv6=1 >/dev/null 2>&1 || true
  ip6tables -P INPUT DROP || true
  ip6tables -P OUTPUT DROP || true
  ip6tables -P FORWARD DROP || true
}

gen_keypair() {
  name="$1"
  priv="${KEY_DIR}/${name}.key"
  pub="${KEY_DIR}/${name}.pub"
  if [ ! -f "$priv" ]; then
    wg genkey > "$priv"
    wg pubkey < "$priv" > "$pub"
  fi
  cp "$pub" "${SHARED_DIR}/${name}.pub"
}

wait_for_pub() {
  name="$1"
  file="${SHARED_DIR}/${name}.pub"
  while [ ! -f "$file" ]; do
    log "Waiting for peer key ${name}.pub..."
    sleep 2
  done
  cat "$file"
}

write_config() {
  name="$1"
  content="$2"
  conf="${WG_DIR}/${name}.conf"
  printf "%s\n" "$content" > "$conf"
  chmod 600 "$conf"
}

iptables_reset() {
  iptables -F
  iptables -t nat -F
  iptables -P INPUT DROP
  iptables -P OUTPUT DROP
  iptables -P FORWARD DROP
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

enable_forwarding() {
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

ROLE_CLIENT_ADDR="${ROLE_CLIENT_ADDR:-10.10.0.2/24}"
ROLE_NODE_A_CLIENT_ADDR="${ROLE_NODE_A_CLIENT_ADDR:-10.10.0.1/24}"
ROLE_NODE_A_AB_ADDR="${ROLE_NODE_A_AB_ADDR:-10.20.0.1/24}"
ROLE_NODE_B_AB_ADDR="${ROLE_NODE_B_AB_ADDR:-10.20.0.2/24}"
ROLE_NODE_B_BC_ADDR="${ROLE_NODE_B_BC_ADDR:-10.30.0.1/24}"
ROLE_NODE_C_BC_ADDR="${ROLE_NODE_C_BC_ADDR:-10.30.0.2/24}"
CLIENT_SUBNET="${CLIENT_SUBNET:-10.10.0.0/24}"
DNS_IP="${DNS_IP:-1.1.1.1}"

PORT_CLIENT="${PORT_CLIENT:-51820}"
PORT_AB="${PORT_AB:-51821}"
PORT_BC="${PORT_BC:-51822}"

NODE_A_ENDPOINT="${NODE_A_ENDPOINT:-node-a:${PORT_CLIENT}}"
NODE_B_ENDPOINT="${NODE_B_ENDPOINT:-node-b:${PORT_AB}}"
NODE_C_ENDPOINT="${NODE_C_ENDPOINT:-node-c:${PORT_BC}}"

disable_ipv6

case "$ROLE" in
  client)
    gen_keypair "client_wg0"
    node_a_pub="$(wait_for_pub node-a_wg-client)"

    write_config "wg-client" "[Interface]
Address = ${ROLE_CLIENT_ADDR}
PrivateKey = $(cat "${KEY_DIR}/client_wg0.key")
DNS = ${DNS_IP}

[Peer]
PublicKey = ${node_a_pub}
Endpoint = ${NODE_A_ENDPOINT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"

    iptables_reset
    iptables -A OUTPUT -p udp -d "$(echo "$NODE_A_ENDPOINT" | cut -d: -f1)" --dport "$PORT_CLIENT" -j ACCEPT
    iptables -A INPUT -p udp --sport "$PORT_CLIENT" -j ACCEPT
    iptables -A INPUT -i wg-client -j ACCEPT
    iptables -A OUTPUT -o wg-client -j ACCEPT

    wg-quick up wg-client
    ;;

  node-a)
    gen_keypair "node-a_wg-client"
    gen_keypair "node-a_wg-ab"
    client_pub="$(wait_for_pub client_wg0)"
    node_b_pub="$(wait_for_pub node-b_wg-ab)"

    write_config "wg-client" "[Interface]
Address = ${ROLE_NODE_A_CLIENT_ADDR}
ListenPort = ${PORT_CLIENT}
PrivateKey = $(cat "${KEY_DIR}/node-a_wg-client.key")

[Peer]
PublicKey = ${client_pub}
AllowedIPs = ${CLIENT_SUBNET}
"

    write_config "wg-ab" "[Interface]
Address = ${ROLE_NODE_A_AB_ADDR}
PrivateKey = $(cat "${KEY_DIR}/node-a_wg-ab.key")

[Peer]
PublicKey = ${node_b_pub}
Endpoint = ${NODE_B_ENDPOINT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"

    iptables_reset
    enable_forwarding
    iptables -A INPUT -p udp --dport "$PORT_CLIENT" -j ACCEPT
    iptables -A OUTPUT -p udp -d "$(echo "$NODE_B_ENDPOINT" | cut -d: -f1)" --dport "$PORT_AB" -j ACCEPT
    iptables -A INPUT -i wg-client -j ACCEPT
    iptables -A OUTPUT -o wg-client -j ACCEPT
    iptables -A INPUT -i wg-ab -j ACCEPT
    iptables -A OUTPUT -o wg-ab -j ACCEPT
    iptables -A FORWARD -i wg-client -o wg-ab -j ACCEPT
    iptables -A FORWARD -i wg-ab -o wg-client -j ACCEPT

    wg-quick up wg-client
    wg-quick up wg-ab
    ;;

  node-b)
    gen_keypair "node-b_wg-ab"
    gen_keypair "node-b_wg-bc"
    node_a_pub="$(wait_for_pub node-a_wg-ab)"
    node_c_pub="$(wait_for_pub node-c_wg-bc)"

    write_config "wg-ab" "[Interface]
Address = ${ROLE_NODE_B_AB_ADDR}
ListenPort = ${PORT_AB}
PrivateKey = $(cat "${KEY_DIR}/node-b_wg-ab.key")

[Peer]
PublicKey = ${node_a_pub}
AllowedIPs = ${CLIENT_SUBNET},$(echo "${ROLE_NODE_A_AB_ADDR}" | cut -d/ -f1)/32
"

    write_config "wg-bc" "[Interface]
Address = ${ROLE_NODE_B_BC_ADDR}
PrivateKey = $(cat "${KEY_DIR}/node-b_wg-bc.key")

[Peer]
PublicKey = ${node_c_pub}
Endpoint = ${NODE_C_ENDPOINT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"

    iptables_reset
    enable_forwarding
    iptables -A INPUT -p udp --dport "$PORT_AB" -j ACCEPT
    iptables -A OUTPUT -p udp -d "$(echo "$NODE_C_ENDPOINT" | cut -d: -f1)" --dport "$PORT_BC" -j ACCEPT
    iptables -A INPUT -i wg-ab -j ACCEPT
    iptables -A OUTPUT -o wg-ab -j ACCEPT
    iptables -A INPUT -i wg-bc -j ACCEPT
    iptables -A OUTPUT -o wg-bc -j ACCEPT
    iptables -A FORWARD -i wg-ab -o wg-bc -j ACCEPT
    iptables -A FORWARD -i wg-bc -o wg-ab -j ACCEPT

    wg-quick up wg-ab
    wg-quick up wg-bc
    ;;

  node-c)
    gen_keypair "node-c_wg-bc"
    node_b_pub="$(wait_for_pub node-b_wg-bc)"

    write_config "wg-bc" "[Interface]
Address = ${ROLE_NODE_C_BC_ADDR}
ListenPort = ${PORT_BC}
PrivateKey = $(cat "${KEY_DIR}/node-c_wg-bc.key")

[Peer]
PublicKey = ${node_b_pub}
AllowedIPs = ${CLIENT_SUBNET},$(echo "${ROLE_NODE_B_BC_ADDR}" | cut -d/ -f1)/32
"

    iptables_reset
    enable_forwarding
    iptables -A INPUT -p udp --dport "$PORT_BC" -j ACCEPT
    iptables -A INPUT -i wg-bc -j ACCEPT
    iptables -A OUTPUT -o wg-bc -j ACCEPT
    iptables -A FORWARD -i wg-bc -o eth0 -j ACCEPT
    iptables -A FORWARD -i eth0 -o wg-bc -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -A POSTROUTING -s "${CLIENT_SUBNET}" -o eth0 -j MASQUERADE

    wg-quick up wg-bc
    ;;

  *)
    log "Unknown ROLE: $ROLE"
    exit 1
    ;;
esac

log "Role ${ROLE} up. Tail logs..."
tail -f /dev/null

