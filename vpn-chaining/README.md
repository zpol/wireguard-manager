# vpn-chaining (3-hop WireGuard cascade)

## What this does
Containerized 3-hop VPN cascade:
Client → Node A → Node B → Node C → Internet

All traffic exits through Node C. Nodes A and B are locked down with DROP-by-default firewall rules and can only communicate over WireGuard.

## One-command deploy (single host, lab)
```bash
cd vpn-chaining
docker compose up -d --build
```

## One-command deploy (multi-host production)
1) Copy the inventory example and fill it:
```bash
cd vpn-chaining/deploy
cp inventory.example.env inventory.env
```
2) Set public IPs and hosts in `inventory.env`.
   If the client runs on your laptop, set `CLIENT_HOST=local`.
3) Run deploy:
```bash
./deploy.sh inventory.env
```
4) The deploy will fail if the traceroute hop order does not match
   `HOP_A_EXPECTED`, `HOP_B_EXPECTED`, `HOP_C_EXPECTED`.

## Access the client container
```bash
docker exec -it vpn-client sh
```

## Quick validation
From inside `vpn-client`:
```bash
curl -4 ifconfig.me
```
The IP should match Node C’s public IP (in a real multi-host deployment).

## Tunables (environment variables)
All tunables can be overridden in `docker-compose.yml`:
- `ROLE_CLIENT_ADDR` (default `10.10.0.2/24`)
- `ROLE_NODE_A_CLIENT_ADDR` (default `10.10.0.1/24`)
- `ROLE_NODE_A_AB_ADDR` (default `10.20.0.1/24`)
- `ROLE_NODE_B_AB_ADDR` (default `10.20.0.2/24`)
- `ROLE_NODE_B_BC_ADDR` (default `10.30.0.1/24`)
- `ROLE_NODE_C_BC_ADDR` (default `10.30.0.2/24`)
- `CLIENT_SUBNET` (default `10.10.0.0/24`)
- `PORT_CLIENT` (default `51820`)
- `PORT_AB` (default `51821`)
- `PORT_BC` (default `51822`)
- `NODE_A_ENDPOINT` (default `node-a:51820`)
- `NODE_B_ENDPOINT` (default `node-b:51821`)
- `NODE_C_ENDPOINT` (default `node-c:51822`)
- `DNS_IP` (default `1.1.1.1`)

## Notes
- All containers run with `NET_ADMIN` and `/dev/net/tun`.
- IPv6 is disabled inside containers.
- WireGuard keys are generated on first run and stored in named volumes.
- Keys are shared via the `shared-keys` volume for initial bootstrap.

