# NetShield v0.1

A learning-oriented DNS filtering service written in Python with dnslib, FastAPI, SQLite and Docker.

## Prerequisites
- Windows with WSL2 and Docker Desktop using WSL integration, or a Linux Docker Engine
- Docker Compose v2

## Start
From a WSL terminal in this directory:

```sh
docker compose up --build -d
docker compose logs --tail=40 netshield
```

Dashboard: http://localhost:8080

## Test in WSL
Install `dnsutils` if `dig` is missing (`sudo apt update && sudo apt install -y dnsutils`).

```sh
dig @127.0.0.1 -p 5353 doubleclick.net A +short
dig @127.0.0.1 -p 5353 doubleclick.net A +noall +comments
dig @127.0.0.1 -p 5353 example.com A +short
dig +tcp @127.0.0.1 -p 5353 example.com A +short
curl http://localhost:8080/api/stats
```

A blocked name returns `NXDOMAIN` (seen with `+comments`); the allowed name should resolve if the upstream is reachable.

## Test in Windows PowerShell

```powershell
Resolve-DnsName doubleclick.net -Server 127.0.0.1 -Port 5353
Invoke-RestMethod http://localhost:8080/api/stats
```

Some Windows versions lack `-Port` for Resolve-DnsName; use `dig` in WSL then.

## Blocklist edits
Edit `data/blocklist.txt` with one domain per line. Restart to reload:

```sh
docker compose restart netshield
```

## Stop
```sh
docker compose down
```

## Limitations and safety
- Localhost-only host-port publishing. Do not point your router at it yet.
- Basic blocking via suffix matching; upstream forwarding with a 3-second timeout; no cache, encrypted upstream, automatic list updates, IPv6 listener, DoH bypass mitigation, or authentication on dashboard.
- DNS logs contain browsing metadata. The dashboard is unprotected, so keep it local.
- DNS filtering cannot reliably remove YouTube in-video ads.
- Your computer must remain on for DNS to work when deployed to the network.
- Blocklist entries may cause breakage; make changes carefully.
- Avoid exposing port 53 to the internet; never create an open recursive resolver.

## Run local unit tests (optional)

From the project directory in WSL with Python dependencies installed:

```sh
PYTHONPATH=. python3 -m unittest discover -s tests -v
```
