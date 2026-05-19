# SentinelTrap Sensor

SentinelTrap Sensor is a compact network deception sensor inspired by the
concepts behind T-Pot. It runs fake HTTP, SSH, FTP, and Telnet services on
separate ports, logs interaction attempts to JSON Lines, and shows those events
in a protected dashboard with a source map.

## Safety Notes

- The default bind address is `127.0.0.1`, so only the local machine can reach it.
- Do not expose this to the public internet for a lab demo.
- If you bind to a LAN address, use a controlled lab network and get permission
  from the network owner.
- Run exposed demos inside a VM, container, or disposable lab host. The fake
  services do not execute submitted payloads, but the host is still reachable on
  the network.
- Firewall the sensor away from production devices.
- Treat captured credentials as sensitive, even when they are fake lab examples.

## Run

```powershell
python .\sentineltrap_sensor.py
```

The terminal prints the dashboard username and password. If you do not provide
a password, a random one is generated for that run.

Open the dashboard:

```text
http://127.0.0.1:5000/
```

The dashboard UI is loaded from `dashboard.html`, so keep that file in the same
folder as `sentineltrap_sensor.py`.

The dashboard updates every two seconds. It shows:

- total events and scan hits
- HTTP and SSH hit counts
- a world-style source map
- top source IPs
- raw event details such as paths, user agents, banners, and fake credentials

Set your own dashboard credentials:

```powershell
python .\sentineltrap_sensor.py --dashboard-user instructor --dashboard-password "ChangeThisInClass"
```

Or use environment variables:

```powershell
$env:SENTINELTRAP_DASHBOARD_USER="instructor"
$env:SENTINELTRAP_DASHBOARD_PASSWORD="ChangeThisInClass"
python .\sentineltrap_sensor.py
```

Default fake service ports:

| Service | Port | What it demonstrates |
| --- | ---: | --- |
| HTTP | 8080 | Web probing and fake login capture |
| SSH | 2222 | Banner grabbing and connection logging |
| FTP | 2121 | Command logging and fake credential capture |
| Telnet | 2323 | Legacy plaintext login capture |
| Dashboard | 5000 | Protected event viewing |

## Logs for SIEM or EDR

The sensor writes two logs:

| File | Purpose |
| --- | --- |
| `data/events.jsonl` | Simple UI-friendly event log |
| `data/events-ecs.jsonl` | ECS-style JSON Lines for SIEM/EDR pipelines |
| `samples/sample-events.jsonl` | Sanitized sample UI log for repository viewers |
| `samples/sample-events-ecs.jsonl` | Sanitized sample ECS log for repository viewers |

Each ECS-style event includes fields such as `@timestamp`, `event.action`,
`source.ip`, `source.port`, `destination.ip`, `destination.port`,
`network.protocol`, `service.name`, `observer.type`, and the original event
detail under `sentineltrap.detail`.

Real telemetry is stored locally under `data/`. That directory is ignored by
git because it can contain internal IP addresses, user agents, and submitted
credentials from scans or login attempts.

## Demo Commands

HTTP page visit:

```powershell
curl.exe http://127.0.0.1:8080/
```

HTTP credential attempt:

```powershell
curl.exe -X POST http://127.0.0.1:8080/login -d "username=admin&password=password123"
```

Suspicious web path:

```powershell
curl.exe http://127.0.0.1:8080/.env
```

Scan the fake HTTP and SSH ports:

```powershell
nmap -sV -p 8080,2222 127.0.0.1
```

If `nmap` is not installed, these Windows checks still create dashboard events:

Port connection checks on Windows:

```powershell
Test-NetConnection 127.0.0.1 -Port 2222
Test-NetConnection 127.0.0.1 -Port 2121
Test-NetConnection 127.0.0.1 -Port 2323
```

If you have `nc` or `ncat` installed:

```powershell
ncat 127.0.0.1 2121
ncat 127.0.0.1 2323
```

## Demo Flow

1. Start the sensor and open the dashboard.
2. Visit the fake HTTP page and submit a fake username and password.
3. Run a scan against ports `8080` and `2222`, then watch the source map and
   event table update.
4. Probe `.env`, `wp-login.php`, or `/admin` and point out how scanners look for
   common weak spots.
5. Connect to the fake SSH, FTP, and Telnet ports.
6. Open `data/events.jsonl` and `data/events-ecs.jsonl` and show how the same
   activity can be used by the dashboard and by SIEM/EDR tools.

## Source Map and GeoIP

Localhost and private lab-network traffic is shown as lab traffic on the
map. Real geographic locations require public source IPs and GeoIP enrichment.

Enable public GeoIP lookup:

```powershell
python .\sentineltrap_sensor.py --geo-lookup
```

This uses `ipwho.is` for public IP addresses and caches results in
`data/geo-cache.json`. It does not look up localhost or private RFC1918 lab
addresses.

## Customizing

Change ports:

```powershell
python .\sentineltrap_sensor.py --http-port 8081 --ssh-port 2022 --dashboard-port 5050
```

Make it reachable from other machines on a lab network:

```powershell
python .\sentineltrap_sensor.py --bind 0.0.0.0
```

Use this only in a controlled network.

Expose only the demo ports you want participants to scan. The sensor records
traffic that reaches its listening fake services, so a scan of closed ports will
not appear unless you add listeners for those ports.
