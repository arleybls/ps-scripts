# ps-scripts

A collection of PowerShell utility scripts.

## Scripts

### net-logger.ps1

Live TCP connection monitor and logger. Watches TCP connections on service
ports and identifies the hosts behind them. The console shows the monitored
ports (with descriptions for well-known services), a counter of distinct
hosts, and the connections currently active, refreshed until aborted with
Ctrl+C. Each individual host is logged once per service port, and a summary
log groups hosts per service port, ordered by port.

Features:

- **Inbound mode** (default): incoming connections to the ports this host
  listens on, logging the source host of each connection.
- **Outbound mode** (`-Outbound`): connections this host makes to remote
  service ports, logging the destination host.
- Port filtering (`-Ports`), reverse DNS resolution (`-ResolveDns`),
  custom log file (`-LogFile`), refresh rate (`-Refresh`), and more —
  run with `-Help` for the full list.

Quick example:

```powershell
# Watch incoming connections on all listening ports
.\net-logger.ps1

# Watch incoming RDP only, polling every 5 s, logging to a specific file
.\net-logger.ps1 -Ports 3389 -Refresh 5 -LogFile C:\logs\rdp-watch.log

# Log every destination host reached on port 443, with DNS names
.\net-logger.ps1 -Outbound -Ports 443 -ResolveDns
```
