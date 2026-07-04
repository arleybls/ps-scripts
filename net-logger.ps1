<#
.SYNOPSIS
    net-logger - Live monitor of TCP connections on service ports (inbound or outbound).

.DESCRIPTION
    Inbound mode (default): continuously watches every TCP port the host is
    listening on and reports all incoming (established) connections to those
    ports, identifying the SOURCE host of each connection.

    Outbound mode (-Outbound): watches connections this host makes TO remote
    service ports, identifying the DESTINATION host of each connection.

    In either mode, -Ports limits monitoring to just the listed ports.

    Console (refreshed every cycle until aborted with Ctrl+C):
      - The service ports currently being monitored (with a description when the
        port is a well-known service).
      - A counter of how many different source hosts have connected.
      - The connections currently active, ordered by service port.
      - With -ResolveDns, the DNS name of each source IP (resolved in the
        background, cached per IP) is shown next to the IP and in the logs.

    Logs (created under the log directory):
      - net-logger_sources_<date>.log (inbound) or
        net-logger_destinations_<date>.log (outbound) : ONE entry per individual
        host at each service port - logged the first time that host is seen on
        that port (timestamp, service port, host). Use -LogAllEvents to instead
        log every new connection event.
      - net-logger_summary.log (inbound) or net-logger_summary_outbound.log :
        hosts grouped per service port, ordered by service port. Rewritten
        whenever activity changes.

.PARAMETER Help
    Show usage help with examples and exit. Aliases: -h. PowerShell's built-in
    "-?" also works and shows this comment-based help via Get-Help.

.PARAMETER Ports
    List of service ports to monitor. Inbound mode: only these listening ports
    are watched. Outbound mode: only connections to these remote ports are
    watched. Default: inbound watches ALL listening ports; outbound watches
    the built-in well-known service ports.

.PARAMETER Outbound
    Monitor outgoing connections instead of incoming ones: a connection matches
    when its REMOTE port is a monitored service port, and the logged host is
    the destination host this machine connected to.

.PARAMETER Process
    Limit monitoring to connections owned by these processes. Accepts process
    names (without .exe, wildcards allowed) and/or PIDs. Example: -Process w3wp
    watches only IIS worker process connections. Patterns also match IIS
    application pool names, so -Process DefaultAppPool watches one specific
    app pool. In outbound mode with no -Ports, a process filter watches ALL
    remote ports (add -WellKnownOnly to restrict to well-known service ports).

.PARAMETER WellKnownOnly
    Restrict the monitored ports to the built-in well-known service ports.
    Ignored when -Ports is given.

.PARAMETER RefreshSeconds
    Refresh rate: seconds between polling cycles. Default: 2. Alias: -Refresh.

.PARAMETER Csv
    Write the logs as CSV files instead of plain text: the host-entry log gets
    one row per entry (timestamp, port, service, host, DNS name, state,
    process, PID, app pool) and the summary one row per host@port. Auto-named
    files use the .csv extension.

.PARAMETER CsvDelimiter
    Field delimiter for -Csv output. Default: ',' (comma). Use ';' when the
    file is opened by Excel configured with a semicolon list separator
    (common in European/Brazilian regional formats). Note: reading such files
    with Import-Csv then needs -Delimiter ';'.

.PARAMETER LogFile
    Full path of the output log file for host entries. The summary log is
    written next to it as <name>_summary.log (or .csv with -Csv). Overrides
    the automatic file naming under -LogDirectory.

.PARAMETER LogDirectory
    Directory where log files are written with automatic names (ignored when
    -LogFile is given). Default: <script folder>\logs.

.PARAMETER IncludeLoopback
    Also report connections coming from 127.0.0.1 / ::1. Off by default.

.PARAMETER LogAllEvents
    Log every new connection event instead of the default behavior of logging
    only the first occurrence of each source host at each service port.

.PARAMETER ResolveDns
    Resolve source IPs to DNS names (reverse/PTR lookup) and show the name next
    to the IP on the console and in the logs. Off by default. Lookups run on
    background threads and are cached per IP, so they never stall the display;
    a name appears a cycle or two after the source is first seen.

.PARAMETER RunSeconds
    Stop automatically after this many seconds (0 = run until aborted).
    Added to -RunMinutes when both are given.

.PARAMETER RunMinutes
    Stop automatically after this many minutes (0 = run until aborted).
    Added to -RunSeconds when both are given.

.EXAMPLE
    .\net-logger.ps1
    Monitors incoming connections on all listening ports until Ctrl+C.

.EXAMPLE
    .\net-logger.ps1 -Ports 80,443,3389
    Monitors incoming connections on ports 80, 443 and 3389 only.

.EXAMPLE
    .\net-logger.ps1 -Outbound -Ports 443 -ResolveDns
    Logs every destination host this machine connects to on port 443,
    with DNS names resolved.

.EXAMPLE
    .\net-logger.ps1 -Outbound -Process w3wp -ResolveDns
    Logs every destination host the IIS worker processes connect to, on any
    remote port, with DNS names resolved.

.EXAMPLE
    .\net-logger.ps1 -Ports 3389 -Refresh 5 -LogFile C:\logs\rdp-watch.log
    Watches incoming RDP connections, polling every 5 seconds, logging to
    C:\logs\rdp-watch.log (summary in C:\logs\rdp-watch_summary.log).

.EXAMPLE
    .\net-logger.ps1 -Help
    Shows usage help with examples (-h and -? also work).

.NOTES
    Copyright (c) 2026 Arley Silveira. All rights reserved.

    Requires Windows 8 / Server 2012 or later (Get-NetTCPConnection).
    Process names of listeners resolve best when run as Administrator.
    IIS worker processes (w3wp) are shown with their application pool name in
    brackets, e.g. w3wp[MyAppPool], read from the process command line - this
    also needs an elevated session, since app pools run under other identities.
#>
[CmdletBinding()]
param(
    [Alias('h')]
    [switch]$Help,

    [ValidateRange(1, 65535)]
    [int[]]$Ports = @(),

    [switch]$Outbound,

    [string[]]$Process = @(),

    [switch]$WellKnownOnly,

    [Alias('Refresh')]
    [ValidateRange(1, 3600)]
    [int]$RefreshSeconds = 2,

    [switch]$Csv,

    [ValidateLength(1, 1)]
    [string]$CsvDelimiter = ',',

    [string]$LogFile = '',

    [string]$LogDirectory = '',

    [switch]$IncludeLoopback,

    [switch]$LogAllEvents,

    [switch]$ResolveDns,

    [ValidateRange(0, 86400)]
    [int]$RunSeconds = 0,

    [ValidateRange(0, 10080)]
    [int]$RunMinutes = 0
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Host ''
    Write-Host ' NET-LOGGER - live TCP connection monitor and logger' -ForegroundColor Cyan
    Write-Host ' ===================================================' -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host ' Watches TCP connections on service ports and identifies the hosts behind'
    Write-Host ' them. The console shows the monitored ports (with descriptions for'
    Write-Host ' well-known services), a counter of distinct hosts, and the connections'
    Write-Host ' currently active. Each individual host is logged ONCE per service port.'
    Write-Host ' Runs until aborted with Ctrl+C.'
    Write-Host ''
    Write-Host ' MODES' -ForegroundColor Yellow
    Write-Host '   Inbound (default)  incoming connections to ports this host listens on;'
    Write-Host '                      logs the SOURCE host of each connection.'
    Write-Host '   Outbound           connections this host makes to remote service ports;'
    Write-Host '                      logs the DESTINATION host. Enable with -Outbound.'
    Write-Host ''
    Write-Host ' PARAMETERS' -ForegroundColor Yellow
    Write-Host '   -Ports <p1,p2,...>     Monitor only these service ports.'
    Write-Host '   -Outbound              Watch outgoing instead of incoming connections.'
    Write-Host '   -Process <name|pid>    Only connections owned by these processes (names'
    Write-Host '                          without .exe, wildcards OK, or PIDs). IIS app pool'
    Write-Host '                          names also match (e.g. -Process DefaultAppPool).'
    Write-Host '                          Outbound with -Process and no -Ports watches ALL'
    Write-Host '                          remote ports.'
    Write-Host '   -WellKnownOnly         Restrict to well-known service ports.'
    Write-Host '   -RefreshSeconds <n>    Refresh rate in seconds (default 2). Alias: -Refresh.'
    Write-Host '   -Csv                   Write logs as CSV files instead of plain text.'
    Write-Host '   -CsvDelimiter <char>   CSV field delimiter (default ","). Use ";" for'
    Write-Host '                          Excel with semicolon regional list separators.'
    Write-Host '   -LogFile <path>        Output log file for host entries; the summary is'
    Write-Host '                          written next to it as <name>_summary.log/.csv.'
    Write-Host '   -LogDirectory <path>   Folder for auto-named logs (default: .\logs).'
    Write-Host '   -ResolveDns            Resolve host IPs to DNS names (background, cached).'
    Write-Host '   -IncludeLoopback       Also report connections from/to 127.0.0.1 / ::1.'
    Write-Host '   -LogAllEvents          Log every connection event, not one entry per host.'
    Write-Host '   -RunSeconds <n>        Stop automatically after n seconds (0 = run forever).'
    Write-Host '   -RunMinutes <n>        Stop automatically after n minutes; added to'
    Write-Host '                          -RunSeconds when both are given.'
    Write-Host '   -Help | -h | -?        Show this help.'
    Write-Host ''
    Write-Host ' EXAMPLES' -ForegroundColor Yellow
    Write-Host '   .\net-logger.ps1'
    Write-Host '       Monitor incoming connections on all listening ports.'
    Write-Host '   .\net-logger.ps1 -Ports 80,443,3389'
    Write-Host '       Monitor incoming connections on ports 80, 443 and 3389 only.'
    Write-Host '   .\net-logger.ps1 -Outbound -Ports 443 -ResolveDns'
    Write-Host '       Log every destination host reached on port 443, with DNS names.'
    Write-Host '   .\net-logger.ps1 -Outbound -Process w3wp -ResolveDns'
    Write-Host '       Log every destination host IIS worker processes connect to.'
    Write-Host '   .\net-logger.ps1 -Ports 3389 -Refresh 5 -LogFile C:\logs\rdp-watch.log'
    Write-Host '       Watch incoming RDP, poll every 5 s, log to a specific file.'
    Write-Host ''
    Write-Host ' LOGS' -ForegroundColor Yellow
    Write-Host '   net-logger_sources_<date>.log       one entry per source host per port (inbound)'
    Write-Host '   net-logger_destinations_<date>.log  one entry per destination host per port (outbound)'
    Write-Host '   net-logger_summary[_outbound].log   hosts grouped per service port, ordered by port'
    Write-Host ''
    Write-Host ' Full parameter documentation: Get-Help .\net-logger.ps1 -Detailed' -ForegroundColor DarkGray
    Write-Host ''
}

if ($Help) { Show-Usage; return }

# ---------------------------------------------------------------------------
# Well-known service port descriptions
# ---------------------------------------------------------------------------
$WellKnownPorts = @{
      20 = 'FTP (Data)'
      21 = 'FTP (Control)'
      22 = 'SSH'
      23 = 'Telnet'
      25 = 'SMTP'
      53 = 'DNS'
      67 = 'DHCP (Server)'
      68 = 'DHCP (Client)'
      69 = 'TFTP'
      80 = 'HTTP'
      88 = 'Kerberos'
     110 = 'POP3'
     111 = 'RPCbind'
     119 = 'NNTP'
     123 = 'NTP'
     135 = 'MS RPC Endpoint Mapper'
     137 = 'NetBIOS Name Service'
     138 = 'NetBIOS Datagram'
     139 = 'NetBIOS Session'
     143 = 'IMAP'
     161 = 'SNMP'
     179 = 'BGP'
     389 = 'LDAP'
     443 = 'HTTPS'
     445 = 'SMB / CIFS'
     465 = 'SMTPS'
     514 = 'Syslog'
     587 = 'SMTP (Submission)'
     636 = 'LDAPS'
     993 = 'IMAPS'
     995 = 'POP3S'
    1080 = 'SOCKS Proxy'
    1433 = 'MS SQL Server'
    1521 = 'Oracle Database'
    1723 = 'PPTP VPN'
    2049 = 'NFS'
    3268 = 'LDAP Global Catalog'
    3306 = 'MySQL'
    3389 = 'RDP (Remote Desktop)'
    5060 = 'SIP'
    5432 = 'PostgreSQL'
    5900 = 'VNC'
    5985 = 'WinRM (HTTP)'
    5986 = 'WinRM (HTTPS)'
    6379 = 'Redis'
    8080 = 'HTTP (Alternate)'
    8443 = 'HTTPS (Alternate)'
   27017 = 'MongoDB'
}

function Get-PortDescription {
    param([int]$Port)
    if ($WellKnownPorts.ContainsKey($Port)) { return $WellKnownPorts[$Port] }
    return ''
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
# Total run limit in seconds; 0 = run until aborted
$RunLimitSeconds = $RunSeconds + ($RunMinutes * 60)

# Mode: inbound logs the SOURCE of incoming connections, outbound the DESTINATION
$ModeName = 'INBOUND'
$HostRole = 'source'
if ($Outbound) { $ModeName = 'OUTBOUND'; $HostRole = 'destination' }

$LogExtension = '.log'
if ($Csv) { $LogExtension = '.csv' }

if (-not [string]::IsNullOrWhiteSpace($LogFile)) {
    # Explicit output log file; summary goes next to it as <name>_summary.log/.csv
    if (-not [System.IO.Path]::IsPathRooted($LogFile)) {
        $LogFile = Join-Path (Get-Location).Path $LogFile
    }
    $LogDirectory = Split-Path -Parent $LogFile
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    $EventLogFile   = $LogFile
    $SummaryLogFile = Join-Path $LogDirectory `
        ([System.IO.Path]::GetFileNameWithoutExtension($LogFile) + '_summary' + $LogExtension)
}
else {
    if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
        $LogDirectory = Join-Path $PSScriptRoot 'logs'
    }
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    if ($Outbound) {
        $EventLogFile   = Join-Path $LogDirectory ("net-logger_destinations_{0}{1}" -f (Get-Date -Format 'yyyy-MM-dd'), $LogExtension)
        $SummaryLogFile = Join-Path $LogDirectory ('net-logger_summary_outbound' + $LogExtension)
    }
    else {
        $EventLogFile   = Join-Path $LogDirectory ("net-logger_sources_{0}{1}" -f (Get-Date -Format 'yyyy-MM-dd'), $LogExtension)
        $SummaryLogFile = Join-Path $LogDirectory ('net-logger_summary' + $LogExtension)
    }
}

$LoopbackAddresses = @('127.0.0.1', '::1', '0.0.0.0', '::')

# State kept across polling cycles
$SeenConnections = @{}   # key: "remoteIP:remotePort->localPort"  (active/known sockets)
$DistinctHosts   = New-Object 'System.Collections.Generic.HashSet[string]'
$HostPortStats   = @{}   # key: "localPort|remoteIP" -> stats record
$ProcessCache    = @{}   # PID -> process name
$AppPoolCache    = @{}   # PID -> IIS app pool name ('' = none/unknown)
$DnsCache        = @{}   # IP -> resolved DNS name ('' = lookup done, no name)
$DnsPending      = @{}   # IP -> in-flight Task[System.Net.IPHostEntry]
$DnsUpdated      = $false # a pending lookup completed -> refresh summary log
$TotalEvents     = 0
$StartTime       = Get-Date

function Get-ProcessName {
    param([int]$ProcessId)
    if (-not $ProcessCache.ContainsKey($ProcessId)) {
        $name = '-'
        try {
            $p = Get-Process -Id $ProcessId -ErrorAction Stop
            $name = $p.ProcessName
        } catch { }
        $ProcessCache[$ProcessId] = $name
    }
    return $ProcessCache[$ProcessId]
}

function Get-AppPoolFromCommandLine {
    # Extracts the IIS application pool name from a w3wp.exe command line
    # (w3wp.exe -ap "PoolName" ...). Returns '' when there is none.
    param([string]$CommandLine)
    if ([string]::IsNullOrEmpty($CommandLine)) { return '' }
    if ($CommandLine -match '-ap\s+"([^"]+)"') { return $Matches[1] }
    if ($CommandLine -match '-ap\s+(\S+)')     { return $Matches[1] }
    return ''
}

function Get-AppPoolName {
    # IIS app pool of a worker process (w3wp only), read once from its command
    # line via CIM and cached. Needs an elevated session for other users' PIDs.
    param([int]$ProcessId)
    if (-not $AppPoolCache.ContainsKey($ProcessId)) {
        $pool = ''
        if ((Get-ProcessName -ProcessId $ProcessId) -eq 'w3wp') {
            try {
                $proc = Get-CimInstance -ClassName Win32_Process `
                        -Filter "ProcessId = $ProcessId" -ErrorAction Stop
                if ($null -ne $proc) {
                    $pool = Get-AppPoolFromCommandLine -CommandLine ([string]$proc.CommandLine)
                }
            } catch { }
        }
        $AppPoolCache[$ProcessId] = $pool
    }
    return $AppPoolCache[$ProcessId]
}

function Get-ProcessLabel {
    # Process name, with the IIS app pool in brackets when there is one
    param([int]$ProcessId)
    $name = Get-ProcessName -ProcessId $ProcessId
    $pool = Get-AppPoolName -ProcessId $ProcessId
    if ($pool -ne '') { return "{0}[{1}]" -f $name, $pool }
    return $name
}

function Test-ProcessMatch {
    # True when no -Process filter is set, or the owning process matches one of
    # the given names (wildcards OK, '.exe' ignored) or PIDs.
    param([int]$OwningPid)

    if ($Process.Count -eq 0) { return $true }
    $name = Get-ProcessName -ProcessId $OwningPid
    $pool = Get-AppPoolName -ProcessId $OwningPid
    foreach ($p in $Process) {
        if ($p -match '^\d+$') {
            if ($OwningPid -eq [int]$p) { return $true }
        }
        else {
            $pattern = $p -replace '\.exe$', ''
            if ($name -like $pattern) { return $true }
            if ($pool -ne '' -and $pool -like $pattern) { return $true }
        }
    }
    return $false
}

function Get-SourceDnsName {
    # Non-blocking reverse DNS: lookups run on thread-pool threads via
    # GetHostEntryAsync and are cached per IP. Returns '' until a name is known.
    param([string]$Ip)

    if (-not $ResolveDns) { return '' }
    if ($DnsCache.ContainsKey($Ip)) { return $DnsCache[$Ip] }

    if ($DnsPending.ContainsKey($Ip)) {
        $task = $DnsPending[$Ip]
        if ($task.IsCompleted) {
            $name = ''
            try {
                if (-not $task.IsFaulted -and $null -ne $task.Result) {
                    $name = [string]$task.Result.HostName
                    if ($name -eq $Ip) { $name = '' }  # no PTR record, echoes the IP
                }
            } catch { }
            $DnsCache[$Ip] = $name
            $DnsPending.Remove($Ip)
            $script:DnsUpdated = $true
            return $name
        }
        return ''  # still resolving on a background thread
    }

    try {
        $DnsPending[$Ip] = [System.Net.Dns]::GetHostEntryAsync($Ip)
    } catch {
        $DnsCache[$Ip] = ''
    }
    return ''
}

function Write-EventLog {
    param([datetime]$When, [int]$Port, [string]$SourceHost, [int]$SourcePort, [string]$State,
          [string]$ProcName, [int]$ProcId, [string]$Pool = '')
    $desc = Get-PortDescription -Port $Port
    if ([string]::IsNullOrEmpty($desc)) { $desc = 'unknown service' }
    $dns = Get-SourceDnsName -Ip $SourceHost

    if ($Csv) {
        [pscustomobject]@{
            Timestamp   = $When.ToString('yyyy-MM-dd HH:mm:ss')
            ServicePort = $Port
            Service     = $desc
            HostRole    = $HostRole
            Host        = $SourceHost
            HostPort    = $SourcePort
            DnsName     = $dns
            State       = $State
            Process     = $ProcName
            PID         = $ProcId
            AppPool     = $Pool
        } | Export-Csv -LiteralPath $EventLogFile -Append -NoTypeInformation -Encoding UTF8 `
                       -Delimiter ([char]$CsvDelimiter)
        return
    }

    $src = "{0}:{1}" -f $SourceHost, $SourcePort
    if ($dns -ne '') { $src = "$src ($dns)" }
    $procPart = "process {0} (PID {1})" -f $ProcName, $ProcId
    if ($Pool -ne '') { $procPart = "process {0} (PID {1}, pool {2})" -f $ProcName, $ProcId, $Pool }
    $line = "{0:yyyy-MM-dd HH:mm:ss} | port {1,5} ({2}) | {3} {4} | {5} | {6}" -f `
            $When, $Port, $desc, $HostRole, $src, $State, $procPart
    Add-Content -LiteralPath $EventLogFile -Value $line -Encoding UTF8
}

function Write-SummaryLog {
    # Connections grouped by source host at each service port, ordered by service port.
    if ($Csv) {
        $byPort = $HostPortStats.Values | Group-Object -Property Port | Sort-Object { [int]$_.Name }
        $rows = @()
        foreach ($portGroup in $byPort) {
            $port = [int]$portGroup.Name
            $desc = Get-PortDescription -Port $port
            if ([string]::IsNullOrEmpty($desc)) { $desc = 'unknown service' }
            foreach ($h in ($portGroup.Group | Sort-Object -Property SourceHost)) {
                $dnsName = ''
                if ($DnsCache.ContainsKey($h.SourceHost)) { $dnsName = $DnsCache[$h.SourceHost] }
                $rows += [pscustomobject]@{
                    ServicePort = $port
                    Service     = $desc
                    HostRole    = $HostRole
                    Host        = $h.SourceHost
                    DnsName     = $dnsName
                    Connections = $h.Count
                    FirstSeen   = $h.FirstSeen.ToString('yyyy-MM-dd HH:mm:ss')
                    LastSeen    = $h.LastSeen.ToString('yyyy-MM-dd HH:mm:ss')
                    Processes   = (@($h.Processes.Keys) | Sort-Object) -join ';'
                }
            }
        }
        $rows | Export-Csv -LiteralPath $SummaryLogFile -NoTypeInformation -Encoding UTF8 `
                           -Delimiter ([char]$CsvDelimiter)
        return
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('==========================================================================')
    [void]$sb.AppendLine(" net-logger summary ($ModeName) - connections by $HostRole host per service port")
    [void]$sb.AppendLine(" Monitoring since : $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))")
    [void]$sb.AppendLine(" Last updated     : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))")
    [void]$sb.AppendLine(" Distinct hosts   : $($DistinctHosts.Count)")
    [void]$sb.AppendLine(" Connection events: $TotalEvents")
    [void]$sb.AppendLine('==========================================================================')

    $byPort = $HostPortStats.Values | Group-Object -Property Port | Sort-Object { [int]$_.Name }
    foreach ($portGroup in $byPort) {
        $port = [int]$portGroup.Name
        $desc = Get-PortDescription -Port $port
        if ([string]::IsNullOrEmpty($desc)) { $desc = 'unknown service' }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine(("---- Service port {0} ({1}) ----" -f $port, $desc))
        $hosts = $portGroup.Group | Sort-Object -Property SourceHost
        foreach ($h in $hosts) {
            $hostLabel = $h.SourceHost
            if ($DnsCache.ContainsKey($h.SourceHost) -and $DnsCache[$h.SourceHost] -ne '') {
                $hostLabel = "{0} ({1})" -f $h.SourceHost, $DnsCache[$h.SourceHost]
            }
            $procList = (@($h.Processes.Keys) | Sort-Object) -join ','
            [void]$sb.AppendLine(("  {0,-56} connections: {1,-5} first: {2:yyyy-MM-dd HH:mm:ss}  last: {3:yyyy-MM-dd HH:mm:ss}  process: {4}" -f `
                $hostLabel, $h.Count, $h.FirstSeen, $h.LastSeen, $procList))
        }
    }

    Set-Content -LiteralPath $SummaryLogFile -Value $sb.ToString() -Encoding UTF8
}

function Show-Console {
    param(
        [object[]]$MonitoredPorts,   # sorted unique ints
        [object[]]$ActiveConnections # connection display records, sorted by port
    )

    try { Clear-Host } catch { }

    $elapsed = (Get-Date) - $StartTime
    $modeText = 'incoming'
    if ($Outbound) { $modeText = 'outgoing' }
    Write-Host '=============================================================================' -ForegroundColor DarkCyan
    Write-Host ("  NET-LOGGER [{0}]  -  {1} TCP connection monitor  (press Ctrl+C to abort)" -f `
                $ModeName, $modeText)                                                          -ForegroundColor Cyan
    Write-Host ("  Host: {0}   Started: {1:yyyy-MM-dd HH:mm:ss}   Uptime: {2:hh\:mm\:ss}" -f `
                $env:COMPUTERNAME, $StartTime, $elapsed)                                       -ForegroundColor Gray
    Write-Host ("  Event log  : {0}" -f $EventLogFile)                                         -ForegroundColor DarkGray
    Write-Host ("  Summary log: {0}" -f $SummaryLogFile)                                       -ForegroundColor DarkGray
    Write-Host '=============================================================================' -ForegroundColor DarkCyan

    # --- monitored service ports ---
    Write-Host ''
    $portsHeader = 'LISTENING SERVICE PORTS'
    if ($Outbound) { $portsHeader = 'MONITORED REMOTE SERVICE PORTS' }
    $portsCount = "$($MonitoredPorts.Count)"
    if ($watchAllPorts) { $portsCount = 'ALL' }
    Write-Host ("  {0} ({1})" -f $portsHeader, $portsCount) -ForegroundColor Yellow
    if ($Ports.Count -gt 0) {
        Write-Host ("    port filter: {0}" -f (($Ports | Sort-Object) -join ', ')) -ForegroundColor DarkYellow
    }
    if ($Process.Count -gt 0) {
        Write-Host ("    process filter: {0}" -f ($Process -join ', ')) -ForegroundColor DarkYellow
    }
    if ($watchAllPorts) {
        Write-Host '    (all remote ports - limited by the process filter)' -ForegroundColor Green
    }
    $wellKnown = @($MonitoredPorts | Where-Object { $WellKnownPorts.ContainsKey([int]$_) })
    $others    = @($MonitoredPorts | Where-Object { -not $WellKnownPorts.ContainsKey([int]$_) })
    foreach ($p in $wellKnown) {
        Write-Host ("    {0,6}  {1}" -f $p, (Get-PortDescription -Port $p)) -ForegroundColor Green
    }
    if ($others.Count -gt 0) {
        Write-Host ("    other : {0}" -f (($others | ForEach-Object { "$_" }) -join ', ')) -ForegroundColor DarkGray
    }

    # --- counters ---
    Write-Host ''
    Write-Host ("  DIFFERENT {0,-12} : {1}" -f "$($HostRole.ToUpper()) HOSTS", $DistinctHosts.Count) -ForegroundColor Magenta
    Write-Host ("  HOSTS LOGGED           : {0}  (unique host @ service port)" -f $HostPortStats.Count) -ForegroundColor Magenta
    Write-Host ("  CONNECTION EVENTS      : {0}" -f $TotalEvents)         -ForegroundColor Magenta
    Write-Host ("  ACTIVE CONNECTIONS NOW : {0}" -f $ActiveConnections.Count) -ForegroundColor Magenta

    # --- current connections ---
    Write-Host ''
    Write-Host '  CURRENT CONNECTIONS (ordered by service port)' -ForegroundColor Yellow
    if ($ActiveConnections.Count -eq 0) {
        Write-Host '    (none)' -ForegroundColor DarkGray
    }
    else {
        Write-Host ('    {0,-28} {1,-44} {2,-12} {3,-24} {4}' -f `
                    'LOCAL SOCKET', 'REMOTE SOCKET', 'STATE', 'PROCESS', 'SERVICE') -ForegroundColor White
        Write-Host ('    ' + ('-' * 124)) -ForegroundColor DarkGray
        foreach ($c in $ActiveConnections) {
            $svcColor = 'DarkGray'
            if ($c.Service -ne '') { $svcColor = 'Green' }
            Write-Host ('    {0,-28} {1,-44} {2,-12} {3,-24} ' -f `
                        $c.LocalSocket, $c.RemoteSocket, $c.State, $c.Process) -NoNewline
            Write-Host $c.Service -ForegroundColor $svcColor
        }
    }
    Write-Host ''
    Write-Host ("  Refresh every {0}s - last poll {1:HH:mm:ss}" -f $RefreshSeconds, (Get-Date)) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
Write-Host "net-logger starting ($ModeName)... logs -> $LogDirectory"
$portFilterText = 'all'
if ($Ports.Count -gt 0) { $portFilterText = ($Ports | Sort-Object) -join ',' }
elseif ($WellKnownOnly) { $portFilterText = 'well-known' }
$processFilterText = 'any'
if ($Process.Count -gt 0) { $processFilterText = $Process -join ',' }
if (-not $Csv) {
    # Session markers only make sense in the plain-text log format
    Add-Content -LiteralPath $EventLogFile -Encoding UTF8 -Value `
        ("{0:yyyy-MM-dd HH:mm:ss} | === net-logger session started on {1} (mode: {2}, ports: {3}, process: {4}) ===" -f `
         (Get-Date), $env:COMPUTERNAME, $ModeName, $portFilterText, $processFilterText)
}

try {
    while ($true) {
        # 1. Build the set of service ports to watch
        $watchSet = New-Object 'System.Collections.Generic.HashSet[int]'
        $watchAllPorts = $false
        if ($Outbound) {
            # Outbound: -Ports wins; else well-known set, except that a process
            # filter with no port constraints watches ALL remote ports
            if ($Ports.Count -gt 0) { foreach ($p in $Ports) { [void]$watchSet.Add([int]$p) } }
            elseif ($WellKnownOnly -or $Process.Count -eq 0) {
                foreach ($p in @($WellKnownPorts.Keys)) { [void]$watchSet.Add([int]$p) }
            }
            else { $watchAllPorts = $true }
        }
        else {
            # Inbound: ports this host is listening on, optionally limited to
            # -Ports and/or the well-known set
            $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
            foreach ($l in $listeners) {
                $lp = [int]$l.LocalPort
                if (($Ports.Count -eq 0 -or $Ports -contains $lp) -and
                    (-not $WellKnownOnly -or $WellKnownPorts.ContainsKey($lp))) {
                    [void]$watchSet.Add($lp)
                }
            }
        }
        $monitoredPorts = @($watchSet | Sort-Object)

        # 2. Matching connections: LOCAL port watched (inbound) / REMOTE port
        #    watched (outbound), optionally owned by a -Process match
        $connections = @(Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object {
                $_.State -ne 'Listen' -and $_.State -ne 'Bound' -and
                ($watchAllPorts -or
                 $(if ($Outbound) { $watchSet.Contains([int]$_.RemotePort) }
                   else           { $watchSet.Contains([int]$_.LocalPort) })) -and
                ($IncludeLoopback -or ($LoopbackAddresses -notcontains $_.RemoteAddress)) -and
                (Test-ProcessMatch -OwningPid ([int]$_.OwningProcess))
            })

        $summaryDirty = $false
        $activeKeys = New-Object 'System.Collections.Generic.HashSet[string]'
        $display = @()

        foreach ($conn in $connections) {
            # Service port: local side for inbound, remote side for outbound.
            # The logged host is the remote address in both modes.
            $port    = [int]$conn.LocalPort
            if ($Outbound) { $port = [int]$conn.RemotePort }
            $srcHost  = [string]$conn.RemoteAddress
            $srcPort  = [int]$conn.RemotePort
            $ownPid    = [int]$conn.OwningProcess
            $procName  = Get-ProcessName -ProcessId $ownPid
            $procPool  = Get-AppPoolName -ProcessId $ownPid
            $procLabel = Get-ProcessLabel -ProcessId $ownPid
            $key      = "{0}:{1}<->{2}" -f $srcHost, $srcPort, [int]$conn.LocalPort
            [void]$activeKeys.Add($key)

            # New connection -> log the event and update statistics
            if (-not $SeenConnections.ContainsKey($key)) {
                $now = Get-Date
                $SeenConnections[$key] = $now
                $TotalEvents++
                [void]$DistinctHosts.Add($srcHost)

                $statKey = "{0}|{1}" -f $port, $srcHost
                $isNewSource = -not $HostPortStats.ContainsKey($statKey)
                if ($isNewSource) {
                    $HostPortStats[$statKey] = [pscustomobject]@{
                        Port       = $port
                        SourceHost = $srcHost
                        Count      = 1
                        FirstSeen  = $now
                        LastSeen   = $now
                        Processes  = @{ $procLabel = $true }
                    }
                }
                else {
                    $HostPortStats[$statKey].Count++
                    $HostPortStats[$statKey].LastSeen = $now
                    $HostPortStats[$statKey].Processes[$procLabel] = $true
                }

                # Default: one log entry per individual host at each service port
                if ($isNewSource -or $LogAllEvents) {
                    Write-EventLog -When $now -Port $port -SourceHost $srcHost -SourcePort $srcPort `
                                   -State $conn.State -ProcName $procName -ProcId $ownPid -Pool $procPool
                }
                $summaryDirty = $true
            }

            $remoteSocket = "{0}:{1}" -f $srcHost, $srcPort
            $dnsName = Get-SourceDnsName -Ip $srcHost
            if ($dnsName -ne '') { $remoteSocket = "$remoteSocket ($dnsName)" }

            $display += [pscustomobject]@{
                Port         = $port
                LocalSocket  = "{0}:{1}" -f $conn.LocalAddress, $conn.LocalPort
                RemoteSocket = $remoteSocket
                State        = [string]$conn.State
                Process      = $procLabel
                Service      = Get-PortDescription -Port $port
            }
        }

        # Drop sockets that are no longer present so a reconnect counts as a new event
        $gone = @($SeenConnections.Keys | Where-Object { -not $activeKeys.Contains($_) })
        foreach ($k in $gone) { $SeenConnections.Remove($k) }

        # A background DNS lookup finished -> summary needs the new name
        if ($DnsUpdated) { $summaryDirty = $true; $DnsUpdated = $false }

        if ($summaryDirty) { Write-SummaryLog }

        $display = @($display | Sort-Object -Property Port, RemoteSocket)
        Show-Console -MonitoredPorts $monitoredPorts -ActiveConnections $display

        if ($RunLimitSeconds -gt 0 -and ((Get-Date) - $StartTime).TotalSeconds -ge $RunLimitSeconds) { break }
        Start-Sleep -Seconds $RefreshSeconds
    }
}
finally {
    # Runs on Ctrl+C as well - flush a final summary and close the session cleanly
    if ($HostPortStats.Count -gt 0) { Write-SummaryLog }
    if (-not $Csv) {
        Add-Content -LiteralPath $EventLogFile -Encoding UTF8 -Value `
            ("{0:yyyy-MM-dd HH:mm:ss} | === net-logger session ended (events: {1}, distinct hosts: {2}) ===" -f `
             (Get-Date), $TotalEvents, $DistinctHosts.Count)
    }
    Write-Host ''
    Write-Host ("net-logger stopped. {0} events from {1} distinct hosts. Summary: {2}" -f `
                $TotalEvents, $DistinctHosts.Count, $SummaryLogFile) -ForegroundColor Cyan
}
