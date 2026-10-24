#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SelfTest,
    [string]$OutputRoot = [Environment]::GetFolderPath('Desktop'),
    [ValidateRange(30, 120)][int]$CaptureSeconds = 90
)
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    if ($SelfTest) { throw 'SelfTest requires an elevated PowerShell session.' }
    # Elevate only this collector. The user starts Play in their existing normal launcher.
    $root = [IO.Path]::GetFullPath($OutputRoot)
    if ($root.EndsWith('\')) { $root += '.' }
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-OutputRoot', ('"{0}"' -f $root), '-CaptureSeconds', "$CaptureSeconds")
    $child = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $arguments -Verb RunAs -Wait -PassThru
    exit $child.ExitCode
}

$tag = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$folder = Join-Path $OutputRoot "Forever-Network-$tag"
if (Test-Path -LiteralPath $folder) { throw 'Output folder already exists.' }
New-Item -ItemType Directory -Path $folder | Out-Null
$control = Join-Path $folder 'control.txt'
$markers = Join-Path $folder 'markers.txt'
$started = New-Object 'System.Collections.Generic.List[string]'
$failed = $null
$script:logWriteFailure = $false
function Diagnostic-Line([string]$Path, [string]$Text) {
    try { Add-Content -LiteralPath $Path -Value $Text -Encoding UTF8 }
    catch {
        # Text-log failures must never prevent stopping the collector's ETW sessions.
        $script:logWriteFailure = $true
        Write-Warning "Diagnoselog konnte nicht gespeichert werden: $($_.Exception.Message)"
    }
}
function Mark([string]$Text) {
    $line = 'UTC={0} LOCAL={1} {2}' -f [DateTime]::UtcNow.ToString('o'), [DateTimeOffset]::Now.ToString('o'), $Text
    Diagnostic-Line $markers $line
}
function Native([string]$Exe, [string[]]$Arguments) {
    Diagnostic-Line $control ("COMMAND: $Exe " + ($Arguments -join ' '))
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Exe @Arguments 2>&1 | ForEach-Object { $_.ToString() }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    Diagnostic-Line $control ($output -join [Environment]::NewLine)
    Diagnostic-Line $control "EXIT: $code"
    if ($code -ne 0) { throw "$Exe failed (exit $code). See control.txt." }
}
function Processes {
    $items = @(Get-Process -Name WowB, Agent -ErrorAction SilentlyContinue | Sort-Object ProcessName, Id)
    return (($items | ForEach-Object { '{0}:{1}' -f $_.ProcessName, $_.Id }) -join ', ')
}
function Loopback-Test {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $client = New-Object Net.Sockets.TcpClient
    $accepted = $null
    try {
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
        Mark "SELFTEST pid=$PID loopback_port=$port connect-success begin"
        $client.Connect([Net.IPAddress]::Loopback, $port)
        $accepted = $listener.AcceptTcpClient()
        Mark 'SELFTEST loopback connect succeeded'
    } finally {
        if ($accepted) { $accepted.Dispose() }
        $client.Dispose()
        $listener.Stop()
    }
    $refused = New-Object Net.Sockets.TcpClient
    try {
        $refused.Connect([Net.IPAddress]::Loopback, $port)
        throw 'Expected refused connection unexpectedly succeeded.'
    } catch {
        $socketError = $_.Exception
        while ($socketError.InnerException) { $socketError = $socketError.InnerException }
        if ($socketError -isnot [Net.Sockets.SocketException] -or $socketError.SocketErrorCode -ne [Net.Sockets.SocketError]::ConnectionRefused) { throw }
        Mark 'SELFTEST stopped-listener connect correctly refused'
    } finally { $refused.Dispose() }
    $null = [Net.Dns]::GetHostAddresses('localhost')
    Mark 'SELFTEST localhost resolution completed'
    Start-Sleep -Seconds 2
}

try {
    Mark "Collector starting; SelfTest=$SelfTest collector_pid=$PID"
    $buildFile = Join-Path $PSScriptRoot 'diagnostic-build.txt'
    if (Test-Path -LiteralPath $buildFile) {
        $revision = Get-Content -LiteralPath $buildFile | Where-Object { $_ -match '^revision=[0-9a-f]{40}$' } | Select-Object -First 1
        if ($revision) { Mark $revision }
    }
    Mark 'Metadata-only AFD/DNS level 4; machine-wide network/DNS names; no packet capture or HTTP provider.'
    if (-not $SelfTest -and @(Get-Process -Name WowB -ErrorAction SilentlyContinue).Count -gt 0) {
        throw 'Bitte WoW normal schliessen und die Diagnose neu starten. Den normalen Launcher offen lassen.'
    }
    foreach ($entry in @(@('AFD', 'Microsoft-Windows-Winsock-AFD'), @('DNS', 'Microsoft-Windows-DNS-Client'))) {
        $name = 'Forever-' + $entry[0] + '-' + $tag
        Native 'logman.exe' @('query', 'providers', $entry[1])
        Native 'logman.exe' @('start', $name, '-ets', '-o', (Join-Path $folder ($entry[0] + '.etl')), '-p', $entry[1], '0xffffffffffffffff', '4', '-f', 'bincirc', '-max', '8')
        $started.Add($name)
    }
    Mark ('Capture ready; processes=' + (Processes))
    if ($SelfTest) { Loopback-Test } else {
        Write-Host ''
        Write-Host 'JETZT im normalen Forever Launcher auf Play klicken.' -ForegroundColor Green
        Write-Host "Die Aufzeichnung endet automatisch nach $CaptureSeconds Sekunden. Dieses Fenster offen lassen."
        Write-Host 'Erfasst werden systemweite Verbindungsmetadaten und DNS-Namen. Andere Apps moeglichst schliessen.'
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $previous = $null
        while ($watch.Elapsed.TotalSeconds -lt $CaptureSeconds) {
            $current = Processes
            if ($current -ne $previous) { Mark "Observed processes=$current"; $previous = $current }
            Start-Sleep -Milliseconds 250
        }
    }
} catch {
    $failed = $_.Exception.Message
    Mark "FAILED: $failed"
} finally {
    foreach ($name in $started) {
        try { Native 'logman.exe' @('stop', $name, '-ets') }
        catch { Mark "STOP FAILED for owned session $name : $($_.Exception.Message)"; if (-not $failed) { $failed = $_.Exception.Message } }
    }
    Mark 'Capture stop attempted for all sessions started by this collector.'
}
if ($script:logWriteFailure -and -not $failed) { $failed = 'Diagnostic text could not be written completely.' }

try {
    $etl = @(Get-ChildItem -LiteralPath $folder -Filter '*.etl' -File)
    if ($etl.Count -eq 0) { throw 'No ETL files were produced.' }
    $traceXml = Join-Path $folder 'trace.xml'
    $summary = Join-Path $folder 'summary.txt'
    Native 'tracerpt.exe' (@($etl.FullName) + @('-o', $traceXml, '-of', 'XML', '-summary', $summary, '-y'))
    if (-not (Test-Path -LiteralPath $traceXml) -or (Get-Item -LiteralPath $traceXml).Length -eq 0) { throw 'No decoded trace XML was produced.' }
    $counts = @{}
    $afd = New-Object 'System.Collections.Generic.List[object]'
    foreach ($file in $etl) {
        try {
            Get-WinEvent -Path $file.FullName -Oldest -ErrorAction Stop | ForEach-Object {
                $provider = $_.ProviderName
                if ([string]::IsNullOrEmpty($provider)) { $provider = '(unknown)' }
                if (-not $counts.ContainsKey($provider)) { $counts[$provider] = 0 }
                $counts[$provider]++
                if ($SelfTest -and $provider -eq 'Microsoft-Windows-Winsock-AFD' -and $_.Id -in @(1,4,5,6,1000,1017,1018,1020,1021)) {
                    [xml]$eventXml = $_.ToXml()
                    $data = @{}
                    foreach ($node in $eventXml.SelectNodes('//*[local-name()="EventData"]/*[local-name()="Data"]')) { $data[$node.GetAttribute('Name')] = $node.InnerText }
                    $afd.Add([pscustomobject]@{ Id = $_.Id; Data = $data })
                }
            }
        } catch {
            Mark "Event reader warning for $($file.Name): $($_.Exception.Message)"
            if ($SelfTest -and $file.Name -like 'AFD*') { throw }
        }
    }
    foreach ($key in $counts.Keys) { Mark "Decoded event count: $key=$($counts[$key])" }
    if (-not $counts.ContainsKey('Microsoft-Windows-Winsock-AFD') -or $counts['Microsoft-Windows-Winsock-AFD'] -eq 0) {
        throw 'No decoded AFD events: this capture cannot establish absence of socket attempts.'
    }
    Mark 'Review summary.txt for lost events. Circular files may overwrite old events; absence alone is not proof of no attempted connect.'
    if ($SelfTest) {
        # Older events use UserModePid; newer AfdCreate events use ProcessId. Both map EPROCESS/Endpoint to this test process.
        $creates = @($afd | Where-Object { $_.Id -in @(1,1000) -and (($_.Data['UserModePid'] -as [long]) -eq $PID -or ($_.Data['ProcessId'] -as [long]) -eq $PID) })
        $endpoints = @($creates | ForEach-Object { $_.Data['Endpoint'] } | Select-Object -Unique)
        $connects = @($afd | Where-Object { $_.Id -in @(4,5,1018,1021) -and $_.Data['Endpoint'] -in $endpoints })
        $completed = @($afd | Where-Object { $_.Id -in @(6,1017,1020) -and $_.Data['Endpoint'] -in $endpoints -and ($_.Data.ContainsKey('Error') -or $_.Data.ContainsKey('Status')) })
        Mark "SELFTEST decoded test-process creates=$($creates.Count) connects=$($connects.Count) completions=$($completed.Count)"
        if ($creates.Count -eq 0 -or $connects.Count -eq 0 -or $completed.Count -eq 0) { throw 'SelfTest failed: expected decoded AFD socket/create/connect/completion evidence is missing.' }
        $statuses = @($completed | ForEach-Object {
            $raw = if ($_.Data.ContainsKey('Error')) { $_.Data['Error'] } else { $_.Data['Status'] }
            $number = if ($raw -match '^0x') { [Convert]::ToInt64($raw.Substring(2), 16) } else { [long]$raw }
            $number -band 4294967295L
        } | Select-Object -Unique)
        Mark ('SELFTEST captured completion statuses: ' + (($statuses | ForEach-Object { '0x{0:X8}' -f $_ }) -join ', '))
        # Require a real refused result, not STATUS_PENDING or an unrelated nonzero status.
        $refusedStatuses = @(10061L, 3221226038L, 2147952461L, 1225L, 2147943625L)
        if (0L -notin $statuses -or @($statuses | Where-Object { $_ -in $refusedStatuses }).Count -eq 0) {
            throw 'SelfTest failed: decoded successful AND refused connect results are required.'
        }
        Mark 'SELFTEST PASS: real loopback success/refusal and both decoded connect outcomes verified.' 
    }
} catch {
    Mark "EXPORT/VALIDATION FAILED: $($_.Exception.Message)"
    if (-not $failed) { $failed = $_.Exception.Message }
}

# Explicit allowlist: never include raw ETLs, game/account files, registry exports or environments.
$share = @('trace.xml', 'summary.txt', 'control.txt', 'markers.txt') | ForEach-Object { Join-Path $folder $_ } | Where-Object { Test-Path -LiteralPath $_ }
$zip = $folder + '.zip'
try {
    Compress-Archive -LiteralPath $share -DestinationPath $zip -ErrorAction Stop
    if ((Get-Item -LiteralPath $zip).Length -gt 32MB) { throw 'ZIP exceeds 32 MiB. Keep it local and report this message.' }
    Write-Host ''
    Write-Host "ZIP erstellt. Diese Datei im Chat hochladen: $zip" -ForegroundColor Green
    Write-Host 'Die ETL-Originale bleiben lokal im gleichnamigen Ordner.'
} catch { if (-not $failed) { $failed = $_.Exception.Message } }
if ($failed) {
    Write-Host "DIAGNOSEFEHLER: $failed" -ForegroundColor Red
    Write-Host "Die erzeugten Diagnose-Dateien liegen unter: $folder"
    if (-not $SelfTest) { $null = Read-Host 'Enter zum Schliessen' }
    exit 1
}
if (-not $SelfTest) { $null = Read-Host 'Enter zum Schliessen' }
exit 0
