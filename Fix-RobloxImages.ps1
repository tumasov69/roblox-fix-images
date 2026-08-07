[CmdletBinding()]
param(
    [switch]$DiagnoseOnly,
    [switch]$Revert,
    [switch]$Force
)

$TestHost   = 'tr.rbxcdn.com'
$BackupPath = Join-Path $env:ProgramData 'RobloxDnsFix\backup.json'

$Candidates = @(
    [pscustomobject]@{ Name = 'Quad9';      V4 = @('9.9.9.9','149.112.112.112'); V6 = @('2620:fe::fe','2620:fe::9') }
    [pscustomobject]@{ Name = 'Cloudflare'; V4 = @('1.1.1.1','1.0.0.1');         V6 = @('2606:4700:4700::1111','2606:4700:4700::1001') }
    [pscustomobject]@{ Name = 'Google';     V4 = @('8.8.8.8','8.8.4.4');         V6 = @('2001:4860:4860::8888','2001:4860:4860::8844') }
    [pscustomobject]@{ Name = 'AdGuard';    V4 = @('94.140.14.14','94.140.15.15'); V6 = @('2a10:50c0::ad1:ff','2a10:50c0::ad2:ff') }
)

try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

function Write-Head($text) {
    Write-Host ''
    Write-Host ('  ' + $text) -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * $text.Length)) -ForegroundColor DarkCyan
}
function Write-Ok   ($t) { Write-Host '  [ OK ]  ' -ForegroundColor Green      -NoNewline; Write-Host $t }
function Write-Bad  ($t) { Write-Host '  [ !! ]  ' -ForegroundColor Red        -NoNewline; Write-Host $t }
function Write-Warn ($t) { Write-Host '  [ ?? ]  ' -ForegroundColor Yellow     -NoNewline; Write-Host $t }
function Write-Info ($t) { Write-Host '          '                             -NoNewline; Write-Host $t -ForegroundColor Gray }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Elevated {
    param([string[]]$ExtraArgs = @())
    $psArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"") + $ExtraArgs
    try {
        Start-Process powershell.exe -ArgumentList $psArgs -Verb RunAs -ErrorAction Stop
        return $true
    } catch {
        Write-Bad 'Не удалось получить права администратора (вы нажали "Нет"?).'
        return $false
    }
}

function Wait-Close {
    Write-Host ''
    try { Read-Host '  Нажмите Enter, чтобы закрыть окно' | Out-Null } catch { }
}

function Show-Banner {
    $art = @(
        '  ██████╗ ███████╗██╗   ██╗██████╗  █████╗ ███████╗███████╗'
        '  ██╔══██╗██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝██╔════╝'
        '  ██║  ██║█████╗  ██║   ██║██████╔╝███████║███████╗█████╗  '
        '  ██║  ██║██╔══╝  ╚██╗ ██╔╝██╔══██╗██╔══██║╚════██║██╔══╝  '
        '  ██████╔╝███████╗ ╚████╔╝ ██████╔╝██║  ██║███████║███████╗'
        '  ╚═════╝ ╚══════╝  ╚═══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝'
    )
    Write-Host ''
    foreach ($line in $art) { Write-Host $line -ForegroundColor Cyan }
    Write-Host '   Roblox: не грузятся картинки и иконки' -ForegroundColor White
    Write-Host '   диагностика и починка DNS' -ForegroundColor DarkGray
    Write-Host ''
}

function Test-Resolver {
    param([string]$Server, [int]$Samples = 2)
    $ips  = @()
    $best = [int]::MaxValue
    for ($n = 0; $n -lt $Samples; $n++) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $p = @{ Name = $TestHost; Type = 'A'; DnsOnly = $true; NoHostsFile = $true; ErrorAction = 'Stop' }
            if ($Server) { $p['Server'] = $Server }
            $r = @(Resolve-DnsName @p | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
        } catch { $r = @() }
        $sw.Stop()
        if ($r.Count -gt 0) {
            $ips = $r
            if ($sw.ElapsedMilliseconds -lt $best) { $best = [int]$sw.ElapsedMilliseconds }
        }
    }
    if ($ips.Count -eq 0) { $best = -1 }
    [pscustomobject]@{
        Ok  = ($ips.Count -gt 0)
        Ips = $ips
        Ms  = $best
    }
}

function Test-EdgeLatency {
    param([string]$Ip, [int]$TimeoutMs = 2000)
    $best = [int]::MaxValue
    for ($n = 0; $n -lt 2; $n++) {
        $client = New-Object Net.Sockets.TcpClient
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $async = $client.BeginConnect($Ip, 443, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected) {
                $client.EndConnect($async)
                $sw.Stop()
                if ($sw.ElapsedMilliseconds -lt $best) { $best = [int]$sw.ElapsedMilliseconds }
            }
        } catch { } finally { $sw.Stop(); $client.Close() }
    }
    if ($best -eq [int]::MaxValue) { return -1 }
    return $best
}

function Get-ActiveInterfaces {
    param([int[]]$Extra = @())
    Get-NetIPConfiguration | Where-Object {
        $_.NetAdapter.Status -eq 'Up' -and
        ($_.IPv4DefaultGateway -or ($Extra -contains $_.InterfaceIndex))
    }
}

$VpnNamePattern = 'wireguard|wintun|tap-window|tap-nord|openvpn|proton|mullvad|' +
                  'amnezia|hiddify|nekoray|nekobox|sing-?box|xray|v2ray|outline|' +
                  'warp|cloudflare|nordlynx|expressvpn|surfshark|windscribe|psiphon|' +
                  'zerotier|hamachi|radmin|anyconnect|globalprotect|forticlient|' +
                  'pulse secure|sonicwall|check point|softether|vpn|tunnel|tun\d|utun'

function Get-TunnelAdapters {
    $all = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
    @($all | Where-Object {
        $hw = $true
        try { if ($null -ne $_.HardwareInterface) { $hw = [bool]$_.HardwareInterface } } catch { }
        (-not $hw) -and (
            (@(23,53,131,244) -contains $_.InterfaceType) -or
            ($_.InterfaceDescription -match $VpnNamePattern) -or
            ($_.Name -match $VpnNamePattern)
        )
    })
}

function Get-DefaultRouteOwners {
    $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') -contains $_.DestinationPrefix })
    $half = @($routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/1' })
    if ($half.Count -gt 0) {
        return @($half | ForEach-Object { $_.InterfaceIndex } | Select-Object -Unique)
    }
    $zero = @($routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } |
              Sort-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric })
    if ($zero.Count -gt 0) { return @($zero[0].InterfaceIndex) }
    return @()
}

function Get-SystemProxy {
    try {
        $p = Get-ItemProperty -ErrorAction Stop `
             -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        if ($p.ProxyEnable -eq 1 -and -not [string]::IsNullOrWhiteSpace($p.ProxyServer)) {
            return [string]$p.ProxyServer
        }
    } catch { }
    return $null
}

function Get-RasVpn {
    $c = @()
    if (Get-Command Get-VpnConnection -ErrorAction SilentlyContinue) {
        foreach ($allUsers in @($false, $true)) {
            try {
                $c += @(Get-VpnConnection -AllUserConnection:$allUsers -ErrorAction Stop |
                        Where-Object { $_.ConnectionStatus -eq 'Connected' })
            } catch { }
        }
    }
    @($c)
}

function Get-RouteInterface {
    param([string]$Ip)
    if (-not (Get-Command Find-NetRoute -ErrorAction SilentlyContinue)) { return $null }
    try {
        $r = @(Find-NetRoute -RemoteIPAddress $Ip -ErrorAction Stop |
               Where-Object { $_.InterfaceIndex } | Select-Object -First 1)
        if ($r.Count -eq 0) { return $null }
        $a = Get-NetAdapter -InterfaceIndex $r[0].InterfaceIndex -ErrorAction SilentlyContinue
        $alias = "интерфейс $($r[0].InterfaceIndex)"
        if ($a) { $alias = $a.Name }
        return [pscustomobject]@{ Index = $r[0].InterfaceIndex; Alias = $alias }
    } catch { return $null }
}

function Show-VpnAdvice {
    Write-Info 'Что сделать, не выключая VPN:'
    Write-Info '  * включить режим "весь трафик через VPN" (full tunnel), а не только'
    Write-Info '    отдельные сайты — иначе картинки идут мимо туннеля и их режут'
    Write-Info '  * если в клиенте есть список доменов, добавить в него:'
    Write-Info '      *.roblox.com   *.rbxcdn.com   *.rbxcdn.net'
    Write-Info '  * включить "DNS через туннель" (DNS leak protection)'
    Write-Info '  * сменить сервер или страну — часть узлов отдаёт битые ответы CDN'
    Write-Info '  * попробовать другой протокол (WireGuard вместо OpenVPN и наоборот)'
    Write-Info 'Проверить догадку можно так: на минуту выключить VPN и запустить скрипт'
    Write-Info 'заново. Если без VPN всё грузится — дело в настройках VPN, а не в DNS.'
}

function Get-StaticDnsFromRegistry {
    param([string]$InterfaceGuid, [string]$Family)
    $svc = if ($Family -eq 'IPv6') { 'Tcpip6' } else { 'Tcpip' }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Parameters\Interfaces\$InterfaceGuid"
    try {
        $v = (Get-ItemProperty -Path $key -Name NameServer -ErrorAction Stop).NameServer
        if ([string]::IsNullOrWhiteSpace($v)) { return @() }
        return @($v -split '[,\s]+' | Where-Object { $_ })
    } catch { return @() }
}

function Resolve-InterfaceIndex {
    param($Entry)
    if ($Entry.Guid) {
        $a = Get-NetAdapter -ErrorAction SilentlyContinue |
             Where-Object { $_.InterfaceGuid -eq $Entry.Guid } | Select-Object -First 1
        if ($a) { return $a.InterfaceIndex }
    }
    if ($Entry.Alias) {
        $a = Get-NetAdapter -Name $Entry.Alias -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($a) { return $a.InterfaceIndex }
    }

    if ($Entry.Guid) { return $null }
    return $Entry.Index
}

Clear-Host
Show-Banner

foreach ($cmd in @('Resolve-DnsName','Set-DnsClientServerAddress','Get-NetIPConfiguration')) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Bad "В этой системе нет команды $cmd."
        Write-Info 'Скрипт рассчитан на Windows 8 и новее. На Windows 7 он не заработает.'
        Wait-Close; exit 1
    }
}

if ($Revert) {
    Write-Head 'Откат настроек DNS'
    if (-not (Test-Path $BackupPath)) {
        Write-Bad "Файл резервной копии не найден: $BackupPath"
        Write-Info 'Похоже, скрипт ещё ничего не менял. Откатывать нечего.'
        Wait-Close; exit 1
    }
    if (-not (Test-Admin)) {
        Write-Info 'Нужны права администратора, подтвердите запрос UAC...'
        if (Invoke-Elevated -ExtraArgs @('-Revert')) { exit 0 } else { Wait-Close; exit 1 }
    }

    $backup  = Get-Content -Raw -Encoding UTF8 $BackupPath | ConvertFrom-Json
    $pending = @()
    foreach ($e in $backup.Interfaces) {
        $idx = Resolve-InterfaceIndex -Entry $e
        if (-not $idx) {
            Write-Warn "$($e.Alias): адаптер не найден (выключен VPN?), пропускаю."

            $pending += $e
            continue
        }

        $saved = @(@($e.IPv4) + @($e.IPv6) | Where-Object { $_ })
        try {
            Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses -ErrorAction Stop
            if ($saved.Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $saved -ErrorAction Stop
                Write-Ok "$($e.Alias)  ->  $($saved -join ', ')"
            } else {
                Write-Ok "$($e.Alias)  ->  автоматически (DHCP)"
            }
        } catch {
            Write-Bad "$($e.Alias)  ->  $($_.Exception.Message)"
        }
    }
    ipconfig /flushdns | Out-Null

    if ($pending.Count -gt 0) {
        [pscustomobject]@{ SavedAt = $backup.SavedAt; Interfaces = @($pending) } |
            ConvertTo-Json -Depth 5 | Set-Content -Path $BackupPath -Encoding utf8
        Write-Ok 'Кэш DNS очищен. Настройки доступных адаптеров возвращены к исходным.'
        Write-Info 'Включите VPN и запустите ОТКАТИТЬ.bat ещё раз, чтобы вернуть и его настройки.'
    } else {
        Remove-Item $BackupPath -Force -ErrorAction SilentlyContinue
        Write-Ok 'Кэш DNS очищен. Настройки возвращены к исходным.'
    }
    Wait-Close; exit 0
}

Write-Head '1. VPN и прокси'

$tunnels   = @(Get-TunnelAdapters)
$tunnelIdx = @($tunnels | ForEach-Object { $_.InterfaceIndex })
$ras       = @(Get-RasVpn)
$proxy     = Get-SystemProxy
$owners    = @(Get-DefaultRouteOwners)

$vpnRoutesAll = @($owners | Where-Object { $tunnelIdx -contains $_ }).Count -gt 0
$vpnActive    = ($tunnels.Count -gt 0) -or ($ras.Count -gt 0) -or [bool]$proxy

foreach ($t in $tunnels) { Write-Warn "Туннель VPN: $($t.Name)  —  $($t.InterfaceDescription)" }
foreach ($r in $ras)     { Write-Warn "Подключение VPN Windows: $($r.Name)" }
if ($proxy)              { Write-Warn "Системный прокси: $proxy" }

if (-not $vpnActive) {
    Write-Ok 'VPN и прокси не обнаружены.'
} else {
    if ($tunnels.Count -gt 0 -and $vpnRoutesAll) {
        Write-Info 'Весь трафик идёт через туннель.'
    } elseif ($tunnels.Count -gt 0) {
        Write-Info 'Через туннель идёт лишь часть трафика (раздельное туннелирование).'
        Write-Info 'Это частая причина: сайт открывается, а картинки грузятся мимо VPN.'
    }
    Write-Info 'Выключать VPN не требуется — дальше проверки это учитывают.'
}

Write-Head '2. Файл hosts'

$hostsFile  = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsDirty = @()
try {
    $hostsDirty = @(Get-Content $hostsFile -ErrorAction Stop |
        Where-Object { $_ -notmatch '^\s*#' -and $_ -match 'rbxcdn|roblox' })
} catch { }

if ($hostsDirty.Count -gt 0) {
    Write-Warn 'В файле hosts есть жёстко прописанные адреса Roblox:'
    $hostsDirty | ForEach-Object { Write-Info "  $_" }
    Write-Info 'Такие записи со временем протухают — Akamai меняет IP.'
    Write-Info "Если картинки не появятся, удалите эти строки из $hostsFile"
} else {
    Write-Ok 'Чистый, посторонних записей о Roblox нет.'
}

Write-Head '3. Текущий DNS'

$ifaces = @(Get-ActiveInterfaces -Extra $tunnelIdx)
if ($ifaces.Count -eq 0) {
    Write-Bad 'Не найдено активных подключений к интернету.'
    Wait-Close; exit 1
}
foreach ($i in $ifaces) {
    $srv = @($i.DNSServer | Where-Object { $_.AddressFamily -eq 2 } |
                ForEach-Object { $_.ServerAddresses }) -join ', '
    if (-not $srv) { $srv = '(не задан)' }
    $mark = ''
    if ($tunnelIdx -contains $i.InterfaceIndex) { $mark = '  [VPN]' }
    Write-Info "$($i.InterfaceAlias):  $srv$mark"
}
if ($vpnRoutesAll) {
    Write-Info 'Запросы уходят в туннель, поэтому важен DNS именно VPN-адаптера.'
}

$current = Test-Resolver -Server $null
if ($current.Ok) {
    Write-Ok "$TestHost резолвится: $($current.Ips -join ', ')  ($($current.Ms) мс)"
} else {
    Write-Bad "$TestHost НЕ резолвится текущим DNS."
    if ($vpnActive) { Write-Info 'Скорее всего имена разрешает сам VPN и делает это неудачно.' }
}

Write-Head '4. Реальная загрузка картинки'

$imageOk = $false
try {
    $api = Invoke-RestMethod -TimeoutSec 15 -ErrorAction Stop `
        -Uri 'https://thumbnails.roblox.com/v1/games/icons?universeIds=1818&size=256x256&format=Png'
    $imgUrl = $api.data[0].imageUrl
    $img = Invoke-WebRequest -Uri $imgUrl -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
    if ($img.StatusCode -eq 200 -and $img.RawContentLength -gt 0) {
        $imageOk = $true
        Write-Ok "Иконка скачана: HTTP 200, $([math]::Round($img.RawContentLength/1KB)) КБ"
    }
} catch {
    Write-Bad "Не скачалась: $($_.Exception.Message)"
}

$splitTunnel = $false
if ($vpnActive -and $tunnels.Count -gt 0 -and -not ($current.Ok -and $imageOk)) {
    Write-Head '5. Куда идёт трафик Roblox'

    $viaVpn = 0
    $direct = 0
    foreach ($h in @('thumbnails.roblox.com', 'tr.rbxcdn.com', 't0.rbxcdn.com')) {
        $ips = @()
        try {
            $ips = @(Resolve-DnsName -Name $h -Type A -ErrorAction Stop |
                     Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
        } catch { }
        if ($ips.Count -eq 0) { Write-Bad "$h  —  адрес не определился"; continue }

        $ri = Get-RouteInterface -Ip $ips[0]
        if (-not $ri) { Write-Warn "$h ($($ips[0]))  —  маршрут не найден"; continue }

        if ($tunnelIdx -contains $ri.Index) {
            $viaVpn++
            Write-Ok   "$h  ->  через VPN ($($ri.Alias))"
        } else {
            $direct++
            Write-Warn "$h  ->  мимо VPN, напрямую ($($ri.Alias))"
        }
    }
    $splitTunnel = ($viaVpn -gt 0 -and $direct -gt 0)
    if ($splitTunnel) {
        Write-Info ''
        Write-Info 'Часть узлов Roblox идёт через VPN, часть — напрямую.'
        Write-Info 'Именно так пропадают картинки: страница открывается через туннель,'
        Write-Info 'а картинки грузятся напрямую и их режет провайдер.'
    }
}

if ($current.Ok -and $imageOk) {
    Write-Head 'Вердикт'
    Write-Ok 'DNS в порядке, картинки грузятся. Менять ничего не нужно.'
    Write-Info 'Если в игре их всё равно нет — причина не в DNS. Попробуйте:'
    Write-Info '  * полностью закрыть Roblox (проверьте Диспетчер задач) и запустить снова'
    Write-Info '  * отключить блокировщики рекламы и проверку HTTPS в антивирусе'
    Write-Info '  * переустановить Roblox'
    if ($vpnActive) {
        Write-Info ''
        Write-Info 'VPN включён, и сейчас он загрузке не мешает — выключать его не нужно.'
        Write-Info 'Но Roblox надо перезапустить уже с включённым VPN: приложение'
        Write-Info 'запоминает неудачные попытки загрузки.'
    }
    Wait-Close; exit 0
}

if ($splitTunnel) {
    Write-Head 'Вердикт'
    Write-Warn 'Причина в настройках VPN, а не в DNS. Настройки сети менять не буду.'
    Write-Info 'Трафик Roblox разделён между туннелем и обычным подключением.'
    Write-Info ''
    Show-VpnAdvice
    Wait-Close; exit 0
}

if ($current.Ok -and -not $imageOk) {
    Write-Head 'Вердикт'
    Write-Warn 'DNS работает нормально: адрес определяется, но картинка не загружается.'
    Write-Info 'Причина не в DNS, поэтому настройки сети менять не буду.'
    if ($vpnActive) {
        Write-Info 'Трафик идёт через VPN, и обрывается он уже внутри туннеля.'
        Write-Info ''
        Show-VpnAdvice
        Write-Info ''
        Write-Info 'Если VPN настроен верно, мешать может ещё:'
        Write-Info '  * антивирус с проверкой HTTPS (ESET, Kaspersky, Avast) — отключите её'
        Write-Info '  * брандмауэр или родительский контроль'
        Write-Info '  * временный сбой на стороне Roblox — попробуйте позже'
    } else {
        Write-Info 'Что мешает, по убыванию вероятности:'
        Write-Info '  * антивирус с проверкой HTTPS (ESET, Kaspersky, Avast) — отключите её'
        Write-Info '  * прокси или расширение-блокировщик'
        Write-Info '  * брандмауэр или родительский контроль'
        Write-Info '  * временный сбой на стороне Roblox — попробуйте позже'
    }
    Wait-Close; exit 0
}

if ($DiagnoseOnly) {
    Write-Head 'Вердикт'
    Write-Warn 'Проблема есть, но режим -DiagnoseOnly: настройки не менялись.'
    Write-Info 'Запустите скрипт без -DiagnoseOnly, чтобы починить.'
    Wait-Close; exit 0
}

Write-Head '6. Подбор рабочего DNS'

Write-Info 'Проверяю, какие серверы отвечают и насколько близкий CDN они выдают...'
if ($vpnActive) {
    Write-Info 'Замеры идут через туннель — это нормально, так и будет работать потом.'
}
Write-Info ''

$working = @()
foreach ($c in $Candidates) {
    $r = Test-Resolver -Server $c.V4[0]
    if (-not $r.Ok) {
        Write-Bad ("{0,-11} не отвечает / пустой ответ" -f $c.Name)
        continue
    }
    $edge = Test-EdgeLatency -Ip $r.Ips[0]
    if ($edge -ge 0) {
        Write-Ok ("{0,-11} DNS {1,4} мс | до CDN {2,4} мс | {3}" -f $c.Name, $r.Ms, $edge, $r.Ips[0])

        $working += [pscustomobject]@{ Cand = $c; Score = $edge }
    } else {
        Write-Warn ("{0,-11} DNS {1,4} мс | до CDN нет связи | {2}" -f $c.Name, $r.Ms, $r.Ips[0])

        $working += [pscustomobject]@{ Cand = $c; Score = 100000 + $r.Ms }
    }
}

if ($working.Count -eq 0) {
    Write-Head 'Вердикт'
    Write-Bad 'Ни один публичный DNS не сработал.'
    if ($vpnActive) {
        Write-Info 'Обычно так ведёт себя VPN, который заворачивает все DNS-запросы'
        Write-Info 'на свой сервер и наружу их не выпускает. Менять DNS в такой схеме'
        Write-Info 'бесполезно — решать нужно на стороне клиента VPN.'
        Write-Info ''
        Show-VpnAdvice
    } else {
        Write-Info 'Скорее всего запросы блокирует провайдер, антивирус или роутер.'
        Write-Info 'Попробуйте отключить антивирус и запустить скрипт заново.'
    }
    Wait-Close; exit 1
}

$best = ($working | Sort-Object Score | Select-Object -First 1).Cand
Write-Info ''
Write-Info "Выбран: $($best.Name)  ($($best.V4 -join ', '))  — у него самый близкий CDN"

if (-not (Test-Admin)) {
    Write-Host ''
    Write-Info 'Для изменения настроек нужны права администратора.'
    Write-Info 'Подтвердите запрос UAC — откроется новое окно...'
    $extra = @()
    if ($Force) { $extra += '-Force' }
    if (Invoke-Elevated -ExtraArgs $extra) { exit 0 }
    Wait-Close; exit 1
}

Write-Head '7. Применение'

$vpnIfaces = @($ifaces | Where-Object { $tunnelIdx -contains $_.InterfaceIndex })
if ($vpnIfaces.Count -gt 0 -and -not $Force) {
    Write-Warn "Среди подключений есть VPN: $(@($vpnIfaces | ForEach-Object { $_.InterfaceAlias }) -join ', ')"
    if ($vpnRoutesAll) {
        Write-Info 'Весь трафик идёт через него, поэтому менять DNS имеет смысл именно там.'
    }
    Write-Info 'Клиент VPN может вернуть свои адреса при переподключении — это не страшно,'
    Write-Info 'откат всегда доступен через ОТКАТИТЬ.bat'
    $ans = ''
    try { $ans = Read-Host '  Менять DNS на адаптере VPN? (д/н)' } catch { }
    if ($ans -notmatch '^(д|y)') {
        $ifaces = @($ifaces | Where-Object { $tunnelIdx -notcontains $_.InterfaceIndex })
        Write-Info 'Хорошо, адаптер VPN не трогаю.'
        if ($ifaces.Count -eq 0) {
            Write-Warn 'Больше менять нечего — выхожу, ничего не изменив.'
            Wait-Close; exit 0
        }
        if ($vpnRoutesAll) {
            Write-Warn 'Учтите: трафик идёт через туннель, поэтому эта правка может не помочь.'
        }
    }
}

$existing = @()
if (Test-Path $BackupPath) {
    try { $existing = @((Get-Content -Raw -Encoding UTF8 $BackupPath | ConvertFrom-Json).Interfaces) } catch { }
}
$knownGuids = @($existing | ForEach-Object { $_.Guid })

$added = @()
foreach ($i in $ifaces) {
    $guid = $i.NetAdapter.InterfaceGuid
    if ($knownGuids -contains $guid) { continue }
    $added += [pscustomobject]@{
        Guid  = $guid
        Index = $i.InterfaceIndex
        Alias = $i.InterfaceAlias
        IPv4  = @(Get-StaticDnsFromRegistry -InterfaceGuid $guid -Family 'IPv4')
        IPv6  = @(Get-StaticDnsFromRegistry -InterfaceGuid $guid -Family 'IPv6')
    }
}

if ($added.Count -gt 0) {
    $null = New-Item -ItemType Directory -Force -Path (Split-Path $BackupPath)
    [pscustomobject]@{
        SavedAt    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Interfaces = @($existing + $added)
    } | ConvertTo-Json -Depth 5 | Set-Content -Path $BackupPath -Encoding utf8
    Write-Ok "Старые настройки сохранены: $BackupPath"
} else {
    Write-Info "Резервная копия уже актуальна: $BackupPath"
}

foreach ($i in $ifaces) {
    $servers = @($best.V4)

    $hasV6 = @($i.DNSServer | Where-Object { $_.AddressFamily -eq 23 } |
                  ForEach-Object { $_.ServerAddresses })
    if ($hasV6.Count -gt 0) { $servers += $best.V6 }

    try {
        Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex `
            -ServerAddresses $servers -ErrorAction Stop
        Write-Ok "$($i.InterfaceAlias)  ->  $($servers -join ', ')"
    } catch {
        Write-Bad "$($i.InterfaceAlias)  ->  $($_.Exception.Message)"
    }
}

ipconfig /flushdns | Out-Null
Write-Ok 'Кэш DNS очищен.'

Write-Head '8. Проверка результата'

Start-Sleep -Seconds 1
$after = Test-Resolver -Server $null
if ($after.Ok) { Write-Ok "$TestHost -> $($after.Ips -join ', ')" }
else           { Write-Bad "$TestHost по-прежнему не резолвится." }

$finalOk = $false
try {
    $api = Invoke-RestMethod -TimeoutSec 15 -ErrorAction Stop `
        -Uri 'https://thumbnails.roblox.com/v1/games/icons?universeIds=1818&size=256x256&format=Png'
    $img = Invoke-WebRequest -Uri $api.data[0].imageUrl -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
    if ($img.StatusCode -eq 200 -and $img.RawContentLength -gt 0) {
        $finalOk = $true
        Write-Ok "Иконка скачана: HTTP 200, $([math]::Round($img.RawContentLength/1KB)) КБ"
    }
} catch {
    Write-Bad "Иконка не скачалась: $($_.Exception.Message)"
}

Write-Head 'Итог'
if ($finalOk) {
    Write-Ok 'Готово — картинки грузятся.'
    Write-Info 'Полностью закройте Roblox (проверьте Диспетчер задач) и запустите заново:'
    Write-Info 'приложение кэширует неудачные попытки загрузки.'
} else {
    Write-Warn 'DNS заменён, но картинка всё ещё не грузится.'
    if ($vpnActive) {
        Write-Info 'Значит дело не в DNS, а в том, как VPN пропускает трафик.'
        Write-Info ''
        Show-VpnAdvice
        Write-Info ''
        Write-Info 'Изменения DNS лучше откатить — они не помогли.'
    } else {
        Write-Info 'Мешает что-то ещё: прокси, антивирус с проверкой HTTPS или брандмауэр.'
    }
    Write-Info 'Откатить изменения:  .\Fix-RobloxImages.ps1 -Revert'
}
Write-Info ''
Write-Info 'Откат в любой момент:  .\Fix-RobloxImages.ps1 -Revert'

Wait-Close
