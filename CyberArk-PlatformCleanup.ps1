<#
.SYNOPSIS
  CyberArk PAM (self-hosted PVWA) platform temizligi. PowerShell 5.1+ / PVWA 11.4+.

.DESCRIPTION
  -Mode Report      : Salt-okunur. Platform basina hesap sayisi, son kullanim vb. -> CSV
  -Mode Deactivate  : CSV'de Approved=YES olan platformlari pasife alir (geri alinabilir)
  -Mode Delete      : CSV'de Approved=YES olan platformlari yedekleyip siler (GERI ALINAMAZ)

  Deactivate/Delete varsayilan olarak DRY-RUN calisir; uygulamak icin -Execute.

.EXAMPLE
  .\CyberArk-PlatformCleanup.ps1 -PvwaUrl https://pvwa.firma.local/PasswordVault -Mode Report -Activities
  .\CyberArk-PlatformCleanup.ps1 -PvwaUrl ... -Mode Deactivate -CsvPath .\platform_report.csv -Execute
  .\CyberArk-PlatformCleanup.ps1 -PvwaUrl ... -Mode Delete     -CsvPath .\platform_report.csv -Execute
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PvwaUrl,
    [ValidateSet('Report', 'Deactivate', 'Delete')][string]$Mode = 'Report',
    [ValidateSet('CyberArk', 'LDAP', 'RADIUS', 'Windows')][string]$AuthType = 'CyberArk',
    [string]$CsvPath = '.\platform_report.csv',
    [int]$StaleDays = 180,
    [switch]$Activities,          # Hesap basina aktivite logu (yavas)
    [int]$ActivitySample = 0,     # Platform basina en fazla N hesap (0 = hepsi)
    [string]$BackupDir = '.\platform_backup',
    [switch]$AllowActive,         # Delete: aktif platformu da sil
    [switch]$Execute
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Base = $PvwaUrl.TrimEnd('/')
# Insan/uygulama kullanimi sayilan aktiviteler (CPM islemleri haric)
$HumanActions = 'retrieve', 'connect', 'use password', 'show password', 'copy password'

function Invoke-Pvwa {
    param([string]$Method, [string]$Path, $Body)
    $p = @{ Method = $Method; Uri = "$Base/$($Path.TrimStart('/'))"; Headers = $script:Headers; ContentType = 'application/json' }
    if ($Body) { $p.Body = ($Body | ConvertTo-Json) }
    Invoke-RestMethod @p
}

function ConvertTo-Day([long]$Epoch) {
    if ($Epoch -le 0) { return '' }
    [DateTimeOffset]::FromUnixTimeSeconds($Epoch).UtcDateTime.ToString('yyyy-MM-dd')
}

function Get-Platforms { (Invoke-Pvwa GET 'API/Platforms/targets').Platforms }

function Get-AccountsByPlatform {
    # Yalnizca kullanicinin gorebildigi kasalardaki hesaplar doner!
    $grouped = @{}; $total = 0; $path = 'API/Accounts?limit=1000'
    while ($path) {
        $data = Invoke-Pvwa GET $path
        foreach ($a in $data.value) {
            $k = "$($a.platformId)".ToLower()
            if (-not $grouped.ContainsKey($k)) { $grouped[$k] = New-Object System.Collections.Generic.List[object] }
            $grouped[$k].Add($a); $total++
        }
        Write-Progress -Activity 'Hesaplar okunuyor' -Status $total
        $path = $data.nextLink
    }
    Write-Progress -Activity 'Hesaplar okunuyor' -Completed
    $grouped
}

function Get-OnboardingRules {
    $rules = @{}
    try {
        foreach ($r in (Invoke-Pvwa GET 'API/AutomaticOnboardingRules').AutomaticOnboardingRules) {
            $k = "$($r.TargetPlatformId)".ToLower()
            if (-not $rules.ContainsKey($k)) { $rules[$k] = @() }
            $rules[$k] += $r.RuleName
        }
    } catch { Write-Warning "Onboarding kurallari okunamadi ($_); elle kontrol edin." }
    $rules
}

function Get-AccountActivity([string]$AccountId) {
    $res = @{ Human = [long]0; Any = [long]0 }
    try { $acts = (Invoke-Pvwa GET "API/Accounts/$AccountId/Activities").Activities } catch { return $res }
    foreach ($a in $acts) {
        $d = [long]$a.Date; $action = "$($a.Action)".ToLower()
        if ($d -gt $res.Any) { $res.Any = $d }
        if (-not $action.StartsWith('cpm') -and ($HumanActions | Where-Object { $action.Contains($_) })) {
            if ($d -gt $res.Human) { $res.Human = $d }
        }
    }
    $res
}

function Invoke-Report {
    $platforms = @(Get-Platforms | Sort-Object PlatformID)
    $accounts = Get-AccountsByPlatform
    $rules = Get-OnboardingRules
    $cutoff = [DateTimeOffset]::UtcNow.AddDays(-$StaleDays).ToUnixTimeSeconds()
    $i = 0

    $rows = foreach ($pl in $platforms) {
        $i++
        $key = "$($pl.PlatformID)".ToLower()
        $accs = @(); if ($accounts.ContainsKey($key)) { $accs = @($accounts[$key]) }
        $safes = @($accs | ForEach-Object { $_.safeName } | Sort-Object -Unique)
        [long]$lastChange = 0; [long]$newest = 0; $cpm = 0
        foreach ($a in $accs) {
            if ([long]$a.secretManagement.lastModifiedTime -gt $lastChange) { $lastChange = [long]$a.secretManagement.lastModifiedTime }
            if ([long]$a.createdTime -gt $newest) { $newest = [long]$a.createdTime }
            if ($a.secretManagement.automaticManagementEnabled) { $cpm++ }
        }

        $humanTxt = 'n/a'; $anyTxt = 'n/a'; [long]$lastHuman = 0
        if ($Activities -and $accs.Count -gt 0) {
            Write-Progress -Activity 'Aktiviteler' -Status "$($pl.PlatformID) ($($accs.Count) hesap)" -PercentComplete (100 * $i / $platforms.Count)
            $sample = $accs; if ($ActivitySample -gt 0) { $sample = $accs | Select-Object -First $ActivitySample }
            [long]$lastAny = 0
            foreach ($a in $sample) {
                $r = Get-AccountActivity $a.id
                if ($r.Human -gt $lastHuman) { $lastHuman = $r.Human }
                if ($r.Any -gt $lastAny) { $lastAny = $r.Any }
            }
            $humanTxt = ConvertTo-Day $lastHuman; if (-not $humanTxt) { $humanTxt = 'kayit yok' }
            $anyTxt = ConvertTo-Day $lastAny; if (-not $anyTxt) { $anyTxt = 'kayit yok' }
        }

        $plRules = @(); if ($rules.ContainsKey($key)) { $plRules = $rules[$key] }
        $latest = ($lastHuman, $lastChange, $newest | Measure-Object -Maximum).Maximum
        if ($accs.Count -eq 0 -and $plRules.Count -eq 0) { $suggestion = 'DELETE_CANDIDATE (hesap yok)' }
        elseif ($accs.Count -eq 0) { $suggestion = 'REVIEW (hesap yok ama onboarding kurali var)' }
        elseif ($Activities -and $latest -lt $cutoff) { $suggestion = "REVIEW_STALE ($StaleDays gundur kullanim/degisim yok; once hesaplar tasinmali)" }
        else { $suggestion = 'KEEP' }

        $safeTxt = ($safes | Select-Object -First 10) -join '; '
        if ($safes.Count -gt 10) { $safeTxt += ' ...' }

        [pscustomobject]@{
            PlatformID = $pl.PlatformID; Name = $pl.Name; NumericID = $pl.ID; Active = $pl.Active
            SystemType = $pl.SystemType; PlatformBaseID = $pl.PlatformBaseID
            AccountCount = $accs.Count; SafeCount = $safes.Count; Safes = $safeTxt; CpmManagedCount = $cpm
            NewestAccountCreated = ConvertTo-Day $newest; LastSecretChange = ConvertTo-Day $lastChange
            LastHumanUse = $humanTxt; LastAnyActivity = $anyTxt
            OnboardingRules = $plRules -join '; '; Suggestion = $suggestion; Approved = ''
        }
    }
    Write-Progress -Activity 'Aktiviteler' -Completed
    $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

    $known = $platforms | ForEach-Object { "$($_.PlatformID)".ToLower() }
    $orphans = $accounts.Keys | Where-Object { $known -notcontains $_ }
    $cand = @($rows | Where-Object { $_.Suggestion -like 'DELETE*' }).Count
    Write-Host "Rapor: $CsvPath ($(@($rows).Count) platform, $cand silme adayi)"
    if ($orphans) { Write-Warning "Hedef platform listesinde olmayan platformId'li hesaplar: $($orphans -join ', ')" }
    Write-Host "Sonraki adim: CSV'yi inceleyin, silinecek satirlarda Approved sutununa YES yazin."
}

function Invoke-Change([string]$Action) {
    $approved = @(Import-Csv $CsvPath | Where-Object { "$($_.Approved)".Trim().ToUpper() -eq 'YES' } | ForEach-Object { $_.PlatformID })
    if ($approved.Count -eq 0) { throw "CSV'de Approved=YES olan satir yok." }

    # Canli veriden yeniden dogrulama (CSV'deki sayilara guvenilmez)
    $live = @{}; foreach ($pl in Get-Platforms) { $live["$($pl.PlatformID)".ToLower()] = $pl }
    $accounts = Get-AccountsByPlatform
    $rules = Get-OnboardingRules

    $modeTxt = 'DRY-RUN'; if ($Execute) { $modeTxt = 'UYGULANIYOR' }
    Write-Host "[$modeTxt] $Action : $($approved.Count) onayli platform"
    if ($Execute) {
        $answer = Read-Host "Onay icin platform sayisini yazin ($($approved.Count))"
        if ($answer.Trim() -ne "$($approved.Count)") { throw 'Iptal edildi.' }
    }
    if ($Action -eq 'Delete') { New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null }

    $log = foreach ($platformId in $approved) {
        $key = $platformId.ToLower(); $pl = $live[$key]
        if (-not $pl) { $result = 'SKIP: platform bulunamadi' }
        elseif ($accounts.ContainsKey($key)) { $result = "SKIP: $($accounts[$key].Count) hesap bagli" }
        elseif ($rules.ContainsKey($key)) { $result = "SKIP: onboarding kurali var ($($rules[$key] -join '; '))" }
        elseif ($Action -eq 'Delete' -and $pl.Active -and -not $AllowActive) { $result = 'SKIP: platform hala aktif (once Deactivate + bekleme suresi)' }
        else {
            try {
                if ($Action -eq 'Delete') {
                    # Yedek alinamazsa silme yapilmaz
                    $zip = Join-Path $BackupDir "$platformId.zip"
                    Invoke-WebRequest -Method Post -Uri "$Base/API/Platforms/$platformId/Export" -Headers $script:Headers -OutFile $zip -UseBasicParsing
                    if (-not (Test-Path $zip) -or (Get-Item $zip).Length -eq 0) { throw 'yedek dosyasi bos' }
                }
                if (-not $Execute) { $result = "DRY-RUN: $Action yapilacakti" }
                elseif ($Action -eq 'Delete') { Invoke-Pvwa DELETE "API/Platforms/targets/$($pl.ID)" | Out-Null; $result = 'DELETED' }
                else { Invoke-Pvwa POST "API/Platforms/targets/$($pl.ID)/deactivate" | Out-Null; $result = 'DEACTIVATED' }
            } catch { $result = "ERROR: $($_.Exception.Message) $($_.ErrorDetails.Message)" }
        }
        Write-Host ("  {0,-40} {1}" -f $platformId, $result)
        [pscustomobject]@{ Time = (Get-Date -Format s); PlatformID = $platformId; Action = $Action; Result = $result }
    }
    $logPath = ".\platform_$($Action.ToLower())_log_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
    $log | Export-Csv -Path $logPath -NoTypeInformation -Encoding UTF8
    Write-Host "Log: $logPath"
}

# --- Ana akis ---
$cred = Get-Credential -Message 'PVWA kullanicisi'
$logonBody = @{ username = $cred.UserName; password = $cred.GetNetworkCredential().Password; concurrentSession = $true } | ConvertTo-Json
$token = Invoke-RestMethod -Method Post -Uri "$Base/API/auth/$AuthType/Logon" -Body $logonBody -ContentType 'application/json'
$script:Headers = @{ Authorization = $token }
$logonBody = $null

try {
    if ($Mode -eq 'Report') { Invoke-Report } else { Invoke-Change $Mode }
}
finally {
    try { Invoke-RestMethod -Method Post -Uri "$Base/API/Auth/Logoff" -Headers $script:Headers | Out-Null } catch { }
}
