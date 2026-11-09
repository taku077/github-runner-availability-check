# OPS046: only two intentional benign Application events on a disposable GitHub runner.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Disposable public Windows GitHub runner required'
}
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { throw 'Missing RUNNER_TEMP' }
$token = [guid]::NewGuid().ToString('N')
$provider = 'PCFM_OPS046_BENIGN'
$eventId = 246
$receiptDir = Join-Path $env:RUNNER_TEMP 'ops046-public-receipt'
$privateDir = Join-Path $env:RUNNER_TEMP ('ops046-internal-' + $token)
New-Item -ItemType Directory -Path $receiptDir, $privateDir -Force | Out-Null
$evtx = Join-Path $privateDir 'controlled-application.evtx'
$receiptPath = Join-Path $receiptDir 'receipt.json'
if ((Test-Path $evtx) -or (Test-Path $receiptPath)) { throw 'Existing output must not be overwritten' }
$markers = [string[]]::new(2)
$markers[0] = 'PCFM_OPS046_BENIGN_' + $token + '_A'
$markers[1] = 'PCFM_OPS046_BENIGN_' + $token + '_B'
if ($markers.Count -ne 2 -or $markers[0] -eq $markers[1]) { throw 'Invalid distinct marker setup' }
foreach ($marker in $markers) {
    & eventcreate.exe /l APPLICATION /so $provider /t INFORMATION /id $eventId /d $marker | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'eventcreate failed' }
}
$live = @(Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName=$provider; Id=$eventId} -ErrorAction Stop)
$xpath = "*[System[Provider[@Name='$provider'] and EventID=$eventId]]"
& wevtutil.exe epl Application $evtx "/q:$xpath" | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $evtx)) { throw 'wevtutil epl failed' }
$archive = @(Get-WinEvent -Path $evtx -ErrorAction Stop)
$items = [System.Collections.Generic.List[object]]::new()
foreach ($marker in $markers) {
    $a = @($live | Where-Object { $_.ToXml().Contains($marker) })
    $b = @($archive | Where-Object { $_.ToXml().Contains($marker) })
    if ($a.Count -ne 1 -or $b.Count -ne 1) { throw 'Marker absent or duplicated' }
    $x=$a[0]; $y=$b[0]
    if ($x.RecordId -ne $y.RecordId -or $y.Id -ne $eventId -or
        $x.ProviderName -ne $provider -or $y.ProviderName -ne $provider -or
        $x.TimeCreated.ToUniversalTime().Ticks -ne $y.TimeCreated.ToUniversalTime().Ticks) {
        throw 'Live and exported evidence mismatch'
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $hash=[Convert]::ToHexString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($marker))).ToLowerInvariant() }
    finally { $sha.Dispose() }
    $record = [pscustomobject][ordered]@{
        marker_sha256=$hash; record_id=[long]$y.RecordId
        event_id=[int]$y.Id; source=$y.ProviderName
        utc=$y.TimeCreated.ToUniversalTime().ToString('o')
        label='CONTROLLED_BENIGN_ACTION_ONLY'
        label_basis='EVENTCREATE_AND_LIVE_EXPORTED_IDENTITY'
    }
    $items.Add($record)
}
Write-Output ('PCFM_OPS046_DIAG count=' + $items.Count + ' ids=' + (($items | ForEach-Object { $_.record_id }) -join ','))
if ($items.Count -ne 2 -or $items[0].record_id -eq $items[1].record_id) { throw 'Expected two distinct events' }
$f=Get-Item -LiteralPath $evtx
if ($f.Length -lt 1) { throw 'Empty EVTX export' }
$receipt=[ordered]@{
    schema='pcfm-ops046-controlled-benign-v1'
    environment='PUBLIC_GITHUB_HOSTED_DISPOSABLE_WINDOWS'
    source_log='Application'
    controlled_events=$items
    controlled_count=2
    evtx_sha256=(Get-FileHash -LiteralPath $evtx -Algorithm SHA256).Hash.ToLowerInvariant()
    evtx_bytes=[long]$f.Length
    raw_evtx_uploaded=$false
    unknown_event_labels_preserved=$true
    whole_log_benign_label=$false
    external_independent_truth_adjudication=$false
    detection_engine_run=$false
    metrics=[ordered]@{status='UNSCORABLE_NO_INDEPENDENTLY_LABELED_FULL_CORPUS';TP=$null;FP=$null;FN=$null;TN=$null;precision=$null;recall=$null;false_positive_rate=$null}
    production_deployment_authorized=$false
}
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -NoNewline -Encoding utf8
Write-Output 'PCFM_OPS046_CONTROLLED_BENIGN_PASS count=2 native_export=verified scoring=UNSCORABLE'
