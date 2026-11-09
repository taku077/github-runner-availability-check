# OPS047: preserve the exact native EVTX export of two intentional test events.
# Contains only disposable public runner events; never run on a personal machine.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Disposable public Windows GitHub runner required'
}
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { throw 'Missing RUNNER_TEMP' }
$token = [guid]::NewGuid().ToString('N')
$provider = 'PCFM_OPS047_BENIGN'
$eventId = 246
$receiptDir = Join-Path $env:RUNNER_TEMP 'ops047-public-receipt'
$privateDir = Join-Path $env:RUNNER_TEMP ('ops047-internal-' + $token)
New-Item -ItemType Directory -Path $receiptDir, $privateDir -Force | Out-Null
$evtx = Join-Path $privateDir 'controlled-application.evtx'
$receiptPath = Join-Path $receiptDir 'receipt.json'
if ((Test-Path $evtx) -or (Test-Path $receiptPath)) { throw 'Existing output must not be overwritten' }
$markers = [string[]]::new(2)
$markers[0] = 'PCFM_OPS047_BENIGN_' + $token + '_A'
$markers[1] = 'PCFM_OPS047_BENIGN_' + $token + '_B'
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
Write-Output ('PCFM_OPS047_DIAG count=' + $items.Count + ' ids=' + (($items | ForEach-Object { $_.record_id }) -join ','))
if ($items.Count -ne 2 -or $items[0].record_id -eq $items[1].record_id -or $archive.Count -ne 2) {
    throw 'Expected exactly two exported, uniquely labeled events (no unlabeled records)'
}
if ($live.Count -ne 2) { throw 'Unexpected live events for our unique synthetic provider' }
$f=Get-Item -LiteralPath $evtx
if ($f.Length -lt 1 -or $f.Length -gt 1048576) { throw 'EVTX export outside 1 MiB bound' }
$exportHash = (Get-FileHash -LiteralPath $evtx -Algorithm SHA256).Hash.ToLowerInvariant()
$publicCopy = Join-Path $receiptDir 'controlled-application.evtx'
if (Test-Path -LiteralPath $publicCopy) { throw 'Refusing public EVTX overwrite' }
Copy-Item -LiteralPath $evtx -Destination $publicCopy -ErrorAction Stop
if ((Get-FileHash -LiteralPath $evtx -Algorithm SHA256).Hash.ToLowerInvariant() -ne $exportHash -or
    (Get-FileHash -LiteralPath $publicCopy -Algorithm SHA256).Hash.ToLowerInvariant() -ne $exportHash) {
    throw 'EVTX source/public copy hashes differ'
}
# Re-open the ACTUAL copy that the artifact step will upload, not just its source.
$copiedEvents = @(Get-WinEvent -Path $publicCopy -ErrorAction Stop)
if ($copiedEvents.Count -ne 2) { throw 'Public copy contains unexpected events' }
foreach ($original in $archive) {
    $matches = @($copiedEvents | Where-Object { $_.RecordId -eq $original.RecordId })
    if ($matches.Count -ne 1 -or $matches[0].Id -ne $eventId -or
        $matches[0].ProviderName -ne $provider -or
        $matches[0].TimeCreated.ToUniversalTime().Ticks -ne $original.TimeCreated.ToUniversalTime().Ticks -or
        $matches[0].ToXml() -ne $original.ToXml()) {
        throw 'Copied EVTX differs from captured synthetic record'
    }
}
$receipt=[ordered]@{
    schema='pcfm-ops047-native-evtx-preserved-v1'
    environment='PUBLIC_GITHUB_HOSTED_DISPOSABLE_WINDOWS'
    source_log='Application'
    controlled_events=$items
    controlled_count=2
    evtx_sha256=$exportHash
    evtx_bytes=[long]$f.Length
    raw_evtx_uploaded=$true
    archived_file='controlled-application.evtx'
    capture_kind='FILTERED_NATIVE_EXPORT_NOT_ORIGINAL_EVENTLOG_SERVICE_DATABASE'
    public_scope='TWO_EXPLICIT_TEST_EVENTS_DISPOSABLE_RUNNER_ONLY'
    payload_may_contain_temporary_runner_computer_name=$true
    source_file_sha256_equals_copy=$true
    artifact_copy_reopened_as_evtx=$true
    independent_external_truth_adjudication=$false
    unknown_event_labels_preserved=$true
    whole_log_benign_label=$false
    detection_engine_run=$false
    metrics=[ordered]@{status='UNSCORABLE_NO_INDEPENDENTLY_LABELED_FULL_CORPUS';TP=$null;FP=$null;FN=$null;TN=$null;precision=$null;recall=$null;false_positive_rate=$null}
    production_deployment_authorized=$false
}
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -NoNewline -Encoding utf8
Write-Output 'PCFM_OPS047_EXPORT_PASS events=2 native_evtx=preserved_and_reopened scoring=UNSCORABLE'
