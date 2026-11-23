# OPS160: disposable public GitHub-hosted Windows runner only. Not a PCFM collector.
param([Parameter(Mandatory=$true)][string]$EvtxPath,
      [Parameter(Mandatory=$true)][string]$ReceiptPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows'){
    throw 'OPS160 requires disposable public GitHub-hosted Windows'
}
if([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)){throw 'RUNNER_TEMP required'}
$root=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd([char[]]@('\','/'))+'\'
function Check-Input([string]$p){
    if([string]::IsNullOrWhiteSpace($p)){throw 'Empty path'}
    $full=[IO.Path]::GetFullPath($p)
    if(-not $full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){throw 'Outside runner temp'}
    $item=Get-Item -LiteralPath $full -ErrorAction Stop
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Invalid/reparse-point file'}
    return $full
}
function Test-Offline([string]$path,[string]$sha,[long]$bytes,[object[]]$expected){
    $p=Check-Input $path
    if($sha -cnotmatch '^[0-9a-f]{64}$' -or $bytes -lt 1 -or $bytes -gt 1048576){throw 'Invalid SHA/size'}
    if($null -eq $expected -or $expected.Count -ne 2){throw 'Expected two records'}
    if((Get-Item -LiteralPath $p).Length -ne $bytes){throw 'EVTX size mismatch'}
    if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha){throw 'EVTX hash mismatch'}
    $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new($p,[Diagnostics.Eventing.Reader.PathType]::FilePath)
    $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query)
    $records=[Collections.Generic.List[object]]::new()
    try{
        while($true){
            $ev=$reader.ReadEvent()
            if($null -eq $ev){break}
            try{
                if($records.Count -ge 2){throw 'Unexpected extra record'}
                $records.Add([pscustomobject]@{
                    record_id=[long]$ev.RecordId
                    event_id=[int]$ev.Id
                    source=[string]$ev.ProviderName
                    ticks=$ev.TimeCreated.ToUniversalTime().Ticks
                })
            }finally{$ev.Dispose()}
        }
    }finally{$reader.Dispose()}
    if($records.Count -ne 2){throw 'Record count mismatch'}
    $ids=[Collections.Generic.HashSet[long]]::new()
    foreach($e in $expected){
        if($null -eq $e){throw 'Null record in receipt'}
        $id=[long]$e.record_id
        if(-not $ids.Add($id)){throw 'Duplicate expected ID'}
        $found=@($records | Where-Object {$_.record_id -eq $id})
        if($found.Count -ne 1){throw 'Record ID not unique/present'}
        $ticks=[datetimeoffset]::Parse([string]$e.utc,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime.Ticks
        if($found[0].event_id -ne [int]$e.event_id -or
           $found[0].source -cne [string]$e.source -or
           $found[0].ticks -ne $ticks){throw 'Native EVTX record differs from receipt'}
    }
    if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha){throw 'EVTX changed while reading'}
    return $records.Count
}
$receiptVerified=Check-Input $ReceiptPath
$r=Get-Content -LiteralPath $receiptVerified -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
if($r.schema -cne 'pcfm-ops047-native-evtx-preserved-v1' -or
   $r.environment -cne 'PUBLIC_GITHUB_HOSTED_DISPOSABLE_WINDOWS' -or
   $r.public_scope -cne 'TWO_EXPLICIT_TEST_EVENTS_DISPOSABLE_RUNNER_ONLY' -or
   $r.controlled_count -ne 2 -or $r.raw_evtx_uploaded -ne $true -or
   $r.whole_log_benign_label -ne $false){throw 'Unexpected synthetic source receipt'}
$events=@($r.controlled_events)
$p=Check-Input $EvtxPath
$original=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
if((Test-Offline $p ([string]$r.evtx_sha256) ([long]$r.evtx_bytes) $events) -ne 2){throw 'Offline verify failed'}
$negative=Join-Path $env:RUNNER_TEMP ('ops160-negative-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $negative -ErrorAction Stop | Out-Null
$rejected=0
try{
    $changed=Join-Path $negative 'altered-copy.evtx'
    Copy-Item -LiteralPath $p -Destination $changed -ErrorAction Stop
    $s=[IO.File]::Open($changed,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try{
        $b=$s.ReadByte()
        if($b -lt 0){throw 'Empty copied file'}
        $s.Position=0
        $s.WriteByte([byte]($b -bxor 1))
        $s.Flush($true)
    }finally{$s.Dispose()}
    try{[void](Test-Offline $changed ([string]$r.evtx_sha256) ([long]$r.evtx_bytes) $events)}catch{$rejected++}
    try{[void](Test-Offline $p ('0'*64) ([long]$r.evtx_bytes) $events)}catch{$rejected++}
    $dup=@($events|ForEach-Object{[pscustomobject]@{record_id=$_.record_id;event_id=$_.event_id;source=$_.source;utc=$_.utc}})
    $dup[1].record_id=$dup[0].record_id
    try{[void](Test-Offline $p ([string]$r.evtx_sha256) ([long]$r.evtx_bytes) $dup)}catch{$rejected++}
    if($rejected -ne 3){throw 'Negative tests did not all reject'}
}finally{Remove-Item -LiteralPath $negative -Recurse -Force -ErrorAction Stop}
if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -cne $original){throw 'Original copy mutated'}
$folder=Join-Path $env:RUNNER_TEMP 'ops160-public-metadata'
New-Item -ItemType Directory -Path $folder -ErrorAction Stop | Out-Null
$report=Join-Path $folder 'receipt.json'
if(Test-Path -LiteralPath $report){throw 'No overwrite'}
[ordered]@{
    schema='pcfm-ops160-native-readonly-evtx-v1'
    environment='PUBLIC_GITHUB_HOSTED_DISPOSABLE_WINDOWS'
    native_reader='EventLogReader(FilePath)'
    records_checked=2
    evtx_sha256=$original
    negative_cases_rejected=$rejected
    original_unchanged=$true
    raw_evtx_uploaded=$false
    independent_provenance_attested=$false
    windows10_native='NOT_RUN'
    spyware_detection='NOT_MEASURED'
    investigated_pc_touched=$false
    production_deployment_gate='BLOCKED'
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $report -Encoding utf8 -NoNewline
Write-Output 'PCFM_OPS160_PASS native_offline_records=2 negative_rejected=3 original_unchanged=true'
