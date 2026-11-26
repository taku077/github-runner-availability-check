# Synthetic end-to-end tests for the private candidate, not a deployment gate.
# Run only on a Windows test environment, with an explicit disposable local root.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$TestRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'Windows PowerShell 5.1 required' }
$verifier=Join-Path $PSScriptRoot 'hosted-rpc-historical-local.ps1'
$rootItem=Get-Item -LiteralPath $TestRoot -Force
if ($rootItem -isnot [IO.DirectoryInfo] -or $rootItem.FullName -notmatch '^[A-Za-z]:\\') { throw 'local test root required' }
$cursor=$rootItem
while ($null -ne $cursor) {
    if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse root rejected' }
    $cursor=$cursor.Parent
}
$drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($rootItem.FullName))
if ($drive.DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable)) { throw 'local drive required' }
$root=Join-Path $rootItem.FullName ('synthetic-review-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$utf=[Text.UTF8Encoding]::new($false,$true)
$names=@('deployments-before','version','settings','subdomain','schedules','deployments-after')
$dep='22222222-2222-4222-8222-222222222222'
$ver='11111111-1111-4111-8111-111111111111'
$ns='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$sourceHash='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
function Require([bool]$condition,[string]$label) { if (-not $condition) { throw "FAIL: $label" } }
function Hash([string]$file) { return (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-New([string]$file,[string]$s) {
    $b=$utf.GetBytes($s)
    $f=[IO.File]::Open($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $f.Write($b,0,$b.Length) } finally { $f.Dispose() }
}
function Encode($o) { return ConvertTo-Json -InputObject $o -Depth 20 -Compress }
function Fixture([string]$case) {
    $dir=Join-Path $root $case
    $inputDir=Join-Path $dir 'input'
    $outputDir=Join-Path $dir 'output'
    $null=New-Item -ItemType Directory -Path $dir
    $null=New-Item -ItemType Directory -Path $inputDir
    $null=New-Item -ItemType Directory -Path $outputDir
    $deployment=[ordered]@{deployments=@([ordered]@{id=$dep;created_on='2020-01-01T00:00:00.123456Z';strategy='percentage';versions=@([ordered]@{version_id=$ver;percentage=100})})}
    $version=[ordered]@{id=$ver;main_module='worker.js';compatibility_date='2020-01-01';migration_tag='v1';urls=@();modules=@([ordered]@{name='worker.js';content_type='application/javascript+module';content_base64='YWJj'});bindings=@([ordered]@{name='CHECKPOINT';type='durable_object_namespace';class_name='Checkpoint';namespace_id=$ns})}
    $settings=[ordered]@{observability=[ordered]@{enabled=$true;head_sampling_rate=1;logs=[ordered]@{enabled=$true;head_sampling_rate=1;persist=$true;invocation_logs=$true};traces=[ordered]@{enabled=$false}};logpush=$false;tail_consumers=$null}
    $vals=@($deployment,$version,$settings,[ordered]@{enabled=$false;previews_enabled=$false},[ordered]@{schedules=@()},$deployment)
    $bodies=@()
    for ($i=0;$i -lt 6;$i++) { $bodies+=,(Encode ([ordered]@{success=$true;errors=@();result=$vals[$i]})) }
    $expected=[ordered]@{deployment=$dep;version=$ver;namespace=$ns;migration='v1';compatibility='2020-01-01';sourceSha256=$sourceHash}
    return [pscustomobject]@{Dir=$dir;InputDir=$inputDir;OutputDir=$outputDir;PinPath=(Join-Path $dir 'pins.json');Bodies=$bodies;Expected=$expected}
}
function Modify-Body($f,[int]$index,[scriptblock]$edit) {
    $obj=ConvertFrom-Json -InputObject $f.Bodies[$index]
    & $edit $obj
    $f.Bodies[$index]=Encode $obj
}
function Save-Fixture($f,[string]$case) {
    $pins=@()
    for ($i=0;$i -lt 6;$i++) {
        $file=Join-Path $f.InputDir ($names[$i]+'.json')
        Write-New $file $f.Bodies[$i]
        $pins+=,[ordered]@{name=$names[$i];httpStatus=200;receivedAt=('2020-01-02T00:00:0'+$i+'.1234567Z');sha256=(Hash $file)}
    }
    if ($case -eq 'pin-order') { $pins[1].name='settings' }
    if ($case -eq 'pin-http') { $pins[2].httpStatus=403 }
    if ($case -eq 'pin-time') { $pins[3].receivedAt='2020-01-01T00:00:00.1234567Z' }
    if ($case -eq 'pin-window') { $pins[5].receivedAt='2020-01-02T00:01:01.1234567Z' }
    $schema='PCFM-RCA197-HISTORICAL-PIN-V1'
    if ($case -eq 'pin-schema') { $schema='invalid' }
    Write-New $f.PinPath (Encode ([ordered]@{schema=$schema;records=$pins;expected=$f.Expected}))
    if ($case -eq 'raw-hash') { [IO.File]::AppendAllText((Join-Path $f.InputDir 'version.json'),' ',$utf) }
    if ($case -eq 'missing') { # Rename only a synthetic fixture, never user data.
        [IO.File]::Move((Join-Path $f.InputDir 'version.json'),(Join-Path $f.InputDir 'missing.fixture'))
    }
}
function Snapshot($f) {
    $list=@(Get-ChildItem -LiteralPath $f.InputDir -File | Sort-Object Name | ForEach-Object { $_.Name+':'+(Hash $_.FullName) })
    return (($list -join '|')+'|pin:'+(Hash $f.PinPath))
}
$cases=[ordered]@{
    'valid'='COMPLETE'
    'raw-hash'='RAW_HASH'
    'missing'='RAW_HASH'
    'duplicate-key'='JSON_SUBSET'
    'pin-hash'='PIN'
    'pin-schema'='PIN'
    'pin-order'='PIN'
    'pin-http'='PIN'
    'pin-time'='PIN'
    'pin-window'='CAPTURE_WINDOW'
    'changed-deployment'='CAPTURE_WINDOW'
    'duplicate-deployment'='SEMANTICS_SUBSET'
    'future-deployment'='SEMANTICS_SUBSET'
    'wrong-version'='SEMANTICS_SUBSET'
    'wrong-source'='SEMANTICS_SUBSET'
    'wrong-binding'='SEMANTICS_SUBSET'
    'enabled-url'='SEMANTICS_SUBSET'
    'cron'='SEMANTICS_SUBSET'
    'wrong-type'='SEMANTICS_SUBSET'
    'api-error'='JSON_SUBSET'
    'output-in-input'='INPUT'
}
$self=@(& $verifier -SelfTest)
Require ($self -contains 'SELFTEST: PASS (17 cases; parser and SHA256 only)') 'built-in self-test'
$passed=0
foreach ($case in $cases.Keys) {
    $f=Fixture $case
    switch ($case) {
        'duplicate-key' { $f.Bodies[1]='{"success":false,"success":true,"errors":[],"result":{}}' }
        'changed-deployment' { Modify-Body $f 5 { param($o) $o.result.deployments[0].versions[0].percentage=99 } }
        'duplicate-deployment' {
            Modify-Body $f 0 { param($o) $o.result.deployments=@($o.result.deployments[0],$o.result.deployments[0]) }
            $f.Bodies[5]=$f.Bodies[0]
        }
        'future-deployment' {
            Modify-Body $f 0 { param($o) $o.result.deployments[0].created_on='2020-01-03T00:00:00Z' }
            $f.Bodies[5]=$f.Bodies[0]
        }
        'wrong-version' { Modify-Body $f 1 { param($o) $o.result.id='33333333-3333-4333-8333-333333333333' } }
        'wrong-source' { Modify-Body $f 1 { param($o) $o.result.modules[0].content_base64='ZGVm' } }
        'wrong-binding' { Modify-Body $f 1 { param($o) $o.result.bindings[0].namespace_id='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' } }
        'enabled-url' { Modify-Body $f 3 { param($o) $o.result.enabled=$true } }
        'cron' { Modify-Body $f 4 { param($o) $o.result.schedules=@([pscustomobject]@{cron='* * * * *'}) } }
        'wrong-type' { Modify-Body $f 2 { param($o) $o.result.observability.enabled='true' } }
        'api-error' { Modify-Body $f 2 { param($o) $o.errors=@([pscustomobject]@{code=1000}) } }
    }
    Save-Fixture $f $case
    $before=Snapshot $f
    $pinHash=Hash $f.PinPath
    if ($case -eq 'pin-hash') { $pinHash='0'*64 }
    $out=$f.OutputDir
    if ($case -eq 'output-in-input') { $out=$f.InputDir }
    $lines=@(& $verifier -InputDirectory $f.InputDir -PinFile $f.PinPath -PinSha256 $pinHash -OutputDirectory $out)
    Require ((Snapshot $f) -ceq $before) "$case source unchanged"
    $files=@(Get-ChildItem -LiteralPath $f.OutputDir -Filter 'historical-summary.json' -File -Recurse)
    if ($case -eq 'output-in-input') {
        Require ($files.Count -eq 0) "$case no output"
        Require (@(Get-ChildItem -LiteralPath $f.InputDir -Directory).Count -eq 0) "$case no fallback"
        $report=ConvertFrom-Json -InputObject ($lines -join [Environment]::NewLine)
    } else {
        Require ($files.Count -eq 1) "$case report count"
        $report=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($files[0].FullName,$utf))
        Require (@($lines | Where-Object { $_ -like 'SAVED: *' }).Count -eq 1) "$case saved path"
    }
    Require ($report.Stage -ceq $cases[$case]) "$case stage"
    Require ($report.Live -is [bool] -and -not $report.Live -and $report.WriteAllowed -is [bool] -and -not $report.WriteAllowed -and $report.Production -ceq 'BLOCKED' -and $report.Coverage -ceq 'UNKNOWN' -and $report.Provenance -ceq 'UNVERIFIED') "$case fail-closed invariants"
    if ($case -eq 'valid') {
        Require ($report.Status -ceq 'HISTORICAL_PARTIAL_REVIEW' -and $report.VerifiedBodies -eq 6 -and $report.PinSha256 -ceq $pinHash -and $report.SelectedFieldsMatch -eq $true) 'valid semantic result'
    } else {
        Require ($report.Status -ceq 'STOP') "$case stopped"
    }
    $passed++
    Write-Output "PASS: $case"
}
Require ($passed -eq 21) 'case count'
Write-Output "TOTAL: $passed/21 end-to-end PASS; built-in 17-case self-test PASS"
Write-Output "SYNTHETIC OUTPUT: $root"
