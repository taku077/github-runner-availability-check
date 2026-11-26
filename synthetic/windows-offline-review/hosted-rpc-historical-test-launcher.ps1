# Private synthetic test launcher. No real evidence, network, or secrets.
# The caller must choose an existing disposable local test root explicitly.
# Candidate and harness must be the exact pinned ASCII bytes. No policy bypass.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$TestRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
function Local-Directory([string]$path) {
    if ($path -notmatch '^[A-Za-z]:\\' -or $path.Substring(2) -match '[:/]') { throw 'LOCAL_PATH_REQUIRED' }
    foreach ($part in $path.Substring(3).TrimEnd('\').Split('\')) {
        if ($part.Length -gt 0 -and ($part -in @('.','..') -or $part -match '[. ]$')) { throw 'AMBIGUOUS_PATH' }
    }
    $item=Get-Item -LiteralPath ([IO.Path]::GetFullPath($path)) -Force
    if ($item -isnot [IO.DirectoryInfo]) { throw 'DIRECTORY_REQUIRED' }
    $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($item.FullName))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'FIXED_DRIVE_REQUIRED' }
    $cursor=$item
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE_PATH' }
        $cursor=$cursor.Parent
    }
    return $item.FullName
}
$report=[ordered]@{Status='STOP';Stage='RUNTIME';SelfTestCases=0;IntegrationCases=0;Production='BLOCKED';Live=$false;WriteAllowed=$false}
$files=[ordered]@{
    'hosted-rpc-historical-local.ps1'=@{Size=15824;Hash='c11a4649e7da615ed5ab78f47bd8ca38c032f47998af337c22c32daaf27df2fe'}
    'hosted-rpc-historical-local.test.ps1'=@{Size=9310;Hash='7ef5426d9d8a5aa35bf37170ddfea20dbd03b7fe585e4d3ed0a14101355c3c22'}
}
function Check-Sources([string]$dir) {
    foreach ($name in $files.Keys) {
        $file=Join-Path $dir $name
        $item=Get-Item -LiteralPath $file -Force
        if ($item -isnot [IO.FileInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -ne $files[$name].Size) { throw 'SOURCE_FILE' }
        $digest=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($digest -cne $files[$name].Hash) { throw 'SOURCE_HASH' }
    }
}
$expected=@('valid','raw-hash','missing','duplicate-key','pin-hash','pin-schema','pin-order','pin-http','pin-time','pin-window','changed-deployment','duplicate-deployment','future-deployment','wrong-version','wrong-source','wrong-binding','enabled-url','cron','wrong-type','api-error','output-in-input')
try {
    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'WINDOWS_POWERSHELL_51_REQUIRED' }
    $report.Stage='PATH'
    $source=Local-Directory $PSScriptRoot
    $root=Local-Directory $TestRoot
    if ($source.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or $root.StartsWith($source.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $source.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'SEPARATE_TEST_ROOT_REQUIRED' }
    $report.Stage='SOURCE_PIN'
    Check-Sources $source
    $report.Stage='PARSE'
    foreach ($name in $files.Keys) {
        $tokens=$null; $parseErrors=$null
        $null=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $source $name),[ref]$tokens,[ref]$parseErrors)
        if (@($parseErrors).Count -ne 0) { throw 'PARSE_FAILED' }
    }
    $report.Stage='EXECUTE'
    $lines=@(& (Join-Path $source 'hosted-rpc-historical-local.test.ps1') -TestRoot $root)
    $report.Stage='OUTPUT'
    if (@($lines | Where-Object { $_ -isnot [string] }).Count -ne 0) { throw 'OUTPUT_TYPE' }
    $passed=@($lines | Where-Object { $_ -clike 'PASS: *' } | ForEach-Object { $_.Substring(6) })
    if ($passed.Count -ne $expected.Count) { throw 'CASE_COUNT' }
    for ($i=0;$i -lt $expected.Count;$i++) {
        if ($passed[$i] -cne $expected[$i]) { throw 'CASE_ORDER' }
    }
    if (@($lines | Where-Object { $_ -ceq 'TOTAL: 21/21 end-to-end PASS; built-in 17-case self-test PASS' }).Count -ne 1) { throw 'SELFTEST_OR_TOTAL' }
    $report.Stage='POST_SOURCE_PIN'
    Check-Sources $source
    $report.SelfTestCases=17
    $report.IntegrationCases=21
    $report.Status='SYNTHETIC_TEST_PASS'
    $report.Stage='COMPLETE'
} catch {
    # Stage only: never print arbitrary exception contents.
}
$report | ConvertTo-Json -Depth 3
if ($report.Status -ne 'SYNTHETIC_TEST_PASS') { throw 'SYNTHETIC_TEST_NOT_PASSED' }
