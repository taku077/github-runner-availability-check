# Windows PowerShell 5.1 candidate: offline historical review only.
# No network calls, credentials, installation, execution-policy changes or write authorization.
# This conservative JSON subset deliberately rejects escaped keys, case collisions,
# reserved keys and number forms outside its supported range. Not JS parser parity.
[CmdletBinding(DefaultParameterSetName='Review')]
param(
    [Parameter(Mandatory=$true,ParameterSetName='Review')][string]$InputDirectory,
    [Parameter(Mandatory=$true,ParameterSetName='Review')][string]$PinFile,
    [Parameter(Mandatory=$true,ParameterSetName='Review')][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$PinSha256,
    [Parameter(Mandatory=$true,ParameterSetName='Review')][string]$OutputDirectory,
    [Parameter(Mandatory=$true,ParameterSetName='Test')][switch]$SelfTest
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
function Assert-True($condition) { if ($condition -isnot [bool] -or -not $condition) { throw 'CHECK_FAILED' } }
function Get-Digest([byte[]]$bytes) {
    $h=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
    finally { $h.Dispose() }
}
function Read-Bounded([string]$path,[int]$max) {
    $parent=Get-Directory ([IO.Path]::GetDirectoryName($path))
    $leaf=[IO.Path]::GetFileName($path)
    Assert-True ($leaf.Length -gt 0 -and $leaf -notmatch '[:/\\]' -and $leaf -notmatch '[. ]$' -and $leaf -notin @('.','..'))
    $item=Get-Item -LiteralPath (Join-Path $parent $leaf) -Force
    Assert-True ($item -is [IO.FileInfo] -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    $f=[IO.File]::Open($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        Assert-True ($f.Length -gt 0 -and $f.Length -le $max)
        $b=New-Object byte[] ([int]$f.Length)
        $n=0
        while ($n -lt $b.Length) {
            $r=$f.Read($b,$n,$b.Length-$n)
            Assert-True ($r -gt 0)
            $n+=$r
        }
        Assert-True ($f.ReadByte() -eq -1)
        return ,$b
    } finally { $f.Dispose() }
}
function Read-StrictSubset([byte[]]$bytes) {
    $utf=[Text.UTF8Encoding]::new($false,$true)
    $s=$utf.GetString($bytes)
    Assert-True ($s.Length -gt 0 -and $s.Length -le 2097152)
    $state=[pscustomobject]@{Text=$s; Pos=0; Nodes=0}
    $pattern='\G[ \t\r\n]*(?<t>"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u(?:[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|(?![dD][89a-fA-F])[0-9a-fA-F]{4})))*"|[{}\[\]:,]|true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)'
    $rx=[regex]::new($pattern,[Text.RegularExpressions.RegexOptions]::CultureInvariant,[TimeSpan]::FromSeconds(2))
    function Next-Token {
        $m=$rx.Match($state.Text,$state.Pos)
        if (-not $m.Success) { throw 'JSON_TOKEN' }
        $state.Pos=$m.Index+$m.Length
        return $m.Groups['t'].Value
    }
    function Read-Value([string]$t,[int]$depth) {
        $state.Nodes++
        Assert-True ($depth -le 48 -and $state.Nodes -le 100000)
        switch -CaseSensitive ($t) {
            '{' {
                $keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                $k=Next-Token
                if ($k -ceq '}') { return }
                while ($true) {
                    Assert-True ($k.StartsWith('"') -and -not $k.Contains('\'))
                    $key=$k.Substring(1,$k.Length-2)
                    Assert-True ($key.Length -gt 0 -and $key -notin @('__proto__','constructor','prototype'))
                    Assert-True ($keys.Add($key))
                    Assert-True ((Next-Token) -ceq ':')
                    Read-Value (Next-Token) ($depth+1)
                    $sep=Next-Token
                    if ($sep -ceq '}') { return }
                    Assert-True ($sep -ceq ',')
                    $k=Next-Token
                }
            }
            '[' {
                $v=Next-Token
                if ($v -ceq ']') { return }
                while ($true) {
                    Read-Value $v ($depth+1)
                    $sep=Next-Token
                    if ($sep -ceq ']') { return }
                    Assert-True ($sep -ceq ',')
                    $v=Next-Token
                }
            }
            'true' { return }
            'false' { return }
            'null' { return }
            default {
                if ($t.StartsWith('"')) { return }
                # Conservative exact-decimal subset; reject exponents and long numbers.
                Assert-True ($t -cmatch '^-?(0|[1-9][0-9]*)(\.[0-9]+)?$')
                Assert-True (($t -replace '[^0-9]','').Length -le 15)
                Assert-True ($t -cnotmatch '^-0(?:\.0+)?$')
            }
        }
    }
    $root=Next-Token
    Assert-True ($root -ceq '{')
    Read-Value $root 0
    Assert-True ($s.Substring($state.Pos) -cmatch '^[ \t\r\n]*$')
    $o=ConvertFrom-Json -InputObject $s -ErrorAction Stop
    Assert-True ($o -is [pscustomobject])
    return $o
}
function Field($o,[string]$name) {
    Assert-True ($o -is [pscustomobject])
    $p=@($o.PSObject.Properties | Where-Object { $_.Name -ceq $name })
    Assert-True ($p.Count -eq 1)
    return ,$p[0].Value
}
function Is-Text($v,[string]$expected) { return ($v -is [string] -and $v -ceq $expected) }
function Is-Flag($v,[bool]$expected) { return ($v -is [bool] -and $v -eq $expected) }
function Is-Number($v,[decimal]$expected) {
    return (($v -is [int] -or $v -is [long] -or $v -is [decimal] -or $v -is [double]) -and $v -eq $expected)
}
function Is-ArrayCount($v,[int]$n) { return ($v -is [array] -and $v.Length -eq $n) }
function Check-Envelope($o) {
    Assert-True (Is-Flag (Field $o 'success') $true)
    Assert-True (Is-ArrayCount (Field $o 'errors') 0)
    $r=Field $o 'result'
    Assert-True ($r -is [pscustomobject])
    return $r
}
function Check-Expected($e) {
    foreach ($name in @('deployment','version')) {
        $value=Field $e $name
        Assert-True ($value -is [string] -and $value -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    }
    $value=Field $e 'namespace'
    Assert-True ($value -is [string] -and $value -cmatch '^[0-9a-f]{32}$')
    $value=Field $e 'sourceSha256'
    Assert-True ($value -is [string] -and $value -cmatch '^[0-9a-f]{64}$')
    $value=Field $e 'migration'
    Assert-True ($value -is [string] -and $value.Length -gt 0 -and $value.Length -le 128)
    $value=Field $e 'compatibility'
    Assert-True ($value -is [string] -and $value -cmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}$')
    $null=[DateTime]::ParseExact($value,'yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture)
}
function Check-Semantics($r,$e,[DateTimeOffset]$captureEnd) {
    $ds=Field $r['deployments-before'] 'deployments'
    Assert-True ($ds -is [array] -and $ds.Count -ge 1 -and $ds.Count -le 1000)
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $ds) {
        $id=Field $entry 'id'
        Assert-True ($id -is [string] -and $id -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
        Assert-True ($seen.Add($id))
        $created=Field $entry 'created_on'
        Assert-True ($created -is [string] -and $created -cmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z$')
        $at=[DateTimeOffset]::Parse($created,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)
        Assert-True ($at -le $captureEnd)
        Assert-True (Is-Text (Field $entry 'strategy') 'percentage')
        $versions=Field $entry 'versions'
        Assert-True ($versions -is [array] -and $versions.Length -gt 0 -and $versions.Length -le 1000)
    }
    $d=$ds[0]
    Assert-True (Is-Text (Field $d 'id') (Field $e 'deployment'))
    Assert-True (Is-Text (Field $d 'strategy') 'percentage')
    $vs=Field $d 'versions'
    Assert-True (Is-ArrayCount $vs 1)
    Assert-True (Is-Text (Field $vs[0] 'version_id') (Field $e 'version'))
    Assert-True (Is-Number (Field $vs[0] 'percentage') 100)
    $v=$r['version']
    Assert-True (Is-Text (Field $v 'id') (Field $e 'version'))
    Assert-True (Is-Text (Field $v 'main_module') 'worker.js')
    Assert-True (Is-Text (Field $v 'migration_tag') (Field $e 'migration'))
    Assert-True (Is-Text (Field $v 'compatibility_date') (Field $e 'compatibility'))
    Assert-True (Is-ArrayCount (Field $v 'urls') 0)
    $m=Field $v 'modules'
    Assert-True (Is-ArrayCount $m 1)
    Assert-True (Is-Text (Field $m[0] 'name') 'worker.js')
    Assert-True (Is-Text (Field $m[0] 'content_type') 'application/javascript+module')
    $b64=Field $m[0] 'content_base64'
    Assert-True ($b64 -is [string] -and $b64.Length -gt 0 -and $b64.Length -le 131072)
    $module=[Convert]::FromBase64String($b64)
    Assert-True ([Convert]::ToBase64String($module) -ceq $b64)
    Assert-True ((Get-Digest $module) -ceq (Field $e 'sourceSha256'))
    $b=Field $v 'bindings'
    Assert-True (Is-ArrayCount $b 1)
    Assert-True (Is-Text (Field $b[0] 'name') 'CHECKPOINT')
    Assert-True (Is-Text (Field $b[0] 'type') 'durable_object_namespace')
    Assert-True (Is-Text (Field $b[0] 'class_name') 'Checkpoint')
    Assert-True (Is-Text (Field $b[0] 'namespace_id') (Field $e 'namespace'))
    Assert-True (@($b[0].PSObject.Properties).Count -eq 4)
    Assert-True (Is-ArrayCount (Field $r['schedules'] 'schedules') 0)
    Assert-True (Is-Flag (Field $r['subdomain'] 'enabled') $false)
    Assert-True (Is-Flag (Field $r['subdomain'] 'previews_enabled') $false)
    $cfg=$r['settings']; $o=Field $cfg 'observability'; $l=Field $o 'logs'
    Assert-True (Is-Flag (Field $o 'enabled') $true)
    Assert-True (Is-Number (Field $o 'head_sampling_rate') 1)
    Assert-True (Is-Flag (Field $l 'enabled') $true)
    Assert-True (Is-Number (Field $l 'head_sampling_rate') 1)
    Assert-True (Is-Flag (Field $l 'persist') $true)
    Assert-True (Is-Flag (Field $l 'invocation_logs') $true)
    Assert-True (Is-Flag (Field (Field $o 'traces') 'enabled') $false)
    Assert-True (Is-Flag (Field $cfg 'logpush') $false)
    Assert-True ($null -eq (Field $cfg 'tail_consumers'))
}
function Get-Directory([string]$path) {
    # Reject UNC, provider paths, drive-relative paths, ADS and ambiguous components.
    Assert-True ($path -match '^[A-Za-z]:\\' -and $path.Substring(2) -notmatch '[:/]')
    foreach ($part in $path.Substring(3).TrimEnd('\').Split('\')) {
        if ($part.Length -eq 0) { continue }
        Assert-True ($part -notin @('.','..') -and $part -notmatch '[. ]$')
    }
    $full=[IO.Path]::GetFullPath($path)
    $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    Assert-True ($drive.DriveType -in @([IO.DriveType]::Fixed,[IO.DriveType]::Removable))
    $item=Get-Item -LiteralPath $full -Force
    Assert-True ($item -is [IO.DirectoryInfo])
    # Static ancestor check, not a race-proof filesystem handle traversal.
    $cursor=$item
    while ($null -ne $cursor) {
        $current=Get-Item -LiteralPath $cursor.FullName -Force
        Assert-True ($current -is [IO.DirectoryInfo] -and ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
        $cursor=$current.Parent
    }
    return $item.FullName
}
if ($SelfTest) {
    $ok=@('{"a":[],"b":{"n":1},"c":false}','{"a":"\uD83D\uDE00"}','{"a":null,"b":-1.25}')
    $bad=@('[{}]','{"a":1,"a":2}','{"a":1,"A":2}','{"\u0061":1}','{"a":01}','{"a":1,}','{"a":"\uD800"}','{"a":1e99}','{"__proto__":{}}','{"a":1}x','{"a":[1,]}','{"a":-0}')
    foreach ($s in $ok) { $null=Read-StrictSubset ([Text.Encoding]::UTF8.GetBytes($s)) }
    foreach ($s in $bad) {
        $rejected=$false
        try { $null=Read-StrictSubset ([Text.Encoding]::UTF8.GetBytes($s)) } catch { $rejected=$true }
        Assert-True $rejected
    }
    $rejected=$false
    try { $null=Read-StrictSubset ([byte[]]@(255)) } catch { $rejected=$true }
    Assert-True $rejected
    Assert-True ((Get-Digest ([Text.Encoding]::UTF8.GetBytes('abc'))) -ceq 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    Write-Output 'SELFTEST: PASS (17 cases; parser and SHA256 only)'
    return
}
$outReady=$false
$names=@('deployments-before','version','settings','subdomain','schedules','deployments-after')
$report=[ordered]@{Status='STOP';Stage='INPUT';VerifiedBodies=0;Live=$false;Coverage='UNKNOWN';Provenance='UNVERIFIED';WriteAllowed=$false;Production='BLOCKED';StrictParser='CONSERVATIVE_SUBSET_NOT_JS_PARITY'}
try {
    $in=Get-Directory $InputDirectory
    $out=Get-Directory $OutputDirectory
    Assert-True (-not $in.Equals($out,[StringComparison]::OrdinalIgnoreCase))
    Assert-True (-not $out.StartsWith($in.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase))
    $outReady=$true
    $pinDir=Get-Directory ([IO.Path]::GetDirectoryName($PinFile))
    Assert-True ($PinFile -match '^[A-Za-z]:\\')
    $report.Stage='PIN'
    $pinBytes=Read-Bounded $PinFile 65536
    Assert-True ((Get-Digest $pinBytes) -ceq $PinSha256.ToLowerInvariant())
    $report.PinSha256=$PinSha256.ToLowerInvariant()
    $p=Read-StrictSubset $pinBytes
    Assert-True (Is-Text (Field $p 'schema') 'PCFM-RCA197-HISTORICAL-PIN-V1')
    $pins=Field $p 'records'; $expected=Field $p 'expected'
    Assert-True (Is-ArrayCount $pins 6)
    Check-Expected $expected
    $results=@{}; $digests=@(); $times=@()
    for ($i=0;$i -lt 6;$i++) {
        $report.Stage='PIN'
        $name=$names[$i]; $pin=$pins[$i]
        Assert-True (Is-Text (Field $pin 'name') $name)
        Assert-True (Is-Number (Field $pin 'httpStatus') 200)
        $time=Field $pin 'receivedAt'
        Assert-True ($time -is [string] -and $time -cmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z$')
        $dt=[DateTimeOffset]::ParseExact($time,"yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)
        if ($i -gt 0) { Assert-True ($dt -ge $times[$i-1]) }
        $times+=,$dt
        $report.Stage='RAW_HASH'
        $h=Field $pin 'sha256'
        Assert-True ($h -is [string] -and $h -cmatch '^[0-9a-f]{64}$')
        $bytes=Read-Bounded (Join-Path $in ($name+'.json')) 2097152
        $actual=Get-Digest $bytes
        Assert-True ($actual -ceq $h)
        $report.VerifiedBodies++
        $digests+=,$actual
        $report.Stage='JSON_SUBSET'
        $results[$name]=Check-Envelope (Read-StrictSubset $bytes)
    }
    $report.Stage='CAPTURE_WINDOW'
    Assert-True (($times[5]-$times[0]).TotalSeconds -le 60)
    Assert-True ($digests[0] -ceq $digests[5])
    $report.Stage='SEMANTICS_SUBSET'
    Check-Semantics $results $expected $times[5]
    $report.Status='HISTORICAL_PARTIAL_REVIEW'
    $report.Stage='COMPLETE'
    $report.CaptureStart=$pins[0].receivedAt
    $report.CaptureEnd=$pins[5].receivedAt
    $report.DeploymentsHashMatch=$true
    $report.SelectedFieldsMatch=$true
} catch { # Never expose arbitrary input or exception contents.
}
# Save only to the caller-chosen output root. No fallback and no overwrite.
if (-not $outReady) {
    $report | ConvertTo-Json -Depth 5
    return
}
try {
    Assert-True ((Get-Directory $out) -ceq $out)
    $folder=Join-Path $out ('RCA197-Historical-'+[Guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $folder -ErrorAction Stop
    $file=Join-Path $folder 'historical-summary.json'
    $json=$report | ConvertTo-Json -Depth 5
    $f=[IO.File]::Open($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $b=[Text.UTF8Encoding]::new($false).GetBytes($json); $f.Write($b,0,$b.Length); $f.Flush($true) } finally { $f.Dispose() }
    Write-Output ('SAVED: '+$file)
    Write-Output $json
} catch { Write-Output 'STOP: OUTPUT_FAILED' }
