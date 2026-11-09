# For public GitHub-hosted Windows Server 2022 only: independent native EVTX read.
# The only input is an upstream PUBLIC sample; NEVER use the investigated PC.
param([Parameter(Mandatory = $true)][string] $IndexPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$sourceUrl = "https://raw.githubusercontent.com/Yamato-Security/hayabusa-sample-evtx/0845333ecb4afcf64c55c6e10946383f168f308c/YamatoSecurity/CredentialAccess/T1558.003_StealOrForgeKerberosTicketsKerberoasting_Security.evtx"
$expectedSha = "957d0c301baad9e6936683b7aa727d23ca7fb6434eaea786794dae528ecffbe9"

if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_OS -ne "Windows" -or
    $env:RUNNER_ENVIRONMENT -ne "github-hosted" -or [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw "OPS043 refuses to run outside a GitHub-hosted Windows runner"
}
if (-not (Test-Path -LiteralPath $IndexPath -PathType Leaf)) {
    throw "Missing public linkage index"
}
if ((Get-Item -LiteralPath $IndexPath).Length -gt 100000) {
    throw "Linkage index exceeds size budget"
}
$index = Get-Content -LiteralPath $IndexPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($index.schema -cne "pcfm-public-independent-evtx-index-v1" -or
    $index.status -cne "HAYABUSA_REPORTED_NOT_SOURCE_VERIFIED" -or
    $index.source_sha256 -cne $expectedSha -or
    $index.source_basename -cne "fixture.evtx" -or
    $index.contains_private_case_data -ne $false) {
    throw "Public reference contract invalid"
}
$refs = @($index.event_references)
if ($refs.Count -ne 9 -or [int]$index.reported_alerts -ne 9) {
    throw "Unexpected number of Hayabusa-reported references"
}

function Assert-SameSourceHash([string] $FilePath) {
    $actual = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $expectedSha) {
        throw "Pinned public sample SHA256 mismatch"
    }
}

function Compare-References([object[]] $References, [hashtable] $Catalog) {
    $matched = 0
    foreach ($link in $References) {
        $recordId = [string][uint64]$link.record_id
        if (-not $Catalog.ContainsKey($recordId)) {
            throw "RecordID not found in independent Windows EVTX interpretation"
        }
        $original = $Catalog[$recordId]
        if ([int]$link.event_id -ne [int]$original.event_id) {
            throw "EventID mismatch between independent reader and Hayabusa"
        }
        if (-not [string]::Equals([string]$link.channel, [string]$original.channel,
                                 [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Event channel mismatch"
        }
        $when = [DateTimeOffset]::Parse([string]$link.timestamp_utc,
                   [System.Globalization.CultureInfo]::InvariantCulture,
                   [System.Globalization.DateTimeStyles]::AssumeUniversal)
        if ($when.Offset -ne [TimeSpan]::Zero) {
            throw "Report timestamp is not UTC"
        }
        $deltaTicks = [math]::Abs([double]($when.UtcDateTime.Ticks - $original.utc_ticks))
        if ($deltaTicks -gt [TimeSpan]::TicksPerMillisecond) {
            throw ("Timestamp mismatch beyond 1ms reporting precision; differenceSeconds={0}" -f ([math]::Round($deltaTicks / 10000000.0, 6)))
        }
        $matched++
    }
    return $matched
}

function Assert-Negative([string] $CaseName, [object] $BadReference,
                         [object[]] $GoodReferences, [hashtable] $Catalog) {
    $check = @($GoodReferences)
    $check[0] = $BadReference
    $wasRejected = $false
    try { [void](Compare-References -References $check -Catalog $Catalog) }
    catch { $wasRejected = $true }
    if (-not $wasRejected) {
        throw "Fail-closed regression: unexpected acceptance of $CaseName"
    }
}

$root = Join-Path $env:RUNNER_TEMP ("pcfm-ops043-" + [guid]::NewGuid().ToString("N"))
[void](New-Item -ItemType Directory -Path $root)
try {
    $evtx = Join-Path $root "fixture.evtx"
    Invoke-WebRequest -Uri $sourceUrl -OutFile $evtx -ErrorAction Stop
    if ((Get-Item -LiteralPath $evtx).Length -ne 69632) {
        throw "Unexpected public fixture size"
    }
    Assert-SameSourceHash -FilePath $evtx

    # Independent reader is the Microsoft Windows Event Log stack, NOT Hayabusa.
    $independentEvents = @(Get-WinEvent -Path $evtx -ErrorAction Stop)
    if ($independentEvents.Count -eq 0 -or $independentEvents.Count -gt 50000) {
        throw "Independent EVTX parser returned out-of-budget record count"
    }
    $catalog = @{}
    foreach ($event in $independentEvents) {
        [xml]$xml = $event.ToXml()
        $sys = $xml.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']")
        if ($null -eq $sys) { throw "Malformed native System element" }
        $channel = $sys.SelectSingleNode("*[local-name()='Channel']")
        $timestamp = $sys.SelectSingleNode("*[local-name()='TimeCreated']")
        if ($null -eq $channel -or $null -eq $timestamp) {
            throw "Missing native event channel or timestamp"
        }
        $recordId = [string][uint64]$event.RecordId
        if ($catalog.ContainsKey($recordId)) { throw "Duplicate native RecordID" }
        $instant = [DateTimeOffset]::Parse($timestamp.Attributes["SystemTime"].Value,
                   [System.Globalization.CultureInfo]::InvariantCulture,
                   [System.Globalization.DateTimeStyles]::AssumeUniversal)
        $catalog[$recordId] = @{
            event_id = [int]$event.Id
            channel = [string]$channel.InnerText
            utc_ticks = [int64]$instant.UtcDateTime.Ticks
        }
    }
    $matched = Compare-References -References $refs -Catalog $catalog
    if ($matched -ne 9) { throw "Independent match count mismatch" }

    # Deliberate mutation checks prove the join rejects forged references.
    $first = $refs[0]
    $good = @{ record_id = [uint64]$first.record_id; event_id = [int]$first.event_id;
               channel = [string]$first.channel; timestamp_utc = [string]$first.timestamp_utc }
    $bad = [pscustomobject]($good.Clone())
    $bad.record_id = [uint64]::MaxValue
    Assert-Negative "RecordID" $bad $refs $catalog
    $bad = [pscustomobject]($good.Clone())
    $bad.event_id = 999999
    Assert-Negative "EventID" $bad $refs $catalog
    $bad = [pscustomobject]($good.Clone())
    $bad.channel = "Impossible-Event-Channel"
    Assert-Negative "Channel" $bad $refs $catalog
    $bad = [pscustomobject]($good.Clone())
    $bad.timestamp_utc = ([DateTimeOffset]::Parse([string]$good.timestamp_utc).AddSeconds(5)).ToString("o")
    Assert-Negative "Timestamp" $bad $refs $catalog

    Assert-SameSourceHash -FilePath $evtx
    Write-Output ("PCFM_OPS043_INDEPENDENT_EVTX_PASS reported_alerts={0} matched={1} native_records={2} negative_cases=4 source_unchanged=true" -f $refs.Count, $matched, $independentEvents.Count)
    Write-Output "PCFM_OPS043_SCOPE=PUBLIC_SAMPLE_WINDOWS_2022_NOT_PC_OR_INDEPENDENT_RULE_VALIDATION"
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
