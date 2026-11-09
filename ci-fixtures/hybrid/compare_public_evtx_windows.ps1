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
    $subsecondExact = 0
    $wholeSecondOnly = 0
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
        if ($deltaTicks -le [TimeSpan]::TicksPerMillisecond) {
            $subsecondExact++
        } else {
            # Only acknowledge explicit whole-second truncation; do not claim exact
            # timestamps or widen acceptance for arbitrary time shifts.
            $reportedTicks = [int64]$when.UtcDateTime.Ticks
            $nativeTicks = [int64]$original.utc_ticks
            $secondTicks = [int64][TimeSpan]::TicksPerSecond
            $reportedSecond = $reportedTicks - ($reportedTicks % $secondTicks)
            $nativeSecond = $nativeTicks - ($nativeTicks % $secondTicks)
            if (($reportedTicks % $secondTicks) -ne 0 -or
                $reportedSecond -ne $nativeSecond) {
                throw "Reported time differs beyond explicit whole-second truncation"
            }
            $wholeSecondOnly++
        }
        $matched++
    }
    return [pscustomobject]@{
        matched = $matched
        subsecond_exact = $subsecondExact
        whole_second_only = $wholeSecondOnly
    }
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
    $comparison = Compare-References -References $refs -Catalog $catalog
    if ($comparison.matched -ne 9) { throw "Independent match count mismatch" }

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

    # OPS044: independently preserve the source XML's 100ns-resolution UTC
    # timestamp from the verified public EVTX; do not call it a confirmed
    # incident time or pretend Hayabusa preserved the fractional seconds.
    $nativeSourceRows = @()
    foreach ($rid in @($catalog.Keys | Sort-Object { [uint64]$_ })) {
        $eventInfo = $catalog[$rid]
        $nativeSourceRows += [ordered]@{
            record_id = [uint64]$rid
            event_id = [int]$eventInfo.event_id
            channel = [string]$eventInfo.channel
            source_xml_system_time_utc = ([datetime]::new([int64]$eventInfo.utc_ticks,
                [System.DateTimeKind]::Utc)).ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
        }
    }
    if ($nativeSourceRows.Count -ne $independentEvents.Count) {
        throw "Native source-time inventory count mismatch"
    }
    $nativeReceipt = [ordered]@{
        schema = "pcfm-ops044-public-xml-source-times-v1"
        status = "NATIVE_SOURCE_XML_TIME_PRESERVED_HAYABUSA_SUBSECOND_UNVERIFIED"
        source_sha256 = $expectedSha
        source_parser = "Microsoft Get-WinEvent -Path / EventRecord.ToXml SystemTime"
        native_source_event_count = $nativeSourceRows.Count
        hayabusa_reported_alerts = $refs.Count
        matched_record_id_event_id_channel = $comparison.matched
        exact_subsecond_time_match = $comparison.subsecond_exact
        seconds_only_time_match = $comparison.whole_second_only
        actual_user_incident_verified = $false
        source_xml_events = @($nativeSourceRows)
    }
    $receiptDir = Join-Path $env:RUNNER_TEMP "pcfm-ops044-public-native-time"
    if (Test-Path -LiteralPath $receiptDir) { throw "Refusing pre-existing native receipt directory" }
    [void](New-Item -ItemType Directory -Path $receiptDir)
    $receiptFile = Join-Path $receiptDir "source-times.json"
    $jsonReceipt = ConvertTo-Json -InputObject $nativeReceipt -Depth 8 -Compress
    [System.IO.File]::WriteAllText($receiptFile, ($jsonReceipt + "`n"),
                                  [System.Text.UTF8Encoding]::new($false))
    $receiptSha = (Get-FileHash -LiteralPath $receiptFile -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Output ("PCFM_OPS044_NATIVE_SOURCE_XML_TIME_RECEIPT events={0} alerts={1} exact={2} second_only={3} receipt_sha256={4}" -f $nativeSourceRows.Count, $refs.Count, $comparison.subsecond_exact, $comparison.whole_second_only, $receiptSha)
    Write-Output "PCFM_OPS044_TIME_SCOPE=PUBLIC_SOURCE_XML_TIME_ONLY_HAYABUSA_FRACTIONAL_MISMATCH_PRESERVED"

    Write-Output ("PCFM_OPS043_INDEPENDENT_RECORDS_MATCHED reported_alerts={0} matched={1} native_records={2} negative_cases=4 subsecond_exact={3} second_only={4} source_unchanged=true" -f $refs.Count, $comparison.matched, $independentEvents.Count, $comparison.subsecond_exact, $comparison.whole_second_only)
    Write-Output "PCFM_OPS043_CONCLUSION=PARTIAL_INDEPENDENT_RECORD_MATCH_TIMESTAMP_PRECISION_UNVERIFIED"
    Write-Output "PCFM_OPS043_SCOPE=PUBLIC_SAMPLE_WINDOWS_2022_NOT_PC_OR_INDEPENDENT_RULE_VALIDATION"
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
