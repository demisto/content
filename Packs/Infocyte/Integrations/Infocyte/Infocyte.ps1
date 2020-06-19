. $PSScriptRoot\CommonServerPowerShell.ps1

# Silence write-progress
$Test = $False
$progressPreference = 'silentlyContinue'

function Invoke-InfocyteScan {
    $Target = $demisto.Args()['target']
    $Demisto.Debug("Scanning Host: $Target")
    $Task = Invoke-ICScanTarget -Target $Target
    $Output = [PSCustomObject]@{
        'Infocyte.Task' = [PSCustomObject]@{
            userTaskId = $Task.userTaskId
            type       = "SCAN"
            target       = $Target
        }
    }
    $MDOutput = $Output."Infocyte.Task" | ConvertTo-Markdown
    ReturnOutputs2 -ReadableOutput $MDOutput -Outputs $Output
}

function Get-InfocyteTaskStatus {
    $task = Get-ICTask -id $demisto.Args()['userTaskId']
    #Get Custom Type
    $opts = $task.data.options
    if ($Task.type -eq "Scan" -AND $opts.extensionIds.count -gt 0 -AND -NOT $opts.driver -AND -NOT $opts.application) {
        $type = "RESPONSE"
    }
    else {
        $type = "SCAN"
    }
    $Output = [PSCustomObject]@{
        'Infocyte.Task(val.userTaskId == obj.userTaskId)' = [PSCustomObject]@{
            userTaskId  = $task.id
            scanId      = $task.data.scanId
            type        = $type
            progress    = $task.progress
            message     = $task.message
            status      = $task.status
            timeElapsed = $task.totalSeconds
        }
    }
    $MDOutput = $Output.'Infocyte.Task(val.userTaskId == obj.userTaskId)' | ConvertTo-Markdown
    ReturnOutputs2 -ReadableOutput $MDOutput -Outputs $Output -RawResponse $task
}

function Get-InfocyteAlerts {
    if (-NOT $max_fetch) {
        $max_fetch = 10
    }
    if (-NOT $first_fetch) {
        $first_fetch = 3
    }

    if ($demisto.Args().ContainsKey('alertId')) {
        $where = @{ id = $demisto.Args()['alertId'] }
        $Alerts = Get-ICAlert -where $where
        if (-NOT $Alerts) {
            ReturnError "No alert found with that Id."
            return
        }
    }
    elseif ($demisto.Args().ContainsKey('lastAlertId')) {
        $where = @{ id = @{ gt = $demisto.Args()['lastAlertId'] } }
        if (-NOT $demisto.Args().ContainsKey('max')) {
            $max = $max_fetch
        } else {
            $max = $demisto.Args()['max']
        }
        $Demisto.Debug("Retreiving $max alerts following lastAlertId: $($demisto.Args()['lastAlertId'])")
        $Alerts = Get-ICAlert -where $where | Select-Object -First $max
        if (-NOT $Alerts) {
            $Demisto.Log("No alerts found following lastAlertId $($demisto.Args()['lastAlertId']).")
            return
        }
    }
    else {
        $LastRun = $Demisto.GetLastRun()
        $Demisto.Debug("LastAlert: $($LastRun|Convertto-Json -compress)")
        if ($LastRun.lastAlertId) {
            $Demisto.Debug("Found lastAlertId: $($LastRun | Convertto-Json -compress)")
            $where = @{ id = @{ gt = $LastRun.lastAlertId } }
        } else {
            $Demisto.Debug("First run: Retrieving all alerts for past $first_fetch days")
            $where = @{ createdOn = @{ gt = (Get-Date).AddDays(-[int]$first_fetch) }}
        }
        $Alerts = Get-ICAlert -where $where | Select-Object -First $max_fetch
        if (-NOT $Alerts) {
            $Demisto.Log("No new alerts found.")
            if ($LastRun.lastAlertId) {
                $Demisto.SetLastRun(@{ lastAlertId = $LastRun.lastAlertId })
            }
            return
        }
        $LastAlertId = $Alerts | Select-Object -Last 1 -ExpandProperty id
        $Demisto.SetLastRun(@{ lastAlertId = $LastAlertId})
    }
    $Output = [PSCustomObject]@{
        'Infocyte.Alert' = $Alerts | Select-Object id,
            name,
            type,
            hostname,
            scanId,
            @{ N="sha1"; E={ $_.fileRepId }},
            signed,
            managed,
            createdOn,
            flagName,
            flagWeight,
            threatScore,
            threatWeight,
            threatName,
            avPositives,
            avTotal,
            hasAvScan,
            @{ N='synapseScore'; E={ if ($_.synapse) { [math]::Round($_.synapse,2)}}},
            size
    }

    if ($Demisto.GetCommand() -eq "fetch-incidents") {
        $Incidents = @()
        $Output.'Infocyte.Alert' | Foreach-Object {
            $NewAlert = @{
                name = "$($_.type)-$($_.name)"
                occurred = $_.createdOn
                rawJSON = $_ | ConvertTo-JSON -Depth 2
                severity = 1
            }
            $Incidents += $NewAlert
        }
        $Demisto.Incidents($Incidents)
    } else {

        $MDOutput = $Output.'Infocyte.Alert' |
            Select-Object id, name, type, sha1, size, threatName, flagName,
            @{N='av'; E={ "$($_.avPositives)/$($_.avTotal)" }}, synapseScore |
            ConvertTo-Markdown
        ReturnOutputs2 -ReadableOutput $MDOutput -Outputs $Output -RawResponse $Alerts
    }
}

function Get-InfocyteScanResult {
    $scanId = $demisto.Args()['scanId']
    $Scan = Get-ICScan -id $scanId
    if (-NOT $Scan) {
        $Demisto.Error("No scan with that Id")
    }

    # Get total count of objects
    $totalCount = 0
    $compromisedCount = 0;
    $scan.data.counts.compromised | Get-Member -Type NoteProperty |
        ForEach-Object { $compromisedCount += $scan.data.counts.compromised | Select-Object -ExpandProperty $_.Name }
    $scan.data.counts.total | Get-Member -Type NoteProperty |
        ForEach-Object { $totalCount += $scan.data.counts.total | Select-Object -ExpandProperty $_.Name }
    $hostCount = $scan.hostCount

    $Hosts = Get-ICObject -Type Host -ScanId $scanId | Select-Object hostname, ip, osVersion
    $Alerts = Get-ICAlert -where @{ scanId = $scanId } |
        Select-Object id, name, type, hostname, @{N='sha1'; E={ $_.fileRepId }}, size, flagName, flagWeight, threatScore, threatWeight, threatName, avPositives, avTotal, @{ N='synapseScore'; E={ if ($_.synapse) { [math]::Round($_.synapse,2)}}}

    # Handle counting for 1 item (powershell makes this hard)
    if ($HostResult.alerts) {
        if ($HostResult.alerts.count) {
            $AlertCount = $HostResult.alerts.count
        } else {
            $AlertCount = 1
        }
    } else {
        $AlertCount = 0
    }
    $output = [PSCustomObject]@{
        'Infocyte.Scan' = [PSCustomObject]@{
            scanId             = $scanId
            completeOn         = $Scan.completedOn
            hostCount          = $hostCount
            objectCount        = $totalCount
            compromisedObjects = $compromisedCount
            Host               = $Hosts
            Alert              = $Alerts
            alertCount         = $AlertCount
        }
    }
    $MDOutput = $Output.'Infocyte.Scan' | Select-Object -ExcludeProperty alerts | ConvertTo-Markdown
    $MDOutput += "`n#### Alerts`n"
    $MDOutput += $Output.'Infocyte.Scan'.alerts |
         Select-Object id, name, type, sha1, size, threatName, flagName, @{N='av'; E={ "$($_.avPositives)/$($_.avTotal)" }}, synapseScore |
         ConvertTo-Markdown
    ReturnOutputs2 -ReadableOutput $MDOutput -Outputs $Output
}

function Get-InfocyteHostScanResult {
    if ($Demisto.args().ContainsKey('hostname')) {
        $hostname = $demisto.Args()['hostname']
    }
    $HostResult = Get-ICHostScanResult -scanId $demisto.Args()['scanId'] -hostname $hostname
    # Handle counting for 1 item (powershell makes this hard)
    if ($HostResult.alerts) {
        if ($HostResult.alerts.count) {
            $AlertCount = $HostResult.alerts.count
        } else {
            $AlertCount = 1
        }
    } else {
        $AlertCount = 0
    }
    $Alerts = $HostResult.alerts |
     Select-Object id, name, @{N='sha1'; E={ $_.fileRepId }}, size, flagName, flagWeight, threatScore, threatWeight, threatName, avPositives, avTotal, @{ N = 'synapseScore'; E = { if ($_.synapse) { [math]::Round($_.synapse,2)}} }
    $output = [PSCustomObject]@{
        'Infocyte.Scan' = [PSCustomObject]@{
            hostId             = $HostResult.hostId
            hostname           = $HostResult.hostname
            ip                 = $HostResult.ip
            completedOn        = $HostResult.completedOn
            scanId             = $HostResult.scanId
            os                 = $HostResult.osVersion
            success            = $HostResult.success
            compromised        = $HostResult.compromised
            alertCount         = $AlertCount
            Alert              = $Alerts
        }
    }
    $MDOutput = $Output.'Infocyte.Scan' | Select-Object -ExcludeProperty alerts | ConvertTo-Markdown
    $MDOutput += "`n#### Alerts`n`n"
    $MDOutput += $Output.'Infocyte.Scan'.alerts |
         Select-Object id, name, type, sha1, size, threatName, flagName, @{N='av'; E={ "$($_.avPositives)/$($_.avTotal)" }}, synapseScore |
         ConvertTo-Markdown
    ReturnOutputs2 -ReadableOutput $MDOutput -Outputs $Output -RawResponse $HostResult
}

function Get-InfocyteResponseResult {
    if ($Demisto.args().ContainsKey('hostname')) {
        $hostname = $demisto.Args()['hostname']
    }
    $HostResult = Get-ICResponseResult -scanId $demisto.Args()['scanId'] -hostname $hostname
    $output = [PSCustomObject]@{
        'Infocyte.Response' = [PSCustomObject]@{
            hostname    = $HostResult.hostname
            ip          = $HostResult.ip
            scanId      = $HostResult.scanId
            hostId      = $HostResult.hostId
            extensionId = $HostResult.extensionId
            extensionName = $HostResult.extensionName
            os          = $HostResult.os
            success     = $HostResult.success
            threatStatus = $HostResult.threatStatus
            compromised = $HostResult.compromised
            completedOn = $HostResult.completedOn
            messages    = $HostResult.messages
        }
    }
    $MDOutput = $Output.'Infocyte.Response' |
         Select-Object hostname, ip, extensionName, completedOn, os, success, threatStatus |
         ConvertTo-Markdown
    $MDOutput += "`n#### Messages`n`n"
    $MDOutput += $Output.'Infocyte.Response'.messages
    ReturnOutputs2 -ReadableOutput $MDOutput -Outputs $Output -RawResponse $HostResult
}

function Invoke-InfocyteResponse {
    param(
        [String]$ExtensionName
    )
    $Ext = Get-ICExtension -where @{ name = $ExtensionName } | Select-Object -Last 1
	if (-NOT $Ext) {
		Throw "Extension with name $ExtensionName does not exist!"
    }
    $Task = Invoke-ICResponse -Target $demisto.Args()['target'] -ExtensionId $Ext.Id
    $output = [PSCustomObject]@{
        'Infocyte.Task' = [PSCustomObject]@{
            userTaskId    = $Task.userTaskId
            type          = "RESPONSE"
            extensionName = $ExtensionName
            target        = $demisto.Args()['target']
        }
    }
    $MDOutput = $Output.'Infocyte.Task' | ConvertTo-Markdown
    ReturnOutputs2 -ReadableOutput $MDOutput -Outputs $Output -RawResponse $Task
}

Function ConvertTo-Markdown {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification = "Pester is wrong")]
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [Object[]]$collection,

        [Parameter(
            Position = 1
        )]
        [int]$MaxColumnWidth = 80
    )

    Begin {
        $items = @()
        $columns = @{}
    }

    Process {
        ForEach($item in $collection) {
            $items += $item
            $item.PSObject.Properties | ForEach-Object {
                if ($null -ne $_.Value ){
                    if (-not $columns.ContainsKey($_.Name) -or
                        ($columns[$_.Name] -lt $_.Value.ToString().Length -AND $columns[$_.Name] -ne $MaxColumnWidth)) {
                        $columns[$_.Name] = [Math]::Min($_.Value.ToString().Length, $MaxColumnWidth)
                    }
                }
            }
        }
    }

    End {
        ForEach($key in $($columns.Keys)) {
            $columns[$key] = [Math]::Max($columns[$key], $key.Length)
        }

        $header = @()
        ForEach($key in $columns.Keys) {
            $header += ('{0,-' + $columns[$key] + '}') -f $key
        }
        $header -join ' | '
        "`n"
        $separator = @()
        ForEach($key in $columns.Keys) {
            $separator += '-' * $columns[$key]
        }
        $separator -join ' | '
        "`n"
        ForEach($item in $items) {
            $values = @()
            ForEach($key in $columns.Keys) {
                $values += ('{0,-' + $columns[$key] + '}') -f $item.($key)
            }
            $values -join ' | '
            "`n"
        }
    }
}

# Override ReturnOutputs (use [PSCustomOject] inputs instead of [hashtables]inputs)
# NOTE: This will be depreciated once these updates to ReturnOutputs in CommonServerPowershell.ps1
# are in the new content release
function ReturnOutputs2 ([string]$ReadableOutput, [Object]$Outputs, [Object]$RawResponse) {
    $entry = @{
        Type           = [EntryTypes]::note;
        ContentsFormat = [EntryFormats]::json.ToString();
        HumanReadable  = $ReadableOutput;
        Contents       = $RawResponse;
        EntryContext   = $Outputs
    }
    # Return 'readable_output' only if needed
    if ($ReadableOutput -and -not $outputs -and -not $RawResponse) {
        $entry.Contents = $ReadableOutput
        $entry.ContentsFormat = [EntryFormats]::text.ToString();
    }
    elseif ($Outputs -and -not $RawResponse) {
        # if RawResponse was not provided but outputs were provided then set Contents as outputs
        $entry.Contents = $Outputs
    }
    $demisto.Results($entry) | Out-Null
    return $entry
}

function Main {

    # Parse Params
    $Instance = $demisto.Params()['InstanceName']
    $Token = $demisto.Params()['APIKey']
    if ($demisto.Params().ContainsKey('insecure')) {
        $DisableSSLVerification = $demisto.Params()['insecure']
    } else {
        $DisableSSLVerification = $false
    }
    if ($demisto.Params().ContainsKey('proxy') -AND $demisto.Params()['proxy']) {
        # Parse proxy envirorment variable
        if ($Env:HTTPS_PROXY) {
            $a = $Env:HTTPS_PROXY -split "//" | Select-Object -Last 1
            if ($a -match "@") {
                $a = $a -split "@"
                $Proxy = $a | Select-Object -Last 1
                $ProxyUser = $a[0] -split ":" | Select-Object -First 1;
                $ProxyPass = $a[0] -split ":" | Select-Object -Last 1;
                $Demisto.Debug("Using Proxy: $($ProxyUser):*****@$Proxy")
            } else {
                $Proxy = $a
                $Demisto.Debug("Using Proxy: $Proxy")
            }
        } else {
            $Demisto.Error('Proxy was selected but not found in $Env:HTTPS_PROXY')
        }
    }
    if ($Demisto -AND $demisto.Params().ContainsKey('max_fetch')) {
        $Script:max_fetch = [int]$demisto.Params()['max_fetch']
    }
    if ($demisto.Params().ContainsKey('first_fetch')) {
        $Script:first_fetch = [int]($demisto.Params()['first_fetch'] -split " " | Select-Object -First 1)
    }

    Import-Module -Name InfocyteHUNTAPI | Out-Null
    $v = (Get-Module -name InfocyteHUNTAPI | Select-Object -ExpandProperty Version).ToString()
    $Demisto.Debug("Initiating! Connecting to $Instance running Infocyte PSModule version $v")

    try {
        $connected = Set-ICToken -Instance $Instance -Token $Token -Proxy $Proxy -ProxyUser $ProxyUser -ProxyPass $ProxyPass -DisableSSLVerification:$DisableSSLVerification
        if (-NOT $connected) {
            ReturnError -Message "Could not connect to instance $Instance!" | Out-Null
            return
        }
    } catch {
        ReturnError -Message "Could not connect to instance $Instance." -Err $_ | Out-Null
        return
    }

    $Demisto.Debug("Connected to $Instance! Running command $($Demisto.GetCommand())")

    try {
        Switch ($Demisto.GetCommand()) {
            "test-module" {
                $Demisto.Debug("Running test-module")
                ReturnOutputs2 "ok" | Out-Null
            }
            "fetch-incidents" {
                Get-InfocyteAlerts | Out-Null
            }
            "infocyte-get-alerts" {
                Get-InfocyteAlerts | Out-Null
            }
            "infocyte-scan-host" {
                Invoke-InfocyteScan | Out-Null
            }
            "infocyte-get-taskstatus" {
                Get-InfocyteTaskStatus | Out-Null
            }
            "infocyte-get-scanresult" {
                Get-InfocyteScanResult | Out-Null
            }
            "infocyte-get-hostscanresult" {
                Get-InfocyteHostScanResult | Out-Null
            }
            "infocyte-get-responseresult" {
                Get-InfocyteResponseResult | Out-Null
            }
            "infocyte-run-response" {
                Invoke-InfocyteResponse -ExtensionName $demisto.Args()['extensionName'] | Out-Null
            }
            "infocyte-isolate-host" {
                Invoke-InfocyteResponse -ExtensionName "Host Isolation" | Out-Null
            }
            "infocyte-restore-host" {
                Invoke-InfocyteResponse -ExtensionName "Host Isolation Restore" | Out-Null
            }
            "infocyte-recover-file" {
                Invoke-InfocyteResponse -ExtensionName "Recover Files" | Out-Null
            }
            "infocyte-start-ediscovery" {
                Invoke-InfocyteResponse -ExtensionName "E-Discovery" | Out-Null
            }
            "infocyte-collect-evidence" {
                Invoke-InfocyteResponse -ExtensionName "Collect ForensicEvidence" | Out-Null
            }
            "infocyte-kill-process" {
                Invoke-InfocyteResponse -ExtensionName "Terminate Process" | Out-Null
            }
        }
    }
    catch {
        ReturnError -Message "Something has gone wrong in Infocyte.ps1:Main() [$($_.Exception.Message)]" -Err $_ | Out-Null
        return
    }
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT $Test) {
    Main
}
