. $PSScriptRoot\CommonServerPowerShell.ps1

# Silence write-progress
$progressPreference = 'silentlyContinue'

function Invoke-InfocyteScan {
    $Demisto.Debug("Scanning Host: $($demisto.Args()['Target'])")
    $Target = $demisto.Args()['Target']
    $Task = Invoke-ICScanTarget -Target $target
    $prefix = "Infocyte.Task"
    $Output = @{
        'Infocyte.Task' = @{
            userTaskId = $Task.userTaskId
            type       = "SCAN"
            host       = $Target
        }
    }
    ReturnOutputs -ReadableOutput ([PSCustomObject]$Output."$prefix" | ConvertTo-Markdown) -Outputs $Output | Out-Null
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

    $prefix = "Infocyte.Task(val.userTaskId == obj.userTaskId)"
    $Output = @{
        'Infocyte.Task(val.userTaskId == obj.userTaskId)' = @{
            userTaskId  = $task.id
            scanId      = $task.data.scanId
            type        = $type
            progress    = $task.progress
            message     = $task.message
            status      = $task.status
            timeElapsed = $task.totalSeconds
        }
    }
    ReturnOutputs -ReadableOutput ([PSCustomObject]$Output."$prefix" | ConvertTo-Markdown) -Outputs $Output | Out-Null
}

function Get-InfocyteAlerts {
    $fields = @('id', 'name', 'type', 'hostname', 'scanId', 'fileRepId', 'signed', 'managed', 'createdOn', 'flagName',
     'flagWeight', 'threatScore', 'threatWeight', 'threatName', 'avPositives', 'avTotal', 'hasAvScan', 'synapse', 'size')
    $max = $demisto.Params()['max_fetch']

    if ($demisto.Args().ContainsKey('alertId')) {
        $where = @{ id = $demisto.Args()['alertId'] }
    }
    elseif ($demisto.Args().ContainsKey('lastAlertId')) {
        $where = @{ id = @{ gt = $demisto.Args()['lastAlertId'] } }
    }
    else {
        $LastRun = $demisto.GetLastRun()
        $LastAlert = $LastRun.results.'Infocyte.Alert' | Sort-Object id | Select-Object -Last 1
        if ($LastAlert) {
            $where = @{ id = @{ gt = $LastAlert.id } }
        }
    }

    $Alerts = Get-ICAlert -where $where | Select-Object -First $max | Select-Object $fields
    if (-NOT $Alerts) {
        return
    }

    $formatedAlerts = @()
    $Alerts | Foreach-Object {
        $formatedAlerts += [PSCustomObject]@{
            id      = $_.id      # "f959f69f-c3e7-42ca-af90-a76f53312720"
            name    = $_.name    # "kprocesshacker.sys"
            type    = $_.type    # "Autostart"
            hostname    = $_.hostname   # "pegasusactual"
            scanId      = $_.scanId     # "aeac5ff3-52e9-4073-b37f-a23cadd3c69e"
            sha1        = $_.fileRepId  # "a21c84c6bf2e21d69fa06daaf19b4cc34b589347"
            signed      = $_.signed     # true,
            managed     = $_.managed       # null
            createdOn   = $_.createdOn     # "2020-05-28T05:57:18.403Z"
            flagName    = $_.flagname      # "Controlled Item"
            flagWeight  = $_.flagweight    # 8
            threatScore = $_.threatScore   # 9
            threatWeight = $_.threatWeight  # 8
            threatName  = $_.threatName    # "Bad"
            avPositives = $_.avPositives   # 21
            avTotal     = $_.avTotal       # 85
            hasAvScan   = $_.hasAvScan     # $true
            synapse     = $_.synapse       # 1.08223234150638
            size        = $_. 45208
        }
    }
    $prefix = "Infocyte.Alert"
    $Output = @{
        'Infocyte.Alert' = $formatedAlerts
    }
    ReturnOutputs -ReadableOutput ([PSCustomObject]$Output."$prefix" | ConvertTo-Markdown)  -Outputs $Output | Out-Null
}

function Get-InfocyteScanResult {
    $scanId = $demisto.Args()['scanId']
    $Scan = Get-ICScan -id $scanId

    # Get total count of objects
    $totalCount = 0
    $compromisedCount = 0;
    $scan.data.counts.compromised | Get-Member -Type NoteProperty | ForEach-Object { $compromisedCount += $scan.data.counts.compromised | Select-Object -ExpandProperty $_.Name }
    $scan.data.counts.total | Get-Member -Type NoteProperty | ForEach-Object { $totalCount += $scan.data.counts.total | Select-Object -ExpandProperty $_.Name }
    $hostCount = $scan.hostCount

    $Hosts = Get-ICObject -Type Host -ScanId $scanId | Select-Object hostname, ip, osVersion
    if ($Scan) {
        $Alerts = Get-ICAlert -where @{ scanId = $scanId } | Select-Object id, name, type, hostname, scanId, fileRepId, signed, managed, createdOn, flagName, flagWeight, threatScore, threatWeight, threatName, avPositives, avTotal, hasAvScan, synapse, size

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
    }

    $prefix = "Infocyte.Scan"
    $output = @{
        'Infocyte.Scan' = @{
            scanId             = $Scan.data.scanId
            compromised        = $HostResult.compromised
            completeOn          = $Scan.completedOn
            hostCount          = $hostCount
            objectCount        = $totalCount
            compromisedObjects = $compromisedCount
            hosts              = $Hosts
            alerts             = $Alerts
            alertCount         = $AlertCount
            hostname           = $HostResult.hostname
            ip                 = $HostResult.ip
        }
    }
    ReturnOutputs -ReadableOutput ([PSCustomObject]$Output."$prefix" | ConvertTo-Markdown) -Outputs $Output | Out-Null
}

function Get-InfocyteHostScanResult {
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
    $prefix = "Infocyte.Scan"
    $output = @{
        'Infocyte.Scan' = @{
            scanId             = $HostResult.scanId
            hostId             = $HostResult.hostId
            os                 = $HostResult.osVersion
            success            = $HostResult.success
            compromised        = $HostResult.compromised
            completedOn        = $HostResult.completedOn
            alerts             = $HostResult.alerts | Select-Object id, name, type, hostname, scanId, fileRepId, signed, managed, createdOn, flagName, flagWeight, threatScore, threatWeight, threatName, avPositives, avTotal, hasAvScan, synapse, size
            alertCount         = $AlertCount
            hostname           = $HostResult.hostname
            ip                 = $HostResult.ip
        }
    }
    ReturnOutputs -ReadableOutput ([PSCustomObject]$Output."$prefix" | ConvertTo-Markdown) -Outputs $Output | Out-Null
}

function Get-InfocyteResponseResult {
    $HostResult = Get-ICResponseResult -scanId $demisto.Args()['scanId'] -hostname $hostname
    $prefix = "Infocyte.Response"
    $output = @{
        'Infocyte.Response' = @{
            scanId      = $HostResult.scanId
            hostId      = $HostResult.hostId
            extensionId = $HostResult.extensionId
            extensionName = $HostResult.extensionName
            os          = $HostResult.osVersion
            success     = $HostResult.success
            threatStatus = $HostResult.threatStatus
            compromised = $HostResult.compromised
            completedOn = $HostResult.completedOn
            messages    = $HostResult.output
            hostname    = $HostResult.hostname
            ip          = $HostResult.ip
        }
    }
    ReturnOutputs -ReadableOutput ([PSCustomObject]$Output."$prefix" | ConvertTo-Markdown) -Outputs $Output | Out-Null
}

function Invoke-InfocyteResponse {
    param(
        [String]$ExtensionName
    )
    $Ext = Get-ICExtension -where @{ name = $ExtensionName } | Select-Object -Last 1
	if (-NOT $Ext) {
		Throw "Extension with name $ExtensionName does not exist!"
    }
    $Task = Invoke-ICResponse -Target $demisto.Args()['Target'] -ExtensionId $Ext.Id
    $prefix = "Infocyte.Task"
    $output = @{
        'Infocyte.Task' = @{
            userTaskId    = $Task.userTaskId
            type          = "RESPONSE"
            extensionName = $ExtensionName
            target        = $Target
        }
    }
    ReturnOutputs -ReadableOutput ([PSCustomObject]$Output."$prefix" | ConvertTo-Markdown) -Outputs $Output | Out-Null
}

Function ConvertTo-Markdown {
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [PSCustomObject[]]$collection,

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
            if ($MaxColumnWidth) {
                # ...
            }
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

        $separator = @()
        ForEach($key in $columns.Keys) {
            $separator += '-' * $columns[$key]
        }
        $separator -join ' | '

        ForEach($item in $items) {
            $values = @()
            ForEach($key in $columns.Keys) {
                $values += ('{0,-' + $columns[$key] + '}') -f $item.($key)
            }
            $values -join ' | '
        }
    }
}

function Main {
    # Parse Params
    $Instance = $demisto.Params()['InstanceName']
    $Token = $demisto.Params()['APIKey']
    $DisableSSLVerification = $demisto.Params()['insecure']
    if ($demisto.Params()['proxy']) {
        # Parse proxy envirorment variable
        $a = $Env:HTTPS_PROXY -split "//" | Select-Object -Last 1
        if ($a -match "@") {
            $a = $a -split "@"
            $Proxy = $a | Select-Object -Last 1
            $ProxyUser = $a[0] -split ":" | Select-Object -First 1;
            $ProxyPass = $a[0] -split ":" | Select-Object -Last 1;
        } else {
            $Proxy = $a
        }
    }

    Import-Module -Name InfocyteHUNTAPI | Out-Null
    $v = (Get-Module -name InfocyteHUNTAPI | Select-Object -ExpandProperty Version).ToString()
    $Demisto.Debug("Initiating! Connecting to $Instance running Infocyte PSModule version $v")

    try {
        $connected = Set-ICToken -Instance $Instance -Token $Token -Proxy $Proxy -ProxyUser $ProxyUser -ProxyPass $ProxyPass -DisableSSLVerification:$DisableSSLVerification
        if (-NOT $connected) {
            ReturnError "Could not connect to instance $Instance!"
            return
        }
    } catch {
        ReturnError "Could not connect to instance $Instance. [$($_.Exception.Message)]"
        return
    }

    $Demisto.Debug("Connected to $Instance! Running command $($Demisto.GetCommand())")

    try {
        Switch ($Demisto.GetCommand()) {
            "test-module" {
                $Demisto.Debug("Running test-module")
                ReturnOutputs "ok"
            }
            "fetch-incidents" {
                Get-InfocyteAlerts
            }
            "infocyte-get-alerts" {
                Get-InfocyteAlerts
            }
            "infocyte-scan-host" {
                Invoke-InfocyteScan
            }
            "infocyte-get-taskstatus" {
                Get-InfocyteTaskStatus
            }
            "infocyte-get-scanresult" {
                Get-InfocyteScanResult
            }
            "infocyte-get-hostscanresult" {
                Get-InfocyteHostScanResult
            }
            "infocyte-run-response" {
                Invoke-InfocyteResponse -ExtensionName $demisto.Args()['ExtensionName']
            }
            "infocyte-get-responseresult" {
                Get-InfocyteResponseResult
            }
            "infocyte-isolate-host" {
                Invoke-InfocyteResponse -ExtensionName "Host Isolation"
            }
            "infocyte-restore-host" {
                Invoke-InfocyteResponse -ExtensionName "Host Isolation Restore"
            }
            "infocyte-recover-file" {
                Invoke-InfocyteResponse -ExtensionName "Recover Files"
            }
            "infocyte-start-ediscovery" {
                Invoke-InfocyteResponse -ExtensionName "E-Discovery"
            }
            "infocyte-collect-evidence" {
                Invoke-InfocyteResponse -ExtensionName "Collect ForensicEvidence"
            }
            "infocyte-kill-process" {
                Invoke-InfocyteResponse -ExtensionName "Terminate Process"
            }
        }
    }
    catch {
        ReturnError "Something has gone wrong in MAIN(): $($_.Exception.Message)"
    }
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1") {
    Main
}
