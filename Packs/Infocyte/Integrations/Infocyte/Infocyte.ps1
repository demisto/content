. $PSScriptRoot\CommonServerPowerShell.ps1

# Silence write-progress
$progressPreference = 'silentlyContinue'

function Invoke-InfocyteScan {
    $Demisto.Debug("Scanning Host: $($demisto.Args()['Target'])")
    $Target = $demisto.Args()['Target']
    $Task = Invoke-ICScanTarget -Target $target
    #$prefix = "Infocyte.Task"
    $Output = @{
        Infocyte = @{
            Task = @{
                userTaskId = $Task.userTaskId
                type       = "SCAN"
                host       = $Target
            }
        }
    }
    ReturnOutputs -ReadableOutput "Scan initiated!" -Outputs $Output | Out-Null
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

    #$prefix = "Infocyte.Task"
    $Output = @{
        Infocyte = @{
            Task = @{
                userTaskId  = $task.id
                scanId      = $task.data.scanId
                type        = $type
                progress    = $task.progress
                message     = $task.message
                status      = $task.status
                timeElapsed = $task.totalSeconds
            }
        }
    }
    ReturnOutputs -ReadableOutput "Task status retrieved" -Outputs $Output | Out-Null
}

function Get-InfocyteAlerts {
    $LastAlert = GetLastRun | Sort-Object id | Select-Object -Last 1
    if ($LastAlert) {
        $where = @{ id = @{ gt = $LastAlert.id } }
    }
    $Alerts = Get-ICAlert -where $where | Select-Object id, name, type, hostname, scanId, fileRepId, signed, managed,        createdOn, flagName, flagWeight, threatScore, threatWeight, threatName,        avPositives, avTotal, hasAvScan, synapse, size

    #$prefix = "Infocyte.Alert"
    $Output = @{
        Infocyte = @{
            Alert = @{
                id      = $Alerts.id      # "f959f69f-c3e7-42ca-af90-a76f53312720"
                name    = $Alerts.name    # "kprocesshacker.sys"
                type    = $Alerts.type    # "Autostart"
                hostname    = $Alerts.hostname   # "pegasusactual"
                scanId      = $Alerts.scanId     # "aeac5ff3-52e9-4073-b37f-a23cadd3c69e"
                sha1        = $Alerts.fileRepId  # "a21c84c6bf2e21d69fa06daaf19b4cc34b589347"
                signed      = $Alerts.signed     # true,
                managed     = $Alerts.managed       # null
                createdOn   = $Alerts.createdOn     # "2020-05-28T05:57:18.403Z"
                flagName    = $Alerts.flagname      # "Controlled Item"
                flagWeight  = $Alerts.flagweight    # 8
                threatScore = $Alerts.threatScore   # 9
                threatWeight = $Alerts.threatWeight  # 8
                threatName  = $Alerts.threatName    # "Bad"
                avPositives = $Alerts.avPositives   # 21
                avTotal     = $Alerts.avTotal       # 85
                hasAvScan   = $Alerts.hasAvScan     # $true
                synapse = $Alerts.synapse       # 1.08223234150638
                size        = $Alerts. 45208
            }
        }
    }
    ReturnOutputs -ReadableOutput "Alerts retrieved!" -Outputs $Output | Out-Null
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

    #$prefix = "Infocyte.Scan"
    $output = @{
        Infocyte = @{
            Scan = @{
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
    }
    ReturnOutputs -ReadableOutput "Scan results!" -Outputs $Output | Out-Null
}

function Get-InfocyteHostScanResult {
    <#
    if ($demisto.Args().ContainsKey('hostname')) {
        $hostname = $demisto.Args()['hostname']
    }
    elseif ($demisto.Args().ContainsKey('ip')) {
        #$ip = $demisto.Args()['ip']
    }
    else {
        Throw "hostname or ip not provided!"
    }
    #>
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
    #$prefix = "Infocyte.Scan"
    $output = @{
        Infocyte = @{
            Scan = @{
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
    }
    ReturnOutputs -ReadableOutput "Host Scan results retrieved!" -Outputs $Output | Out-Null
}

function Get-InfocyteResponseResult {
    <#
    if ($demisto.Args().ContainsKey('hostname')) {
        $hostname = $demisto.Args()['hostname']
    }
    elseif ($demisto.Args().ContainsKey('ip')) {
        #$ip = $demisto.Args()['ip']
    }
    else {
        Throw "hostname or ip not provided!"
    }
    #>
    $HostResult = Get-ICResponseResult -scanId $demisto.Args()['scanId'] -hostname $hostname
    #$prefix = "Infocyte.Response"
    $output = @{
        Infocyte = @{
            Response = @{
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
    }
    ReturnOutputs -ReadableOutput "Response results retrieved!" -Outputs $Output | Out-Null
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
    #$prefix = "Infocyte.Task"
    $output = @{
        Infocyte = @{
            Task = @{
                userTaskId    = $Task.userTaskId
                type          = "RESPONSE"
                extensionName = $ExtensionName
                target        = $Target
            }
        }
    }
    ReturnOutputs -ReadableOutput "Response action initiated!" -Outputs $Output | Out-Null
}

function Main {
    $Instance = $demisto.Params()['InstanceName']
    $Token = $demisto.Params()['APIKey']
    Import-Module -Name InfocyteHUNTAPI | Out-Null
    $v = (Get-Module -name InfocyteHUNTAPI | Select-Object -ExpandProperty Version).ToString()
    $Demisto.Debug("Initiating! Connecting to $Instance running Infocyte PSModule version $v")

    try {
        $connected = Set-ICToken -Instance $Instance -Token $Token
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
