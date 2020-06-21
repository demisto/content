[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "", Justification="Known issue in pester")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidTrailingWhitespace", "", Justification="Ignore")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "", Justification="Ignore")]
Param()

BeforeAll {
    . "$PSScriptRoot\Infocyte.ps1"
    
    # Define Vars (scoped within 'It')
    $GUID = "^[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}$"
    $TestHost = "pegasusactual"
    $TestAlertId = "f959f69f-c3e7-42ca-af90-a76f53312720"
    $TestUserTaskId = '873ea61b-1705-49e6-87a5-57db12369ea1'
    $TestScanId = "aeac5ff3-52e9-4073-b37f-a23cadd3c69e"
    $TestResponseScanId = "36f48e02-845f-4a09-9b7a-c10d0a03ae13"
    <#
    $demisto.ServerEntry.params = @{
        InstanceName = "testpanxsoar"
        APIKey       = ""
        insecure     = $false
        proxy        = $false
        first_fetch  = '3'
        max_fetch    = '10'
    }
    #>
}

Describe 'Infocyte Integration Unit Tests' {

    BeforeAll {
        $Alerts = @()
        0..9 | ForEach-Object {
            $Alerts += [PSCustomObject]@{
                id           = "f959f69f-c3e7-42ca-af90-a76f53312720"
                name         = "kprocesshacker.sys"
                type         = "Autostart"
                hostname     = "pegasusactual"
                scanId       = "aeac5ff3-52e9-4073-b37f-a23cadd3c69e"
                fileRepId    = "a21c84c6bf2e21d69fa06daaf19b4cc34b589347"
                signed       = $true
                managed      = $null
                createdOn    = "2020-05-28T05:57:18.404Z"
                flagName     = $null
                flagWeight   = $null
                threatScore  = 9
                threatWeight = 8
                threatName   = "Bad"
                avPositives  = 21
                avTotal      = 85
                hasAvScan    = $true
                synapse      = 1.08223234150638
                size         = 45208
            }
        } 
        Mock Get-ICAlert { $Alerts }
    }

    Context "fetch-incidents" {
                                   
        It 'Returns 10 alerts after an alertId' {
            $demisto.ContextArgs = @{ lastAlertId = $TestAlertId }
            $r = Get-InfocyteAlerts
            $r.EntryContext.'Infocyte.Alert'.count | Should -Be 10
            $r.EntryContext.'Infocyte.Alert'[0].scanId | Should -Be $TestScanId
        }
    }

    Context "infocyte-scan-host" {

        It 'kicks off a scan' {
            $demisto.ContextArgs = @{ target = $Testhost }
            mock Invoke-ICScanTarget {
                [PSCustomObject]@{ userTaskId = "ffef64cd-aaf3-4c2b-a650-a2eedb9215be" }
            }
            $r = Invoke-InfocyteScan
            $r.EntryContext.'Infocyte.Task'.userTaskId | Should -Match $GUID
        }

    }

    Context "infocyte-get-taskstatus" {

        It 'gets task status on the scan' {
            $demisto.ContextArgs = @{ userTaskId = $testUserTaskId }
            $opts = [PSCustomObject]@{
                hook        = $True
                driver      = $True
                events      = $True
                memory      = $True
                module      = $True
                account     = $True
                network     = $True
                process     = $True
                artifact    = $True
                autostart   = $True
                installed   = $False
                application = $True
            }
            Mock Get-ICTask {
                [PSCustomObject]@{
                    userId       = $null
                    createdOn    = "6/9/20 5:47:04 PM"
                    endedOn      = $null
                    id           = "ffef64cd-aaf3-4c2b-a650-a2eedb9215be"
                    message      = "Scanning 1 host..."
                    name         = "Scanning OnDemand"
                    data         = @{scanId="37d56fad-b87c-42a5-b4b6-3303754e87ef"; options=$opts; scanName="20200609-1747"; updatedOn=$null}
                    progress     = 0
                    itemCount    = 1
                    relatedId    = "f5acd0e1-7012-445d-af04-1ea0a89e334c"
                    jobId        = $null
                    startedOn    = [DateTime]"6/9/20 5:47:04 PM"
                    status       = "Active"
                    type         = "Scan"
                    stats        = @{status=@{}; itemCounts=@{}}
                    archived     = $False
                    totalSeconds = $null
                }
            }
            $r = Get-InfocyteTaskStatus
            $r.EntryContext.'Infocyte.Task(val.userTaskId == obj.userTaskId)'.scanId | Should -Match $GUID
        }
    }

    Context "infocyte-run-response" {

        It 'kicks off a Terminate Process response action' {
            $demisto.ContextArgs = @{ target = $Testhost }
            Mock Get-ICExtension {
                [PSCustomObject]@{ 
                    id           = "2ffd753a-ba60-4414-8991-52aa54615e73"
                    name         = "Terminate Process"
                    type         = "action"
                    versionCount = 4
                    active       = $True
                    deleted      = $False
                    createdOn    = [DateTime]"5/12/2020 10:40:41 PM"
                    createdBy    = $null
                    updatedOn    = [DateTime]"5/26/2020 5:43:01 AM"
                    updatedBy    = $null
                    guid         = "5a2e94d9-fa88-4ffe-8aa9-ef53660b3a53"
                }
            } -ParameterFilter { $extensionName -eq "Terminate Process" }
            Mock Invoke-ICResponse {
                [PSCustomObject]@{ userTaskId = "ffef64cd-aaf3-4c2b-a650-a2eedb9215be" }
            }

            $r = Invoke-InfocyteResponse -ExtensionName "Terminate Process"
            $r.EntryContext.'Infocyte.Task'.userTaskId | Should -Match $GUID
        }
    }

    Context "infocyte-get-scanresult" {

        It 'returns scan result metadata' {
            $demisto.ContextArgs = @{ scanId = $TestScanId }
            $data = [PSCustomObject]@{
                counts = [PSCustomObject]@{
                    total = [PSCustomObject]@{
                        files = 2084
                        hooks = 0
                        hosts = 1
                        memory = 0
                        drivers = 222
                        modules = 66
                        scripts = 0
                        accounts = 14
                        artifacts = 973
                        processes = 98
                        autostarts = 725
                        totalHosts = 1
                        connections = 33
                        applications = 101
                    }
                    compromised = [PSCustomObject]@{
                        files = 5
                        hosts = 0
                        memory = 0
                        drivers = 1
                        modules = 0
                        scripts = 0
                        accounts = 0
                        artifacts = 3
                        processes = 0
                        autostarts = 1
                    }
                }
            }
            Mock Get-ICScan {
                [PSCustomObject]@{
                    id               = "aeac5ff3-52e9-4073-b37f-a23cadd3c69e"
                    targetId         = "f5acd0e1-7012-445d-af04-1ea0a89e334c"
                    name             = "20200528-0532"
                    startedOn        = [DateTime]"5/28/20 5:32:54 AM"
                    completedOn      = [DateTime]"5/28/20 5:33:21 AM"
                    updatedOn        = [DateTime]"5/28/20 5:57:42 AM"
                    updating         = $False
                    data             = $data
                    hidden           = $False
                    hostCount        = 1
                    processCount     = 98
                    moduleCount      = 66
                    driverCount      = 222
                    memoryCount      = 0
                    accountCount     = 14
                    artifactCount    = 973
                    autostartCount   = 725
                    hookCount        = 0
                    connectionCount  = 33
                    totalHostCount   = 1
                    scriptCount      = 0
                    applicationCount = 101
                }
            }
            Mock Get-ICObject {
                [PSCustomObject]@{
                    hostname  = "pegasusactual"
                    ip        = "x.x.x.x"
                    osVersion = "Windows 10 Pro 2004 Professional 64-bit"
                }
            } -ParameterFilter { $type -eq "Host" }

            $r = Get-InfocyteScanResult
            $r.EntryContext.'Infocyte.Scan'.scanId | Should -Match $GUID
        }
    }

    Context "infocyte-get-hostscanresult" {

        It 'returns hostscan results for a single host' {
            $demisto.ContextArgs = @{ scanId = $TestScanId }
            mock Get-ICHostScanResult {
                [PSCustomObject]@{
                    scanId      = "aeac5ff3-52e9-4073-b37f-a23cadd3c69e"
                    hostId      = "558feacbbae80c63d54ec1252ac34bdc285b20a7"
                    os          = "Windows 10 Pro 2004 Professional 64-bit"
                    success     = $True
                    compromised = $True
                    completedOn = [DateTime]"5/28/20 5:57:15 AM"
                    alerts      = $Alerts
                    hostname    = "pegasusactual"
                    ip          = "x.x.x.x"
                }
            }
            $r = Get-InfocyteHostScanResult
            $r.EntryContext.'Infocyte.Scan'.scanId | Should -Match $GUID
        }
    }

    Context "infocyte-get-responseresult" {

        It 'returns response action result' {
            $demisto.ContextArgs = @{ scanId = $TestResponseScanId }
            mock Get-ICResponseResult {
                [PSCustomObject]@{
                    scanId        = "36f48e02-845f-4a09-9b7a-c10d0a03ae13"
                    hostId        = "558feacbbae80c63d54ec1252ac34bdc285b20a7"
                    extensionId   = "2ffd753a-ba60-4414-8991-52aa54615e73"
                    os            = "Windows 10 Pro 2004 Professional 64-bit"
                    success       = $True
                    threatStatus  = "Unknown"
                    compromised   = $False
                    completedOn   = [DateTime]"6/3/20 1:02:41 PM"
                    runTime       = 0
                    extensionName = "Terminate Process"
                    messages      = @("Finding and killing processes that match the following search terms (name, path, or pid):",
                                    "Term[1]: C:\windows\system32\calc.exe",
                                    "Term[2]: 17604",
                                    "Term[3]: calculator, Killed 0 processes.")
                    hostname      = "pegasusactual"
                    ip            = "x.x.x.x"
                }                
            }
            $r = Get-InfocyteResponseResult
            $r.EntryContext.'Infocyte.Response'.scanId | Should -Match $GUID
        }
    }
}
