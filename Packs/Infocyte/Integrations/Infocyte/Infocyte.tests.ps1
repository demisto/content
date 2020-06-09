. $PSScriptRoot\Infocyte.ps1

Describe 'Infocyte Integration' {

    $GUID = "^[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}$"
    $Testhost = ""
    $TestScanId = "aeac5ff3-52e9-4073-b37f-a23cadd3c69e"
    $TestScanId2 = "36f48e02-845f-4a09-9b7a-c10d0a03ae13" # Response

    $demisto.ServerEntry.params = @{
        InstanceName = "testpanxsoar"
        APIKey = ""
        insecure = $true
        proxy = $false
    }

    Context "fetch-incidents" {

        It 'returns alerts' {
            #$Demisto.ServerEntry.command = "fetch-incidents"
            Get-InfocyteAlerts
            $Demisto.Results.Contents.'Infocyte.Alert'.scanId | Should -Match $GUID
        }
    }

    Context "infocyte-scan-host" {

        AfterAll {
            $tasks = Get-ICTask -where @{ status = "Active" }
            $tasks | where-object { $_.id } | foreach-object {
                Invoke-ICAPI -Method POST -endpoint "userTasks/$($_.id)/cancel"
            }
        }
        It 'kicks off a scan' {
            #$Demisto.ServerEntry.command = "infocyte-scan-host"
            $demisto.ContextArgs = @{ Target = $Testhost }
            Invoke-InfocyteScan
            $Demisto.Results.Contents.'Infocyte.Scan'.scanId | Should -Match $GUID
        }

        It 'gets task status on the scan' {
            Start-Sleep 2
            #$Demisto.ServerEntry.command = "infocyte-get-taskstatus"
            $demisto.ContextArgs = @{ scanId = $ScanId }
            Get-InfocyteTaskStatus
            $Demisto.Results.Contents.'Infocyte.Scan'.scanId | Should -Match $GUID
        }
    }

    Context "infocyte-kill-process" {

        AfterAll {
            $tasks = Get-ICTask -where @{ status = "Active" }
            $tasks | where-object { $_.id } | foreach-object {
                Invoke-ICAPI -Method POST -endpoint "userTasks/$($_.id)/cancel"
            }
        }

        It 'kicks off a response action' {
            #$Demisto.ServerEntry.command = "infocyte-kill-process"
            $demisto.ContextArgs = @{ Target = $Testhost }
            Invoke-InfocyteResponse -ExtensionName "Terminate Process"
            $Demisto.Results.Contents.'Infocyte.Response'.scanId | Should -Match $GUID
        }

        It 'gets task status on the response action' {
            Start-Sleep 2
            #$Demisto.ServerEntry.command = "infocyte-get-taskstatus"
            $demisto.ContextArgs = @{ scanId = $ScanId }
            Get-InfocyteTaskStatus
            $Demisto.Results.Contents.'Infocyte.Response'.scanId | Should -Match $GUID
        }
    }

    Context "infocyte-get-scanresult" {

        It 'returns scan result metadata' {
            #$Demisto.ServerEntry.command = "infocyte-get-scanresult"
            $demisto.ContextArgs = @{ scanId = $TestScanId }
            Get-InfocyteScanResult
            $demisto.Results.Contents.'Infocyte.Scan'.scanId | Should -Match $GUID
        }
    }

    Context "infocyte-get-hostscanresult" {

        It 'returns hostscan results for a single hosy' {
            #$Demisto.ServerEntry.command = "infocyte-get-hostscanresult"
            $demisto.ContextArgs = @{ scanId = $TestScanId }
            Get-InfocyteHostScanResult
            $demisto.Results.Contents.'Infocyte.Scan'.scanId | Should -Match $GUID
        }
    }

    Context "infocyte-get-responseresult" {

        It 'returns response action result' {
            #$Demisto.ServerEntry.command = "infocyte-get-responseresult"
            $demisto.ContextArgs = @{ scanId = $TestScanId2 }
            Get-InfocyteResponseResult
            $demisto.Results.Contents.'Infocyte.Response'.scanId | Should -Match $GUID
        }
    }
}