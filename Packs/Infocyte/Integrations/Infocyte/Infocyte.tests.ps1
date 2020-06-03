. $PSScriptRoot\Infocyte.ps1

$GUID = "^[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}$"
$Testhost = "pegasusactual"
$TestScanId = "aeac5ff3-52e9-4073-b37f-a23cadd3c69e"
$TestScanId2 = "36f48e02-845f-4a09-9b7a-c10d0a03ae13" # Response

Describe 'Infocyte Integration' {

    Context "test-module" {
        Mock ReturnOutputs {}

        It 'returns ok on test-module' {
            $Demisto.ServerEntry.command = "test-module"
            #$demisto.ContextArgs = @{ Target = 'pegasusactual' }
            Main
            Assert-MockCalled -CommandName ReturnOutputs -Times 1
        }
    }

    Context "fetch-incidents" {

        It 'returns alerts' {
            $Demisto.ServerEntry.command = "fetch-incidents"
            Main
            $Demisto.Results.Contents.Infocyte.Alert.scanId | Should -Match $GUID
        }
    }

    Context "infocyte-scan-host" {

        It 'kicks off a scan' {
            $Demisto.ServerEntry.command = "infocyte-scan-host"
            $demisto.ContextArgs = @{ Target = $Testhost }
            Main
            $Demisto.Results.Contents.Infocyte.Scan.scanId | Should -Match $GUID
        }

        It 'gets task status on the scan' {
            Start-Sleep 2
            $Demisto.ServerEntry.command = "infocyte-get-taskstatus"
            $demisto.ContextArgs = @{ scanId = $ScanId }
            Main
            $Demisto.Results.Contents.Infocyte.Scan.scanId | Should -Match $GUID
        }

        AfterAll {
            $tasks = Get-ICTask -where @{ status = "Active" }
            $tasks | where-object { $_.id } | foreach-object {
                Invoke-ICAPI -Method POST -endpoint "userTasks/$($_.id)/cancel"
            }
        }
    }

    Context "infocyte-kill-process" {

        It 'kicks off a response action' {
            $Demisto.ServerEntry.command = "infocyte-kill-process"
            $demisto.ContextArgs = @{ Target = $Testhost }
            Main
            $Demisto.Results.Contents.Infocyte.Response.scanId | Should -Match $GUID
        }

        It 'gets task status on the response action' {
            Start-Sleep 2
            $Demisto.ServerEntry.command = "infocyte-get-taskstatus"
            $demisto.ContextArgs = @{ scanId = $ScanId }
            Main
            $Demisto.Results.Contents.Infocyte.Response.scanId | Should -Match $GUID
        }

        AfterAll {
            $tasks = Get-ICTask -where @{ status = "Active" }
            $tasks | where-object { $_.id } | foreach-object {
                Invoke-ICAPI -Method POST -endpoint "userTasks/$($_.id)/cancel"
            }
        }
    }

    Context "infocyte-get-scanresult" {

        It 'returns scan result metadata' {
            $Demisto.ServerEntry.command = "infocyte-get-scanresult"
            $demisto.ContextArgs = @{ scanId = $TestScanId }
            Main
            $demisto.Results.Contents.Infocyte.Scan.scanId | Should -Match $GUID
        }
    }

    Context "infocyte-get-hostscanresult" {

        It 'returns hostscan results for a single hosy' {
            $Demisto.ServerEntry.command = "infocyte-get-hostscanresult"
            $demisto.ContextArgs = @{ scanId = $TestScanId }
            Main
            $demisto.Results.Contents.Infocyte.Scan.scanId | Should -Match $GUID
        }
    }

    Context "infocyte-get-responseresult" {

        It 'returns response action result' {
            $Demisto.ServerEntry.command = "infocyte-get-responseresult"
            $demisto.ContextArgs = @{ scanId = $TestScanId2 }
            Main
            $demisto.Results.Contents.Infocyte.Response.scanId | Should -Match $GUID
        }
    }
}
#Assert-MockCalled -CommandName ReturnError -Times 1 -ParameterFilter {$Message.Contains("not valid with the schema")}