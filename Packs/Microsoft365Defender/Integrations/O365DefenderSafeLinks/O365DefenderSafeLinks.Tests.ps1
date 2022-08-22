BeforeAll {
    . "$PSScriptRoot\O365DefenderSafeLinks.ps1"
    . $PSScriptRoot\CommonServerPowerShell.ps1
}

Describe 'Helper functions test' {
    Context "CreateContextForReport" {
                                   
        It 'Single result- Not array case' {
            $response = @{field="data";RunspaceId="1"}
            $context = CreateContextForReport $response

            $context.Data | Should -Be $response
            $context.ReportId | Should -Be "1"

        }

        It 'Mulitple results - Array case' {
            $response = @(@{field="data_1";RunspaceId="1"};@{field="data_2";RunspaceId="1"})
            $context = CreateContextForReport $response

            $context.Data | Should -Be $response
            $context.ReportId | Should -Be "1"

        }
    }

}
    