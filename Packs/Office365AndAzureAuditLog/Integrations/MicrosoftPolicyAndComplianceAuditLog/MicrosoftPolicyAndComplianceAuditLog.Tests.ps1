[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "", Justification="Known issue in pester")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidTrailingWhitespace", "", Justification="Ignore")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "", Justification="Ignore")]
Param()

BeforeAll {
    . "$PSScriptRoot/MicrosoftPolicyAndComplianceAuditLog.ps1"
}
. "$PSScriptRoot/MicrosoftPolicyAndComplianceAuditLog.ps1"  # temporary
class MockClient : ExchangeOnlinePowershellV3Client {
    CreateSession() {}
    DisconnectSession() {}
}

Mock Search-UnifiedAuditLog {return Get-Content "test_data/audit_log.json" -Raw | ConvertFrom-Json} -Verifiable

$temp = Get-Content "test_data/audit_log.json" -Raw | ConvertFrom-Json
Describe "SearchAuditLogCommand" {
    It "Correct params" {
        $client = MockClient "url" "app_id" "organization" "aGVsbG8=" "password"
        ($human_readable, $entry_context, $raw_response) = SearchAuditLogCommand $client
        ($human_readable, $entry_context, $raw_response) | Should -Be ($temp, $null, $null)
    }
}