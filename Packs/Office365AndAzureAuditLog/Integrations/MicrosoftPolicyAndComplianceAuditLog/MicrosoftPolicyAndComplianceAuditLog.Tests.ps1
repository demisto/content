[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "", Justification="Known issue in pester")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidTrailingWhitespace", "", Justification="Ignore")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "", Justification="Ignore")]
Param()

$AUDIT_LOG_JSON = Get-Content "test_data/audit_log.json" -Raw | ConvertFrom-Json

BeforeAll {
    . "$PSScriptRoot/MicrosoftPolicyAndComplianceAuditLog.ps1"
    Mock Connect-ExchangeOnline
    Mock Disconnect-ExchangeOnline
}

$temp = Get-Content "test_data/audit_log.json" -Raw | ConvertFrom-Json
Describe "SearchAuditLogCommand" {
    It "Correct params" {
        Mock Search-UnifiedAuditLog {return $AUDIT_LOG_JSON} -Verifiable
        Mock Get-Date {return "Wednesday, July 12, 2023 9:58:19 AM"}
        $client = [ExchangeOnlinePowershellV3Client]::new("url", "app_id", "organization", "aGVsbG8=", "password")
        ($human_readable, $entry_context, $raw_response) = SearchAuditLogCommand $client
        ($human_readable, $entry_context, $raw_response) | Should -Be ($temp, $null, $null)
    }
}