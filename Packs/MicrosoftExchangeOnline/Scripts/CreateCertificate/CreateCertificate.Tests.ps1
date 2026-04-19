Describe "CreateCertificate - Write-Host alias fix (XSUP-67362)" {

    BeforeEach {
        # Simulate what CommonServerPowerShell does at runtime:
        # Define Write-HostToLog and alias Write-Host to it.
        function global:Write-HostToLog($UserInput) { }
        Set-Alias -Name 'Write-Host' -Value 'Write-HostToLog' -Scope Global
    }

    AfterEach {
        # Cleanup: restore native Write-Host
        Remove-Item 'Alias:Write-Host' -Force -ErrorAction SilentlyContinue
        Remove-Item 'Function:global:Write-HostToLog' -Force -ErrorAction SilentlyContinue
    }

    It "CreateCertificate.ps1 removes the Write-Host alias on load" {
        # Verify that after sourcing CreateCertificate.ps1, the alias is gone.
        # The alias is currently set (from BeforeEach).
        $aliasBefore = Get-Alias -Name 'Write-Host' -ErrorAction SilentlyContinue
        $aliasBefore | Should -Not -BeNullOrEmpty
        $aliasBefore.Definition | Should -Be 'Write-HostToLog'

        # Source the script (with $Test flag to prevent Main from running)
        $Test = $true
        . $PSScriptRoot\CreateCertificate.ps1

        # After sourcing, the alias should be removed
        $aliasAfter = Get-Alias -Name 'Write-Host' -ErrorAction SilentlyContinue
        if ($null -ne $aliasAfter) {
            # If an alias still exists, it should NOT point to Write-HostToLog
            $aliasAfter.Definition | Should -Not -Be 'Write-HostToLog'
        }

        # Write-Host should now resolve to the native cmdlet
        $cmd = Get-Command Write-Host -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
    }
}
