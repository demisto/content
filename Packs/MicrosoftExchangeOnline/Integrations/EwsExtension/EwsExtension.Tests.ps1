Describe "PowerShell version" {
    It "is 7.1.4" {
        $expectedVersion = [Version] "7.1.4"
        $actualVersion = $PSVersionTable.PSVersion

        # Assert that the actual version matches the expected version
        $actualVersion | Should -Be $expectedVersion
    }
}
