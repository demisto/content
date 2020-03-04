. $PSScriptRoot\CommonServerPowerShell.ps1

Write-Host "starting test ..."

Describe 'Check-DemistoServerRequest' {
    It 'Check that a call to demisto DemistoServerRequest mock works. Should always return an empty response' {
        global:DemistoServerRequest(@{}) | Should -BeNullOrEmpty         
        $demisto.GetAllSupportedCommands() | Should -BeNullOrEmpty
    }
}

Describe 'Check-UtilityFunctions' {
    It "argToList" {
        $r = argToList("a,b,c,2")
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"
        $r.Length | Should -Be 4
        $r = argToList('["a","b","c",2]')
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"
        $r[3] | Should -Be 2
        $r.Length | Should -Be 4
        $r = argToList(@("a","b","c",2))
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"
        $r[3] | Should -Be 2
        $r.Length | Should -Be 4
        $r = argToList("a")
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"        
        $r.Length | Should -Be 1
    }
}
