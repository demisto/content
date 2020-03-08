. $PSScriptRoot\CommonServerPowerShell.ps1

Write-Host "starting test ..."

Describe 'Check-DemistoServerRequest' {
    It 'Check that a call to demisto DemistoServerRequest mock works. Should always return an empty response' {
        global:DemistoServerRequest @{} | Should -BeNullOrEmpty         
        $demisto.GetAllSupportedCommands() | Should -BeNullOrEmpty
    }
}

Describe 'Check-UtilityFunctions' {
    It "ArgToList" {
        $r = argToList "a,b,c,2"
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"
        $r.Length | Should -Be 4
        $r = argToList '["a","b","c",2]'
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"
        $r[3] | Should -Be 2
        $r.Length | Should -Be 4
        $r = argToList @("a","b","c",2)
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"
        $r[3] | Should -Be 2
        $r.Length | Should -Be 4
        $r = argToList "a"
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"        
        $r.Length | Should -Be 1
    }

    It "ReturnError simple" {
        $msg = "this is an error"
        $r = ReturnError $msg
        $r.ContentsFormat | Should -Be "text"
        $r.Type | Should -Be 4
        $r.Contents | Should -Be $msg
        $r.EntryContext | Should -BeNullOrEmpty
    }
    Context "Check log function" {
        Mock DemistoServerLog {}

        It "ReturnError complex" {    
            # simulate an error
            Test-JSON "{badjson}" -ErrorAction SilentlyContinue -ErrorVariable err
            $msg = "this is a complex error"
            $r = ReturnError $msg $err @{Failed = $true}
            $r.Contents | Should -Be $msg
            $r.EntryContext.Failed | Should -BeTrue
            Assert-MockCalled -CommandName DemistoServerLog -Times 2 -ParameterFilter {$level -eq "error"}
            Assert-MockCalled -CommandName DemistoServerLog -Times 1 -ParameterFilter {$msg.Contains("Test-JSON : Cannot parse the JSON")}
        }
    }
}
