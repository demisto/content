. $PSScriptRoot\Infocyte.ps1

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

}