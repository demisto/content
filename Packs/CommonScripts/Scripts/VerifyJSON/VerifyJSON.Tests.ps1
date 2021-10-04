BeforeAll {
    . $PSScriptRoot\VerifyJSON.ps1
}

Describe 'VerifJSON' {
    Context "Valid Json" {
        BeforeAll {
            Mock ReturnOutputs {}
        }        
        It 'Check Valid Json passes' {
            $demisto.ContextArgs = @{json = '{"test": "this"}' }
            Main
            Assert-MockCalled -CommandName ReturnOutputs -Times 1
        }
    }

    Context "InValid Json" {
        BeforeAll {
            Mock ReturnError {}
        }        
        It 'Check InValid Json fails' {
            $demisto.ContextArgs = @{json = '{"test": this"}' }
            Main
            Assert-MockCalled -CommandName ReturnError -Times 1 -ParameterFilter {$Message.Contains("Cannot parse the JSON")}
        }
    }

    Context "Schema Validation" {
        BeforeAll {
            Mock ReturnError {}
        }
        
        It 'Check InValid Json schema fails' {
            $schema = @'
{
    "definitions": {},
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "http://example.com/root.json",
    "type": "object",
    "title": "The Root Schema",
    "required": [
    "name",
    "age"
    ],
    "properties": {
    "name": {
        "$id": "#/properties/name",
        "type": "string",
        "title": "The Name Schema",
        "default": "",
        "examples": [
        "Ashley"
        ],
        "pattern": "^(.*)$"
    },
    "age": {
        "$id": "#/properties/age",
        "type": "integer",
        "title": "The Age Schema",
        "default": 0,
        "examples": [
        25
        ]
    }
    }
}
'@
            $demisto.ContextArgs = @{json = '{"name": "Ashley", "age": "25"}'; schema = $schema}
            Main
            Assert-MockCalled -CommandName ReturnError -Times 1 -ParameterFilter {$Message.Contains("not valid with the schema")}
        }
    }
}
