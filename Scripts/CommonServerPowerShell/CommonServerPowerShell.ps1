# Silence Progress STDOUT (e.g. long http request download progress)
$progressPreference = 'silentlyContinue'

enum ServerLogLevel {
    debug
    info
    error
}

# Demist Object Class for communicating with the Demisto Server
class DemistoObject {
    hidden [hashtable] $ServerEntry
    hidden [bool] $IsDebug
    hidden [bool] $IsIntegration
    hidden [hashtable] $ContextArgs

    DemistoObject ([hashtable]$context) {
        $this.ServerEntry = $context
        $this.ContextArgs = $context.args
        $this.IsDebug = $context.IsDebug
        if ($this.IsDebug) {
            $this.ContextArgs.Remove("debug-mode")
        }
        $this.IsIntegration = $context.integration
    }

    [hashtable] Args () {
        return $this.ContextArgs
    }

    [hashtable] Params () {
        return $this.ServerEntry.params
    }

    [string] GetCommand () {
        return $this.ServerEntry.command
    }

    [hashtable] Investigation () {
        return $this.ServerEntry.context.Inv
    }

    [hashtable] GetContext () {
        return $this.ServerEntry.context.ExecutionContext
    }

    Log ($Entry) {
        $Command = @{ type = "entryLog"; args = @{ message = $Entry } } | ConvertTo-Json -Compress -Depth 20
        $global:DemistoOutputStream.WriteLine($Command)
    }

    Results ($EntryRaw) {
        $Entry = $this.ConvertToEntry($EntryRaw)
        $Command = @{ type = "result"; results = $Entry } | ConvertTo-Json -Compress -Depth 20
        $global:DemistoOutputStream.WriteLine($Command)
    }

    [array] ConvertToEntry ($EntryRaw) {
        $Entry = ""
        $EntryType = $EntryRaw.GetType().name
        switch ($EntryType) {
            "Hashtable" {
                if ($EntryRaw.ContainsKey("Contents") -and $EntryRaw.ContainsKey("ContentsFormat")) {
                    $Entry = @($EntryRaw)
                }
                else {
                    $Entry = @(@{Type = 1; Contents = $EntryRaw; ContentsFormat = "json" })
                }
                ; Break 
            }
            "Object[]" {
                foreach ($EntryObj in $EntryRaw) {
                    if (!$Entry) {
                        $Entry = $this.ConvertToEntry($EntryObj)
                    }
                    else {
                        $Entry += $this.ConvertToEntry($EntryObj)[0]
                    }
                }
                ; Break
            }
            "PSCustomObject" {
                if ($EntryRaw.Contents -and $EntryRaw.ContentsFormat) {
                    $Entry = @($EntryRaw)
                }
                else {
                    $Entry = @(@{Type = 1; Contents = $EntryRaw; ContentsFormat = "json" })
                }
                ; Break 
            }
            default {
                $EntryContent = [string]$EntryRaw
                $Entry = @(@{Type = 1; Contents = $EntryContent; ContentsFormat = "text" })
                ; Break 
            }
        }
        return $entry
    }

    [array] ServerRequest ($Cmd) {
        return global:DemistoServerRequest $cmd
    }

    [array] DT ($Value, $Name) {
        return $this.ServerRequest(@{type = "dt"; name = $Name; value = $Value }).result
    }

    [array] GetFilePath ($ID) {
        return $this.ServerRequest(@{type = "getFileByEntryID"; command = "getFilePath"; args = @{id = $ID } })
    }

    [array] DemistoUrls () {
        return $this.ServerRequest(@{type = "demistoUrls" })
    }

    [array] DemistoVersion () {
        return $this.ServerRequest(@{type = "demistoVersion" })
    }

    [string] UniqueFile () {
        return New-Guid
    }

    [hashtable] ParentEntry () {
        return $this.ServerEntry.context.ParentEntry
    }

    [string] GetLicenseID () {
        return $this.ServerRequest(@{type = "executeCommand"; command = "getLicenseID"; args = @{ } }).id
    }

    Info ($Log) {
        global:DemistoServerLog ([ServerLogLevel]::info) $Log
    }

    Debug ($Log) {
        global:DemistoServerLog ([ServerLogLevel]::debug) $Log
    }

    Error ($Log) {
        global:DemistoServerLog ([ServerLogLevel]::error) $Log
    }

    [array] GetIncidents () {
        return $this.ServerEntry.context.Incidents
    }

    [array] Incidents () {
        return $this.GetIncidents()
    }

    [hashtable] Incident () {
        return $this.GetIncidents()[0]
    }

    # Script Functions

    [array] ExecuteCommand ($Command, $CmdArgs) {
        if ( $this.IsIntegration ) {
            throw "Method not supported"
        }
        return $this.ServerRequest(@{type = "executeCommand"; command = $Command; args = $CmdArgs })
    }

    [array] Execute ($Module, $Command, $CmdArgs) {
        if ( $this.IsIntegration ) {
            throw "Method not supported"
        }
        return $this.ServerRequest(@{type = "execute"; module = $Module; command = $Command; args = $CmdArgs })
    }

    [array] GetAllSupportedCommands () {
        if ( $this.IsIntegration ) {
            throw "Method not supported"
        }
        return $this.ServerRequest(@{type = "getAllModulesSupportedCmds" })
    }

    SetContext ($Name, $Value) {
        if ( $this.IsIntegration ) {
            throw "Method not supported"
        }
        $this.ServerRequest(@{type = "setContext"; name = $Name; value = $Value })
    }

    [Object[]] GetModules () {
        if ( $this.IsIntegration ) {
            throw "Method not supported"
        }
        return $this.ServerRequest(@{type = "getAllModules" })
    }

    # Integration Functions

    [string] IntegrationInstance () {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        return $this.ServerEntry.context.IntegrationInstance
    }

    [array] Incidents ($Incidents) {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        $Incidents = $Incidents | ConvertTo-Json -Depth 6
        return $this.Results(@{Type = 1; Contents = $Incidents; ContentsFormat = "json" })
    }

    [array] Credentials ($Credentials) {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        $Credentials = $Credentials | ConvertTo-Json -Depth 6
        return $this.Results(@{Type = 1; Contents = $Credentials; ContentsFormat = "json" })
    }

    [Object[]] GetLastRun () {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        return $this.ServerRequest(@{type = "executeCommand"; command = "getLastRun"; args = @{ } })
    }

    SetLastRun ($Value) {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        $this.ServerRequest(@{type = "executeCommand"; command = "setLastRun"; args = @{ value = $Value } })
    }

    [Object[]] GetIntegrationContext () {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        return $this.ServerRequest(@{type = "executeCommand"; command = "getIntegrationContext"; args = @{ } })
    }

    SetIntegrationContext ($Value) {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        $this.ServerRequest(@{type = "executeCommand"; command = "setIntegrationContext"; args = @{ value = $Value } })
    }
}

$InnerContext = $global:InnerContext | ConvertFrom-Json -AsHashtable
[DemistoObject]$demisto = [DemistoObject]::New($InnerContext)
Remove-Variable InnerContext
function global:Write-Host($UserInput) { $demisto.Log($UserInput) | Out-Null }
function global:Write-Output($UserInput) { $demisto.Log($UserInput) | Out-Null }

function tableToMarkdown {
    <#
.DESCRIPTION

Converts a demisto table in JSON form to a Markdown table

.PARAMETER name (required)

The name of the table

.PARAMETER t (required)

The JSON table - List of dictionaries with the same keys or a single dictionary

.PARAMATER headers

A list of headers to be presented in the output table (by order).
If string will be passed then table will have single header. Default will include all available headers.

.PARAMATER headerTransform

A function that formats the original data headers

.PARAMATER removeNull

Remove empty columns from the table.

.PARAMATER metadata

Metadata about the table contents
#>

}
