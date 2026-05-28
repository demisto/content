. $PSScriptRoot\demistomock.ps1

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "", Scope = "", Justification = "Use of globals set by the Demisto Server")]

# Silence Progress STDOUT (e.g. long http request download progress)
$progressPreference = 'silentlyContinue'

enum ServerLogLevel {
    debug
    info
    error
}

enum EntryTypes {
    note = 1
    downloadAgent = 2
    file = 3
    error = 4
    pinned = 5
    userManagement = 6
    image = 7
    playgroundError = 8
    entryInfoFile = 9
    warning = 11
    map = 15
    widget = 17
}

enum EntryFormats {
    html
    table
    json
    text
    dbotResponse
    markdown
}

<#
.DESCRIPTION
Analyze a PS dict-like object recursively and return any paths that reference to a parent object.

This function employs recursion to traverse through the object hierarchy, keeping track of visited objects to detect
circular references. The function stops recursion when a specified maximum depth or the end of the hierarchy is reached.
If a circular reference is found, it returns the path leading to it.

.PARAMETER obj
The object to analyze.

.PARAMETER visited
A dict containing the parent objects to check against. Should be left empty outside the recursion.

.PARAMETER path
The path to the object being analyzed. Should be left empty outside the recursion.

.PARAMETER depth
The amount of recursive calls to the function up to the current call. Should be 1 outside the recursion.

.PARAMETER maxDepth
The maximum amount of recursive function calls, defaults to 20.

.OUTPUTS
A list of strings of the self referencing paths inside the provided object.
#>
function Get-SelfReferencingPaths($obj, $visited = @{}, $path = @(), $depth = 1, $maxDepth = 20) {
    if ($depth -gt $maxDepth) {
        # Stop recursion when max depth is reached
        return @()
    }

    $selfReferencingPaths = @()
    # If the object has properties (has children that can point back to it), and is not null.
    # Get-Member function will return an error if the member type doesn't exist but here we are setting
    # SilentlyContinue instead.
    if (($obj | Get-Member -MemberType Properties -ErrorAction SilentlyContinue)) {
        if ($visited.ContainsKey($obj)) {
            # Circular reference detected
            if (-not ($path -like "*SyncRoot*")) {
                # SyncRoot is allowed to be self-referencing
                return $path
            }
            return @()
        }

        # Mark the object as visited
        $visited[$obj] = $true

        foreach ($property in $obj.PSObject.Properties) {
            $propertyValue = $property.Value
            $propertyPath = "$($path).$($property.Name)"
            if (-not $path) {
                $propertyPath = "$($property.Name)"
            }

            # Recursively process complex object
            $nestedPaths = Get-SelfReferencingPaths -obj $propertyValue -visited $visited -path $propertyPath -depth ($depth + 1) -maxDepth $maxDepth
            $selfReferencingPaths += $nestedPaths
        }

        # Remove the object from visited list after getting all its children
        $visited.Remove($obj)
    }

    return $selfReferencingPaths
}

<#
.DESCRIPTION
Remove any circular references from a PS dict-like object.

This function gets the circular referencing paths  of the object using Get-SelfReferencingPaths,
It then transverses through the object properties until the circular referencing parent node is reached.
It removes the circular referencing node from the parent node and transverses back to update each parent node with the
change.

.PARAMETER obj
The object to remove self references from.

.OUTPUTS
The updated object, containing no self references.
#>
function Remove-SelfReferences($obj) {

    try {
        # Get self referencing paths
        $selfReferencingPaths = Get-SelfReferencingPaths -obj $obj

        foreach ($path in $selfReferencingPaths) {
            $properties = $path -split '\.'
            $propertyName = $properties[-1]
            $parentPath = $properties[0..($properties.Count - 2)]

            $parentObject = $obj
            $parentObjects = @()
            # Get object at the end of path
            foreach ($prop in $parentPath) {
                $parentObjects += $parentObject
                $parentObject = $parentObject.($prop)
            }

            # Update the object
            $currentObject = $parentObject | Select-Object -ExcludeProperty $propertyName

            # Update back all its parents
            for ($i = $parentObjects.Count - 1; $i -ge 0; $i--) {
                $parentObject = $parentObjects[$i]
                $propName = $properties[$i]
                $parentObject.$propName = $currentObject
                $currentObject = $parentObject
            }

        }

        return $obj

    } catch {
        # Return to default behaviour if errors were encountered.
        return $obj
    }
}

# Demist Object Class for communicating with the Demisto Server
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'use of global:DemistoServerRequest')]
class DemistoObject {
    hidden [hashtable] $ServerEntry
    hidden [bool] $IsDebug
    hidden [bool] $IsIntegration
    hidden [hashtable] $ContextArgs

    DemistoObject () {
        if($global:InnerContext.GetType().Name -eq 'String') {
            $context = $global:InnerContext | ConvertFrom-Json -AsHashtable
        }
        else {
            $context = $global:InnerContext
        }
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
        DemistoServerLog ([ServerLogLevel]::info) $Log
    }

    Debug ($Log) {
        DemistoServerLog ([ServerLogLevel]::debug) $Log  # disable-secrets-detection
    }

    Error ($Log) {
        DemistoServerLog ([ServerLogLevel]::error) $Log
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
        $Incidents = $Incidents | ConvertTo-Json -Depth 6 -AsArray
        return $this.Results(@{Type = 1; Contents = $Incidents; ContentsFormat = "json" })
    }

    [array] Credentials ($Crds) {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        $Credentials = $Crds | ConvertTo-Json -Depth 6
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
        $integration_context = $this.ServerRequest(@{type = "executeCommand"; command = "getIntegrationContext"; args = @{ } })
        # When Demisto Version is greater equal then "6.0.0".  integration_context will be under "context" attribute.
        if (DemistoVersionGreaterEqualThen -version "6.0.0") {
            $integration_context = $integration_context.context
        }

        return $integration_context
    }

    SetIntegrationContext ($Value) {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        $this.ServerRequest(@{type = "executeCommand"; command = "setIntegrationContext"; args = @{
            value = $Value
            version =  @{
                "version" = -1
                "sequenceNumber" = -1
                "primaryTerm" = -1
            } } })
    }

    [Object[]] GetIntegrationContextVersioned ($Refresh) {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        $integration_context = $this.ServerRequest(@{type = "executeCommand"; command = "getIntegrationContext"; args = @{ refresh = $Refresh } })

        return $integration_context
    }

    SetIntegrationContextVersioned ($Value, $Version, $Sync) {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        $this.ServerRequest(@{type = "executeCommand"; command = "setIntegrationContext"; args = @{value = $Value; version = $Version; sync = $Sync} })
    }

    # UCP (Unified Connector Platform) Functions

    <#
    .DESCRIPTION
    Returns the unified connector metadata for UCP-enabled integrations.

    When running in UCP mode, the server populates the response with connector
    information including connection profiles, connector ID, handler ID, and
    instance ID. Returns an empty result when not in UCP mode.

    .OUTPUTS
    Hashtable representing the connector metadata, or an empty hashtable when
    not running in UCP mode.
    #>
    [hashtable] UnifiedConnectorMetadata () {
        $res = $this.ServerRequest(@{type = "unifiedConnectorMetadata" })
        # ServerRequest may wrap a single object in a 1-element array; unwrap before
        # we type-check, so downstream code always sees a single object.
        if ($res -is [System.Array] -and $res.Count -eq 1) {
            $res = $res[0]
        }
        if ($null -eq $res) {
            return @{}
        }
        # Server may return a PSCustomObject (after JSON parsing) - normalize to hashtable.
        if ($res -is [hashtable]) {
            return $res
        }
        if ($res -is [System.Collections.IDictionary]) {
            $h = @{}
            foreach ($k in $res.Keys) { $h[$k] = $res[$k] }
            return $h
        }
        if ($res -is [PSCustomObject]) {
            $h = @{}
            foreach ($p in $res.PSObject.Properties) { $h[$p.Name] = $p.Value }
            return $h
        }
        return @{}
    }

    <#
    .DESCRIPTION
    Fetches UCP credentials for the given method_unique_id.

    In production, the server returns a credential hashtable containing
    type-specific sub-dicts (oauth2, api_key, plain) with tokens/keys.

    .PARAMETER method_unique_id
    The method_unique_id from a connection profile.

    .PARAMETER from_cache
    Whether to use server-side cached credentials. Defaults to $true.

    .OUTPUTS
    Hashtable representing the credentials, or $null when not available.
    #>
    [object] GetUCPCredentials ([string]$method_unique_id, [bool]$from_cache) {
        $res = $this.ServerRequest(@{type = "getUCPCredentials"; args = @{method_unique_id = $method_unique_id; from_cache = $from_cache } })
        # ServerRequest may wrap a single credentials object in a 1-element array;
        # unwrap so downstream credential-flattening sees a single object.
        if ($res -is [System.Array] -and $res.Count -eq 1) {
            $res = $res[0]
        }
        return $res
    }

    [object] GetUCPCredentials ([string]$method_unique_id) {
        return $this.GetUCPCredentials($method_unique_id, $true)
    }
}

[DemistoObject]$demisto = [DemistoObject]::New()

function global:Write-HostToLog($UserInput) { $demisto.Log($UserInput) | Out-Null }
# we override Write-Host with a function which writes to the demisto.Log.
# Incase there is need to undo this Alias, the integration/script can run the following command
# Remove-Item 'Alias:Write-Host' -Force
Set-Alias -Name 'Write-Host' -Value 'Write-HostToLog' -Scope Global

# -----------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------

<#
.DESCRIPTION
Converts a string representation of args to a list

.PARAMETER Arg
The argument to convert

.PARAMETER Seperator
The seperator to use (default ',')

.OUTPUTS
Object[]. Returns an array of the arguments
#>
function ArgToList($Arg, [string]$Seperator = ",") {
    if (! $Arg) {
        $r = @()
    }
    elseif ($Arg.GetType().IsArray) {
        $r = $Arg
    }
    elseif ($Arg[0] -eq "[" -and $Arg[-1] -eq "]") {
        # json string
        $r = $Arg | ConvertFrom-Json -AsHashtable
    }
    else {
        $r = $Arg.Split($Seperator)
    }
    # we want to return an array and avoid one-at-a-time processing
    # see: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_return?view=powershell-6#return-values-and-the-pipeline
    return @(, $r)
}

<#
.DESCRIPTION
Return an Error entry back to the Server

.PARAMETER Message
Messsage to display in the error entry

.PARAMETER Err
Error to log (optional)

.PARAMETER Outputs
The outputs that will be returned to playbook/investigation context (optional)

.OUTPUTS
The error entry object returned to the server
#>
function ReturnError([string]$Message, $Err, [hashtable]$Outputs) {
    $demisto.Error("$Message")
    if ($Err) {
        $errMsg = $Err | Out-String
        $demisto.Error($errMsg)
    }
    $entry = @{Type = [EntryTypes]::error; ContentsFormat = [EntryFormats]::text.ToString(); Contents = $message; EntryContext = $Outputs }
    $demisto.Results($entry) | Out-Null
    return $entry
}

<#
.DESCRIPTION
This function wraps the $demisto.results(), makes the usage of returning results to the user more intuitively.

.PARAMETER ReadableOutput
Markdown string that will be presented in the warroom, should be human readable

.PARAMETER Outputs
The outputs that will be returned to playbook/investigation context (optional)

.PARAMETER RawResponse
If not provided then will be equal to outputs. usually is the original
raw response from the 3rd party service (optional)

.PARAMETER RemoveSelfRefs
If true, will remove self references in RawResponse and Outputs objects before conversion to json.

.OUTPUTS
The entry object returned to the server
#>
function ReturnOutputs([string]$ReadableOutput, [object]$Outputs, [object]$RawResponse,
                        [Parameter(Mandatory=$false)]
                        [bool]$RemoveSelfRefs = $true) {

    if ($RemoveSelfRefs) {
        # Remove circular references before converting to json.
        $RawResponse = Remove-SelfReferences $RawResponse
        $Outputs = Remove-SelfReferences $Outputs
    }

    $entry = @{
        Type           = [EntryTypes]::note;
        ContentsFormat = [EntryFormats]::json.ToString();
        HumanReadable  = $ReadableOutput;
        Contents       = $RawResponse;
        EntryContext   = $Outputs
    }
    # Return 'readable_output' only if needed
    if ($ReadableOutput -and -not $outputs -and -not $RawResponse) {
        $entry.Contents = $ReadableOutput
        $entry.ContentsFormat = [EntryFormats]::text.ToString();
    }
    elseif ($Outputs -and -not $RawResponse) {
        # if RawResponse was not provided but outputs were provided then set Contents as outputs
        $entry.Contents = $Outputs
    }
    $demisto.Results($entry) | Out-Null
    return $entry
}

<#
.DESCRIPTION
This function wraps the $demisto.results() for polling commands.
It formats the polling result entry to support XSOAR's polling mechanism,
including timeout, interval, and tracking of remaining items.
.PARAMETER ReadableOutput
Markdown string that will be presented in the warroom. Should be human-readable.
.PARAMETER Outputs
The outputs that will be returned to the playbook/investigation context (optional).
.PARAMETER RawResponse
If not provided, this will be set to the value of Outputs. 
Usually represents the original raw response from the 3rd party service (optional).
.PARAMETER CommandName
The name of the polling command that should be called again for the next polling iteration.
.PARAMETER PollingArgs
Arguments that should be passed to the polling command on the next polling iteration.
.PARAMETER RemoveSelfRefs
If true, removes circular/self references from RawResponse and Outputs before JSON conversion.
.OUTPUTS
The polling entry object returned to the server
#>
function ReturnPollingOutputs(
    [string]$ReadableOutput,
    [object]$Outputs,
    [object]$RawResponse,
    [string]$CommandName,
    [object]$PollingArgs,
    [Parameter(Mandatory = $false)]
    [bool]$RemoveSelfRefs = $true,
    [Parameter(Mandatory = $false)]
    [string]$NextRun = "30",
    [Parameter(Mandatory = $false)]
    [string]$Timeout = "600"
) {
    if ($RemoveSelfRefs) {
        $RawResponse = Remove-SelfReferences $RawResponse
        $Outputs = Remove-SelfReferences $Outputs
    }

    $entry = @{
        Type           = [EntryTypes]::note;
        ContentsFormat = [EntryFormats]::json.ToString();
        HumanReadable  = $ReadableOutput;
        Contents       = $RawResponse;
        EntryContext   = $Outputs;
        PollingCommand = $CommandName;
        NextRun        = $NextRun;
        PollingArgs     = $PollingArgs
        Timeout        = $Timeout;
        PollingItemsRemaining = 0;
    }
    # Return 'readable_output' only if needed
    if ($ReadableOutput -and -not $outputs -and -not $RawResponse) {
        $entry.Contents = $ReadableOutput
        $entry.ContentsFormat = [EntryFormats]::text.ToString();
    }
    elseif ($Outputs -and -not $RawResponse) {
        # if RawResponse was not provided but outputs were provided then set Contents as outputs
        $entry.Contents = $Outputs
    }
    $demisto.Results($entry) | Out-Null
    return $entry
}

<#
.DESCRIPTION
This function Gets a string and escape all special characters in it so that it can be in correct markdown format

.PARAMETER data
The string that needs to be escaped

.OUTPUTS
A string in which all special characters are escaped
#>
Function stringEscapeMD(){
    [OutputType([string])]
    Param (
        [Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$data
    )
    begin{
        $markdown_chars = @('\', '`','*', '_', '{', '}', '[',']', '(', ')', '#', '+','-', '|', '!')
    }
    process {
        $result = $data.Replace("`r`n", "<br>").Replace("`r", "<br>").Replace("`n", "<br>")
        foreach ($char in $markdown_chars){
            $result = $result.Replace("$char", "\$char")
        }
        $result
    }
}
<#
.DESCRIPTION
This function Converts a hashtable object into an ordered dictionary object

.PARAMETER hashTable
The hash-table that needs to be converted

.OUTPUTS
Ordered dict with the same keys and values as the hashTable's
#>
Function ConvertTo-OrderedDict {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
Param (
        [Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true)]
        [AllowEmptyCollection()]
        [HashTable]$hashTable
    )
Process {
    $OrderedDictionary = [ordered]@{ }
    foreach ($Element in ($hashTable.GetEnumerator() | Sort-Object -Property Key))
    {
        $OrderedDictionary[$Element.Key] = $Element.Value
    }
    return $OrderedDictionary
}
}
<#
.DESCRIPTION
This function Gets a list of PSObjects and convert it to a markdown table

.PARAMETER collection
The list of PSObjects that will should be converted to markdown format

.PARAMETER name
The name of the markdown table. when given this name will be the title of the table

.OUTPUTS
The markdown table string representation
#>
Function TableToMarkdown{
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true)]
        [AllowEmptyCollection()]
        [Object]$collection,

        [Parameter(Mandatory = $false,Position = 1)]
        [String]$name
    )
    Begin {
        # Initializing $result
        $result = ''
        if ($name) {
            $result += "### $name`n"
        }
        # Initializing $items
        $items = @()
        # Initializing $headers
        $headers = @()
    }

    Process {
        # proccessing items and headers
        ForEach ($item in $collection)
        {
            if ($item -Is [HashTable])
            {
                # Need to convert hashtables to ordered dicts so that the keys/values will be in the same order
                $item = $item | ConvertTo-OrderedDict
            }
            elseif ($item -Is [PsCustomObject]){
            $newItem = @{}
            $item.PSObject.Properties | ForEach-Object { $newItem[$_.Name] = $_.Value }
            $item = $newItem | ConvertTo-OrderedDict
        }
            $items += $item
        }
    }
End {
    if ($items)
        {
            if ($items[0] -is [System.Collections.IDictionary]){
                $headers = $items[0].keys
            }
            else
            {
                $headers = $item[0].PSObject.Properties| ForEach-Object {$_.Name}
            }
            # Writing the headers line
            $result += '| ' + ($headers -join ' | ')
            $result += "`n"

            # Writing the separator line
            $separator = @()
            ForEach ($key in $headers)
            {
                $separator += '---'
            }
            $result += '| ' + ($separator -join ' | ')
            $result += "`n"

            # Writing the values
            ForEach ($item in $items)
            {
                $values = @()
                if ($items[0] -is [System.Collections.IDictionary])
                {
                    $raw_values = $item.values
                }
                else
                {
                    $raw_values = $item[0].PSObject.Properties| ForEach-Object { $_.Value }
                }
                foreach ($raw_value in $raw_values)
                {
                    if ($null -ne $raw_value)
                    {   try{
                            <# PWSH Type Code of numbers are 5 to 15. So we will handle them with ToString
                            and the rest are Json Serializble #>
                            $typeValue = $raw_value.getTypeCode().value__
                            $is_number = ($typeValue -ge 5 -and $typeValue -le 15)
                        } catch { $is_number = $false}

                        if ($raw_value -is [string] -or $is_number)
                        {
                            $value = $raw_value.ToString()
                        }
                        else
                        {
                            $value = $raw_value | ConvertTo-Json -Compress -Depth 5
                        }
                    }
                    else
                    {
                        $value = ""
                    }
                    $values += $value | stringEscapeMD
                }
                $result += '| ' + ($values -join ' | ')
                $result += "`n"
            }
        }
        else
        {
            $result += "**No entries.**`n"
        }
        return $result
    }
}
Set-Alias -Name ConvertTo-Markdown -Value TableToMarkdown

function ConvertTo-Boolean
{
  param
  (
    [Parameter(Mandatory=$false)][string] $value
  )
  switch ($value)
  {
    "y" { return $true; }
    "yes" { return $true; }
    "true" { return $true; }
    "t" { return $true; }
    1 { return $true; }
    "n" { return $false; }
    "no" { return $false; }
    "false" { return $false; }
    "f" { return $false; }
    0 { return $false; }
  }
}

<#
.DESCRIPTION
Creates a file from the given string data.

.PARAMETER file_name
The file name to use for the file in then entry result

.PARAMETER data
String data to use for the file

.PARAMETER is_file_info
If true will return an entry of  type: [EntryTypes]::entryInfoFile

.OUTPUTS
Entry object to return to the server. Use $demisto.Results(obj) to actually send the entry to the server.
#>
function FileResult([string]$file_name, [string]$data, [bool]$is_file_info) {
    $file_type = [EntryTypes]::file
    if ($is_file_info) {
        $file_type = [EntryTypes]::entryInfoFile
    }
    $temp = $demisto.UniqueFile()
    Out-File -FilePath "$($demisto.Investigation().id)_$temp" -Encoding "utf8" -InputObject $data

    return @{
        "Contents" = ''
        "ContentsFormat" = [EntryFormats]::text.ToString()
        "Type" = $file_type
        "File" = $file_name
        "FileID" = $temp
    }
}

function DemistoVersionGreaterEqualThen([string]$version) {
    $demisto_version = $demisto.DemistoVersion().version
    $version_pattern = "\d{1,2}\.\d{1,2}\.\d{1,2}"
    $demisto_version = (Select-string -Pattern $version_pattern -InputObject $demisto_version).Matches[0].Value
    $version = (Select-string -Pattern $version_pattern -InputObject $version).Matches[0].Value

    return [version]::Parse($demisto_version) -ge  [version]::Parse($version)
}

function ParseDateRange{
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $date_str
    )
    $now = $date = Get-Date
    $number, $unit_name = $date_str.Split()
    try{
        $number = -([int]$number)
    } catch [System.Management.Automation.RuntimeException]{
        throw "No number given in '$date_str'"
    }
    if ($null -eq $unit_name){
        throw "Time unit not given in '$date_str'"
    }
    if (!($unit_name.GetType() -eq [String])) {
        throw "Too many arguemnts in '$date_str'"
    }
    if ($unit_name.Contains("minute")){
        $date = $date.AddMinutes($number)
    } elseif ($unit_name.Contains("hour")) {
        $date = $date.AddHours($number)
    } elseif ($unit_name.Contains("day")){
        $date = $date.AddDays($number)
    } elseif ($unit_name.Contains("week")) {
        $date = $date.AddDays($number * 7)
    } elseif ($unit_name.Contains("month")) {
        $date = $date.AddMonths($number)
    } elseif ($unit_name.Contains("year")) {
        $date = $date.AddYears($number)
    } else {
        throw "Could not process time unit '$unit_name'. Available are: minute, hour, day, week, month, year."
    }
    return $date, $now
    <#
    .DESCRIPTION
    Gets a string represents a date range ("3 day", "2 years" etc) and return the time on the past according to
    the date range.

    .PARAMETER date_str
     a date string in a human readable format as "3 days", "5 years".
     Available units: minute, hour, day, week, month, year.

    .EXAMPLE
    ParseDateRange("3 days") (current date it 04/01/21)
    Date(01/01/21)
    #>
}

function GetIntegrationContext {
    [CmdletBinding()]
    param (
        [bool]$refresh = $true,
        [bool]$withVersion = $false
    )
    if (DemistoVersionGreaterEqualThen -version "6.0.0") {
        $integration_context = $demisto.getIntegrationContextVersioned($refresh)

        if ($withVersion -eq $true) {
            return $integration_context
        }
        return $integration_context.context

    }
    return $demisto.GetIntegrationContext()
}

function SetIntegrationContext ([object]$context, $version = -1, [bool]$sync = $true) {
    if (DemistoVersionGreaterEqualThen -version "6.0.0") {
        return $demisto.setIntegrationContextVersioned($context, $version, $sync)
    }
    return $demisto.SetIntegrationContext($context)
}

# -----------------------------------------------------------------------
# UCP (Unified Connector Platform) Auth Helpers
# Mirrors the JS UCP functions in CommonServer.js and Python UCP functions
# in CommonServerPython.py.
# -----------------------------------------------------------------------

# Module-level state (script scope) - mirrors JS `_UCP_*` globals.
$script:UCP_AUTH_PARAMS_INJECTED = $false
$script:UCP_REFRESH_THRESHOLD_SECONDS = 30
$script:UCP_DEFAULT_CAPABILITY = 'automation-and-remediation'
$script:UCP_COMMAND_CAPABILITIES = @{
    'fetch-incidents'  = 'collection-and-ingestion'
    'fetch-assets'     = 'collection-and-ingestion'
    'fetch-indicators' = 'collection-and-ingestion'
    'fetch-samples'    = 'collection-and-ingestion'
}

# Client-side TTL cache (mirrors JS `_ucpCredentialsCache`).
$script:UcpCredentialsCache = @{}

<#
.DESCRIPTION
Extract the expiry epoch (seconds) from a UCP credentials response.

Looks for `expires_at` (ISO-8601 string) at the top level, then inside the
type-specific sub-dict (e.g. `creds.oauth2.expires_at`).

If the timestamp cannot be parsed, falls back to 5 minutes from now.

.PARAMETER creds
Raw credentials object returned from $demisto.GetUCPCredentials().

.OUTPUTS
[Nullable[double]] Unix epoch (seconds) or $null for static (never-expiring) credentials.
#>
function script:Extract-UcpExpiry($creds) {
    if ($null -eq $creds) { return $null }
    $credType = ''
    if ($creds -is [System.Collections.IDictionary] -and $creds.Contains('type')) {
        $credType = "$($creds['type'])"
    } elseif ($creds.PSObject -and $creds.PSObject.Properties['type']) {
        $credType = "$($creds.type)"
    }

    $typeData = $null
    if ($credType) {
        if ($creds -is [System.Collections.IDictionary] -and $creds.Contains($credType)) {
            $typeData = $creds[$credType]
        } elseif ($creds.PSObject -and $creds.PSObject.Properties[$credType]) {
            $typeData = $creds.$credType
        }
    }

    $expiresAtStr = $null
    if ($creds -is [System.Collections.IDictionary] -and $creds.Contains('expires_at')) {
        $expiresAtStr = "$($creds['expires_at'])"
    } elseif ($creds.PSObject -and $creds.PSObject.Properties['expires_at']) {
        $expiresAtStr = "$($creds.expires_at)"
    }

    if (-not $expiresAtStr -and $null -ne $typeData) {
        if ($typeData -is [System.Collections.IDictionary] -and $typeData.Contains('expires_at')) {
            $expiresAtStr = "$($typeData['expires_at'])"
        } elseif ($typeData.PSObject -and $typeData.PSObject.Properties['expires_at']) {
            $expiresAtStr = "$($typeData.expires_at)"
        }
    }

    if ([string]::IsNullOrEmpty($expiresAtStr)) {
        return $null
    }

    try {
        $dt = [DateTime]::Parse($expiresAtStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
        $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        return ($dt - $epoch).TotalSeconds
    } catch {
        $demisto.Debug("[UCP][CommonServerPowerShell.ps1] Error parsing UCP expiry timestamp '$expiresAtStr'. Using 5 minutes as fallback: $_")
        $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        return ([DateTime]::UtcNow - $epoch).TotalSeconds + 300
    }
}

<#
.DESCRIPTION
Invalidate a specific entry in the UCP credentials cache.

Used before retrying after a 401 to force a fresh fetch on the next call to
Get-UcpCredentials.

.PARAMETER methodUniqueId
The method_unique_id to invalidate.
#>
function Invalidate-UcpCredentialsCache([string]$methodUniqueId) {
    if ($script:UcpCredentialsCache.Contains($methodUniqueId)) {
        $script:UcpCredentialsCache.Remove($methodUniqueId)
    }
    $demisto.Debug("[UCP][CommonServerPowerShell.ps1] Invalidated cached credentials for methodUniqueId=$methodUniqueId")
}

<#
.DESCRIPTION
Check whether this integration instance is running in UCP (ConnectUs) mode.

UCP mode is active when $demisto.UnifiedConnectorMetadata() returns a non-empty
connector descriptor containing at least one connection profile.

Prefer Test-ShouldUseUcpAuth instead.

.OUTPUTS
[bool] True if UCP metadata is present, False otherwise.
#>
function Test-UcpEnabled {
    [OutputType([bool])]
    Param()
    try {
        $info = $demisto.UnifiedConnectorMetadata()
        if ($null -eq $info) { return $false }

        $profiles = $null
        if ($info -is [System.Collections.IDictionary] -and $info.Contains('connectionProfiles')) {
            $profiles = $info['connectionProfiles']
        } elseif ($info.PSObject -and $info.PSObject.Properties['connectionProfiles']) {
            $profiles = $info.connectionProfiles
        }
        if ($null -eq $profiles) { return $false }
        return (@($profiles).Count -gt 0)
    } catch {
        return $false
    }
}

<#
.DESCRIPTION
Determine whether UCP credentials should be injected per-request.

Returns True when UCP is enabled AND credentials have not already been injected
into integration params by the server (the
`$script:UCP_AUTH_PARAMS_INJECTED` flag).

.OUTPUTS
[bool] True if per-request UCP credential injection should be used.
#>
function Test-ShouldUseUcpAuth {
    [OutputType([bool])]
    Param()
    return ((Test-UcpEnabled) -and (-not $script:UCP_AUTH_PARAMS_INJECTED))
}

<#
.DESCRIPTION
Resolve the UCP capability for the current (or given) command.

Uses `$script:UCP_COMMAND_CAPABILITIES` for known commands, falling back to
`$script:UCP_DEFAULT_CAPABILITY` ('automation-and-remediation').

.PARAMETER Command
The command name. Defaults to the current command ($demisto.GetCommand()).

.OUTPUTS
[string] The capability string.
#>
function Resolve-UcpCapability {
    [OutputType([string])]
    Param([string]$Command)
    if ([string]::IsNullOrEmpty($Command)) {
        try { $Command = $demisto.GetCommand() } catch { $Command = '' }
    }
    if ($script:UCP_COMMAND_CAPABILITIES.Contains($Command)) {
        return $script:UCP_COMMAND_CAPABILITIES[$Command]
    }
    return $script:UCP_DEFAULT_CAPABILITY
}

<#
.DESCRIPTION
Return the list of connection profiles from UCP metadata.

Internal helper used by Get-UcpMethodUniqueId.

.OUTPUTS
[object[]] Array of profile objects.

.THROWS
Throws when UCP metadata is missing or no connection profiles are defined.
#>
function script:Get-UcpProfiles {
    $info = $demisto.UnifiedConnectorMetadata()
    $demisto.Debug("[UCP][CommonServerPowerShell.ps1] UCP Metadata: $($info | ConvertTo-Json -Compress -Depth 10)")
    if ($null -eq $info) {
        throw "[Unified Connector] Connector metadata is not available. Please verify that this integration instance is configured to use a Unified Connector."
    }

    $profiles = $null
    if ($info -is [System.Collections.IDictionary] -and $info.Contains('connectionProfiles')) {
        $profiles = $info['connectionProfiles']
    } elseif ($info.PSObject -and $info.PSObject.Properties['connectionProfiles']) {
        $profiles = $info.connectionProfiles
    }
    $profiles = @($profiles)
    if ($profiles.Count -eq 0) {
        $demisto.Debug("[UCP][CommonServerPowerShell.ps1] No connection profiles found in connector metadata.")
        throw "[Unified Connector] No authentication profiles are configured for this connector. Please check the connector setup in your Cortex platform and ensure at least one authentication profile is defined."
    }
    return $profiles
}

# Internal helper - look up a property on a hashtable or PSCustomObject.
function script:Get-UcpProp($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary] -and $obj.Contains($name)) {
        return $obj[$name]
    }
    if ($obj.PSObject -and $obj.PSObject.Properties[$name]) {
        return $obj.$name
    }
    return $null
}

<#
.DESCRIPTION
Find the method_unique_id of the first profile matching a sub_capability.

If multiple profiles match, logs a debug message and returns the first.
#>
function script:Find-UcpProfileBySubCapability($profiles, [string]$subCapability) {
    $matches = @()
    foreach ($p in $profiles) {
        $subs = @(Get-UcpProp $p 'sub_capabilities')
        if ($subs -contains $subCapability) {
            $matches += (Get-UcpProp $p 'method_unique_id')
        }
    }
    if ($matches.Count -gt 1) {
        $demisto.Debug("[UCP][CommonServerPowerShell.ps1] Multiple profiles match sub_capability=$subCapability : [$($matches -join ', ')]. Using first match: $($matches[0])")
    }
    if ($matches.Count -gt 0) { return $matches[0] }
    return $null
}

<#
.DESCRIPTION
Find the method_unique_id of the first profile matching a capability.

If multiple profiles match, logs a debug message and returns the first.
#>
function script:Find-UcpProfileByCapability($profiles, [string]$capability) {
    $matches = @()
    foreach ($p in $profiles) {
        if ((Get-UcpProp $p 'capability') -eq $capability) {
            $matches += (Get-UcpProp $p 'method_unique_id')
        }
    }
    if ($matches.Count -gt 1) {
        $demisto.Debug("[UCP][CommonServerPowerShell.ps1] Multiple profiles match capability=$capability : [$($matches -join ', ')]. Using first match: $($matches[0])")
    }
    if ($matches.Count -gt 0) { return $matches[0] }
    return $null
}

<#
.DESCRIPTION
Resolve which connection profile's method_unique_id to use.

Resolution priority:
  1. Match by sub_capability (via Find-UcpProfileBySubCapability).
  2. Match by capability (via Find-UcpProfileByCapability).
  3. Fall back to the first profile in the list.

.PARAMETER Capability
Override capability. Defaults to Resolve-UcpCapability.

.PARAMETER SubCapability
Optional sub-capability for finer matching.

.OUTPUTS
[string] The method_unique_id.
#>
function Get-UcpMethodUniqueId {
    [OutputType([string])]
    Param(
        [string]$Capability,
        [string]$SubCapability
    )
    $profiles = script:Get-UcpProfiles

    if (-not [string]::IsNullOrEmpty($SubCapability)) {
        $bySubCap = script:Find-UcpProfileBySubCapability $profiles $SubCapability
        if ($bySubCap) { return $bySubCap }
    }

    if ([string]::IsNullOrEmpty($Capability)) {
        $Capability = Resolve-UcpCapability
    }
    $byCap = script:Find-UcpProfileByCapability $profiles $Capability
    if ($byCap) { return $byCap }

    $fallback = Get-UcpProp $profiles[0] 'method_unique_id'
    $demisto.Debug("[UCP][CommonServerPowerShell.ps1] Get-UcpMethodUniqueId: no match for capability=$Capability, falling back to first profile -> $fallback")
    return $fallback
}

<#
.DESCRIPTION
Enumerate the property names of a hashtable or PSCustomObject as a string[].

Internal helper used by Flatten-UcpCredentials to copy any "extra" fields a
UCP connection profile may carry beyond the standard credential fields (e.g.
certificate, app_id, organization, url for plain profiles used by Exchange
Online PowerShell V3).
#>
function script:Get-UcpPropNames($obj) {
    if ($null -eq $obj) { return @() }
    if ($obj -is [System.Collections.IDictionary]) {
        return @($obj.Keys | ForEach-Object { "$_" })
    }
    if ($obj.PSObject -and $obj.PSObject.Properties) {
        return @($obj.PSObject.Properties | ForEach-Object { $_.Name })
    }
    return @()
}

<#
.DESCRIPTION
Copy any "extra" fields from a UCP credentials object into the flattened
result hashtable.

The standard Flatten-UcpCredentials output for each credential type only
carries the well-known fields (oauth2 -> access_token/token_type/expires_at;
api_key -> key; plain -> username/password). Some connection profiles
(notably the EWS Extension Online PowerShell V3 / ps_demo connector) bind
additional fields like 'certificate', 'app_id', 'organization', 'url' to a
'plain' profile. Without preserving these, integrations that read them from
$demisto.Params() will get empty values and fail at runtime (e.g. X509
certificate ctor throws "Array may not be empty or null").

This helper copies any field on $creds or $creds.<type> that is NOT already
in $result and NOT one of the reserved meta keys.

.PARAMETER result
The flattened result hashtable to mutate.

.PARAMETER creds
The original UCP credentials object (top-level).

.PARAMETER nested
The type-specific nested sub-object (e.g. $creds.plain). May be $null.
#>
function script:Copy-UcpExtraFields([hashtable]$result, $creds, $nested) {
    # Reserved keys we do not propagate verbatim - they are either already
    # set by the caller or are UCP-internal metadata.
    $reserved = @('type', 'oauth2', 'oauth2_client_credentials',
                  'oauth2_authorization_code', 'api_key', 'plain',
                  'expires_at', 'access_token', 'token_type', 'key',
                  'username', 'password')

    foreach ($source in @($nested, $creds)) {
        if ($null -eq $source) { continue }
        foreach ($name in (Get-UcpPropNames $source)) {
            if ($reserved -contains $name) { continue }
            if ($result.Contains($name)) { continue }
            $value = Get-UcpProp $source $name
            # Skip null values but allow empty strings - the integration may
            # legitimately receive an empty optional field.
            if ($null -eq $value) { continue }
            $result[$name] = $value
        }
    }
}

<#
.DESCRIPTION
Flatten a nested UCP credentials response into a flat hashtable.

$demisto.GetUCPCredentials() returns nested structures like
`@{oauth2 = @{access_token = '...'; ...}; type = 'oauth2'}`. This function
flattens them to `@{type = 'oauth2'; access_token = '...'; ...}`.

In addition to the well-known fields per credential type, any extra fields
present on the credentials object (or its type-specific sub-object) are
preserved on the flattened result. This allows connection profiles to carry
integration-specific fields (e.g. certificate, app_id, organization, url for
the EWS Extension Online PowerShell V3 connector) without requiring
integration-side UCP awareness.

After flattening, validates that the essential credential field is non-empty.
Throws when empty (fail-fast) - matching the JS/Python behavior.

.OUTPUTS
[hashtable] Flattened credentials.
#>
function script:Flatten-UcpCredentials($creds) {
    if ($null -eq $creds) { return $null }
    $credType = "$(Get-UcpProp $creds 'type')"

    if ($credType -in @('oauth2', 'oauth2_client_credentials', 'oauth2_authorization_code')) {
        $data = Get-UcpProp $creds 'oauth2'
        if ($null -eq $data) { $data = $creds }
        $result = @{
            type         = $credType
            access_token = "$(Get-UcpProp $data 'access_token')"
            token_type   = "$(Get-UcpProp $data 'token_type')"
            expires_at   = "$(Get-UcpProp $data 'expires_at')"
        }
        if ([string]::IsNullOrEmpty($result.access_token)) {
            # try to fall back to top level
            $topLevel = "$(Get-UcpProp $creds 'access_token')"
            if (-not [string]::IsNullOrEmpty($topLevel)) {
                $result.access_token = $topLevel
            }
        }
        if ([string]::IsNullOrEmpty($result.token_type)) { $result.token_type = 'Bearer' }
        if ([string]::IsNullOrEmpty($result.access_token)) {
            $demisto.Error("[UCP][CommonServerPowerShell.ps1] Flatten-UcpCredentials: empty access_token for type=$credType")
            throw "[UCP] Authentication failed - the UCP response returned empty credentials. Please verify the authentication profile is correctly configured and the credentials are valid."
        }
        script:Copy-UcpExtraFields $result $creds $data
        return $result
    }

    if ($credType -eq 'api_key') {
        $data = Get-UcpProp $creds 'api_key'
        if ($null -eq $data) { $data = $creds }
        $key = "$(Get-UcpProp $data 'key')"
        if ([string]::IsNullOrEmpty($key)) {
            $key = "$(Get-UcpProp $creds 'key')"
        }
        if ([string]::IsNullOrEmpty($key)) {
            $demisto.Error("[UCP][CommonServerPowerShell.ps1] Flatten-UcpCredentials: empty key for type=$credType")
            throw "[UCP] Authentication failed - the UCP response returned empty credentials. Please verify the authentication profile is correctly configured and the credentials are valid."
        }
        $result = @{ type = $credType; key = $key }
        script:Copy-UcpExtraFields $result $creds $data
        return $result
    }

    if ($credType -eq 'plain') {
        $data = Get-UcpProp $creds 'plain'
        if ($null -eq $data) { $data = $creds }
        $result = @{
            type     = $credType
            username = "$(Get-UcpProp $data 'username')"
            password = "$(Get-UcpProp $data 'password')"
        }
        script:Copy-UcpExtraFields $result $creds $data
        return $result
    }

    return $creds
}

<#
.DESCRIPTION
Get UCP credentials for the current command.

Uses capability resolution to find the right profile, fetches credentials from
the server, and returns a flattened credentials hashtable. Results are cached
client-side with a TTL derived from the response's `expires_at` field; a
refresh is triggered $script:UCP_REFRESH_THRESHOLD_SECONDS before expiry.

Use Invalidate-UcpCredentialsCache to force a fresh fetch on the next call
(e.g. after an authentication error).

.PARAMETER Capability
Override capability.

.PARAMETER SubCapability
Override sub-capability for finer matching.

.OUTPUTS
[hashtable] Flattened credentials, or $null if not in UCP mode.

  For oauth2: @{type='oauth2'; access_token='...'; token_type='Bearer'; expires_at='...'}
  For api_key: @{type='api_key'; key='...'}
  For plain:   @{type='plain'; username='...'; password='...'}
#>
function Get-UcpCredentials {
    [OutputType([hashtable])]
    Param(
        [string]$Capability,
        [string]$SubCapability
    )
    if (-not (Test-UcpEnabled)) {
        return $null
    }

    $methodId = Get-UcpMethodUniqueId -Capability $Capability -SubCapability $SubCapability

    # Check client-side TTL cache.
    if ($script:UcpCredentialsCache.Contains($methodId)) {
        $cached = $script:UcpCredentialsCache[$methodId]
        $expiry = $cached['expiry']
        if ($null -eq $expiry) {
            # Static credentials - never expire.
            return $cached['result']
        }
        $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        $now = ([DateTime]::UtcNow - $epoch).TotalSeconds
        if ($now -lt ($expiry - $script:UCP_REFRESH_THRESHOLD_SECONDS)) {
            return $cached['result']
        }
    }

    try {
        $demisto.Debug("[UCP][CommonServerPowerShell.ps1] Get-UcpCredentials: fetching fresh credentials for method_unique_id=$methodId")
        $creds = $demisto.GetUCPCredentials($methodId, $false)
        if ($null -eq $creds) {
            $demisto.Debug("[UCP][CommonServerPowerShell.ps1] Get-UcpCredentials: $demisto.GetUCPCredentials() returned `$null.")
            return $null
        }

        $flatCreds = script:Flatten-UcpCredentials $creds

        # Store in client-side cache with TTL.
        $expiry = script:Extract-UcpExpiry $creds
        $script:UcpCredentialsCache[$methodId] = @{ result = $flatCreds; expiry = $expiry }

        return $flatCreds
    } catch {
        $demisto.Error("[UCP][CommonServerPowerShell.ps1] Get-UcpCredentials: FAILED for method_unique_id=$methodId : $_")
        throw "[UCP] Failed to retrieve authentication credentials. Please verify the configuration and ensure the authentication profile is valid."
    }
}

# camelCase aliases so PowerShell integrations can call the same names used by
# the JS/Python UCP helpers (e.g. isUcpEnabled, getUcpCredentials).
Set-Alias -Name isUcpEnabled                -Value Test-UcpEnabled
Set-Alias -Name shouldUseUcpAuth            -Value Test-ShouldUseUcpAuth
Set-Alias -Name resolveUcpCapability        -Value Resolve-UcpCapability
Set-Alias -Name getUcpMethodUniqueId        -Value Get-UcpMethodUniqueId
Set-Alias -Name getUcpCredentials           -Value Get-UcpCredentials
Set-Alias -Name invalidateUcpCredentialsCache -Value Invalidate-UcpCredentialsCache
