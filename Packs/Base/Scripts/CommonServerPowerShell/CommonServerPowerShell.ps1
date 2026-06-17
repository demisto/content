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

# --------------------------------------------------------------------------------
# UCP (Unified Connector Platform) exception type
# --------------------------------------------------------------------------------
# Parity port of CommonServerPython.py:10943 `UcpException(DemistoException)`.
# PowerShell requires class/enum declarations to be PARSED before first use, so
# this is declared near the top alongside the enums. It carries the same user-safe
# default message as Python; the Python base `DemistoException` has no analog in
# this harness, so we extend the built-in [System.Exception] directly.
class UcpException : System.Exception {
    static [string] $DEFAULT_MESSAGE = (
        'An authentication configuration error occurred. ' +
        'Please verify the integration instance configuration and try again. ' +
        'If the problem persists, contact Cortex support.'
    )

    UcpException() : base([UcpException]::DEFAULT_MESSAGE) {}
    UcpException([string]$message) : base($message) {}
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

    # UCP merge-target seam (parity with Python's
    # `demisto.callingContext.setdefault('params', {})` at CommonServerPython.py:14035).
    # `Params()` returns `$this.ServerEntry.params`, which may be absent. This method
    # guarantees a live, mutable 'params' dict exists ON the server entry and returns
    # that same reference, so a later `Params()` observes the interpolated values.
    hidden [System.Collections.IDictionary] _ucpParamsMergeTarget() {
        if ($null -eq $this.ServerEntry) { return @{} }
        $existing = $this.ServerEntry.params
        if ($existing -isnot [System.Collections.IDictionary]) {
            $existing = @{}
            $this.ServerEntry.params = $existing
        }
        return $existing
    }

    [Object] UnifiedConnectorMetadata () {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        $ucmRaw = $this.ServerEntry.context.UnifiedConnectorMetadata
        if ($null -eq $ucmRaw) {
            return @{}
        }
        return $ucmRaw
    }

    [Object] GetUCPCredentials ($MethodUniqueID, [bool]$FromCache = $true, $Body = $null) {
        if ( -not $this.IsIntegration ) {
            throw "Method not supported"
        }
        if ([string]::IsNullOrEmpty($MethodUniqueID)) {
            throw "[ucp] method_unique_id is required for GetUCPCredentials"
        }
        if ($FromCache) {
            $params = $this.Params()
            if ($null -ne $params -and $params.ContainsKey('ucp_credentials')) {
                $ucpCreds = $params['ucp_credentials']
                if ($ucpCreds -is [System.Collections.IDictionary] -and $ucpCreds.ContainsKey($MethodUniqueID)) {
                    return $ucpCreds[$MethodUniqueID]
                }
            }
        }
        $cmdArgs = @{ method_unique_id = $MethodUniqueID }
        if ($null -ne $Body) {
            $cmdArgs['body'] = $Body
        }
        return $this.ServerRequest(@{type = "executeCommand"; command = "getUCPCredentials"; args = $cmdArgs })
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

# ================================================================================
# UCP (Unified Connector Platform / ConnectUs) param interpolation + utilities
# --------------------------------------------------------------------------------
# 1:1 behavioral port of the Python source of truth:
#   content/Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:13680-14343
#
# DEVIATIONS forced by this host harness (CommonServerPowerShell.ps1):
#   * Merge target: Python uses demisto.callingContext['params']; here we use the
#     internal DemistoObject._ucpParamsMergeTarget() seam added above.
#   * Command accessor: this harness exposes GetCommand(), not command().
#   * UnifiedConnectorMetadata() returns @{} (never $null) when absent, and BOTH
#     it and GetUCPCredentials() THROW when not in integration mode -> all callers
#     guard via Test-UcpEnabled / try-catch so the bootstrap stays a no-op.
#   * _select_ucp_profiles is capability-only here, matching the LIVE Python
#     implementation (CommonServerPython.py:13826) and build_ucp_params usage.
# ================================================================================

# --- Module-level UCP state & constants (parity: CommonServerPython.py:13681-13714) ---

# Set $true on a successful interpolation; read by Test-ShouldUseUcpAuth.
$script:UcpAuthParamsInjected = $false

# Seconds before token expiry to consider the cache stale and re-fetch.
$script:UcpRefreshThresholdSeconds = 30

# In-process TTL cache for UCP credentials, keyed by method_unique_id.
$script:UcpCredsCache = @{}

# Command-to-capability mapping; default 'automation-and-remediation'.
$script:UcpDefaultCapability = 'automation-and-remediation'
$script:UcpCommandCapabilities = @{
    'fetch-incidents' = 'collection-and-ingestion'
    'fetch-assets'    = 'collection-and-ingestion'
}

# Canonical credential-envelope schema per profile type. Ordinal (case-sensitive)
# comparers are used to match Python dict semantics exactly. The api_key alias is
# mandatory: auth.parameter is 'api_key' but the runtime envelope stores the
# secret under 'key'. 'passthrough' intentionally has NO entry (generic lookup).
$script:UcpCanonicalFieldKeys = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
$apiKeyMap = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
$apiKeyMap['api_key'] = 'key'
$plainMap = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
$plainMap['username'] = 'username'
$plainMap['password'] = 'password'
$script:UcpCanonicalFieldKeys['api_key'] = $apiKeyMap
$script:UcpCanonicalFieldKeys['plain'] = $plainMap

# --- UCP debug logging helper (never throws; safe in bare-mock contexts) ---
# Emits through the standard demisto.debug channel so UCP diagnostics show up as
# normal debug logging (no buffering, no War Room entry, no params.logs injection).
function Write-UcpDebug([string]$Message) {
    try {
        if ($null -ne $demisto) { $demisto.debug($Message) | Out-Null }
    } catch { }
}

function Write-UcpError([string]$Message) {
    try {
        if ($null -ne $demisto) { $demisto.error($Message) | Out-Null }
    } catch { }
}

# --- C3: Set-UcpByPath (parity: _place_by_path, CommonServerPython.py:13719) ---
function Set-UcpByPath {
    # Place $Value into $Target at the dotted $Path, creating intermediate ordered
    # dicts as needed. Two paths sharing a parent fold into a single nested dict.
    # Mutates $Target in place; returns nothing meaningful.
    param(
        [System.Collections.IDictionary]$Target,
        [string]$Path,
        [object]$Value
    )
    # `-split '\.'` (NOT '.', which is a regex "any char"); drop empty segments to
    # match Python's `[seg for seg in path.split('.') if seg != '']`.
    $segments = @(($Path -split '\.') | Where-Object { $_ -ne '' })
    if ($segments.Count -eq 0) {
        Write-UcpDebug("[UCP][Set-UcpByPath] path='$Path' produced no segments; nothing placed.")
        return
    }
    $cursor = $Target
    for ($i = 0; $i -lt $segments.Count - 1; $i++) {
        $segment = $segments[$i]
        $existing = $null
        if ($cursor.Contains($segment)) { $existing = $cursor[$segment] }
        if ($existing -isnot [System.Collections.IDictionary]) {
            $existing = [ordered]@{}
            $cursor[$segment] = $existing
        }
        $cursor = $existing
    }
    $cursor[$segments[-1]] = $Value
}


# --- C4: ConvertFrom-UcpParamMap (parity: _parse_param_map, :13758) ---
function ConvertFrom-UcpParamMap {
    # Parse a UCP param_map STRING into an ORDERED array of pairs. String-only
    # parse: a dict/hashtable input stringifies and does NOT parse (parity rule).
    # Split entries on ',', then each on the FIRST ':' only; trim; drop empties.
    # Returns @() or an array of [pscustomobject]@{FieldId; Destination}.
    param([object]$ParamMap)
    $pairs = [System.Collections.ArrayList]::new()
    # Python: `if not param_map: return []` -- $null / '' / empty are falsy.
    if (-not $ParamMap) { return @() }
    $raw = [string]$ParamMap
    foreach ($entry in ($raw -split ',')) {
        $entry = $entry.Trim()
        if ([string]::IsNullOrEmpty($entry)) { continue }
        if ($entry -notmatch ':') {
            Write-UcpError("[UCP][CommonServerPowerShell.ps1] ConvertFrom-UcpParamMap: malformed entry '$entry' (no ':'); skipping.")
            continue
        }
        # `-split ':', 2` reproduces Python's `split(':', 1)` (first colon only).
        $parts = $entry -split ':', 2
        $fieldId = ($parts[0]).Trim()
        $destination = ($parts[1]).Trim()
        if ([string]::IsNullOrEmpty($fieldId) -or [string]::IsNullOrEmpty($destination)) {
            Write-UcpDebug("[UCP][ConvertFrom-UcpParamMap] empty field id or destination ('$fieldId' -> '$destination'); skipping.")
            continue
        }
        [void]$pairs.Add([pscustomobject]@{ FieldId = $fieldId; Destination = $destination })
    }
    Write-UcpDebug("[UCP][ConvertFrom-UcpParamMap] parsed $($pairs.Count) pair(s).")
    return @($pairs.ToArray())
}


# --- UCP object normalization helpers (pscustomobject <-> hashtable) ---
function ConvertTo-UcpDictionary {
    # Normalize a host-supplied value (which may arrive as [pscustomobject] from
    # ConvertFrom-Json OR as [hashtable]) into an [ordered] dictionary. Non-objects
    # are returned unchanged. Shallow (callers descend as needed).
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) { return $Value }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $dict = [ordered]@{}
        foreach ($prop in $Value.PSObject.Properties) { $dict[$prop.Name] = $prop.Value }
        return $dict
    }
    return $Value
}

function Get-UcpMember {
    # Read a member named $Key from a dict or pscustomobject; $null if absent.
    param([object]$Object, [string]$Key)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Key)) { return $Object[$Key] }
        return $null
    }
    if ($Object -is [System.Management.Automation.PSCustomObject]) {
        $prop = $Object.PSObject.Properties[$Key]
        if ($null -ne $prop) { return $prop.Value }
        return $null
    }
    return $null
}


# --- C8: Resolve-UcpCapability (parity: resolve_ucp_capability, :14120) ---
function Resolve-UcpCapability {
    # Map a command to its capability via $script:UcpCommandCapabilities, falling
    # back to the default. Deviation: uses GetCommand() (this harness has no
    # command() method). Lookup is ordinal/case-sensitive for Python parity.
    param([object]$Command)
    if ($null -eq $Command) {
        try { $Command = $demisto.GetCommand() } catch { $Command = '' }
    }
    $key = [string]$Command
    if ($script:UcpCommandCapabilities.ContainsKey($key)) {
        return $script:UcpCommandCapabilities[$key]
    }
    return $script:UcpDefaultCapability
}


# --- C5: Select-UcpProfiles (parity: _select_ucp_profiles, :13804) ---
function Select-UcpProfiles {
    # Return ALL profiles whose 'capability' equals $Capability (case-sensitive
    # -ceq, for Python `==` parity). Possibly empty. Profiles may be dicts or
    # pscustomobjects (host JSON).
    param([object]$Profiles, [string]$Capability)
    if (-not $Profiles) {
        Write-UcpDebug('[UCP][Select-UcpProfiles] no connectionProfiles in metadata.')
        return @()
    }
    $matched = [System.Collections.ArrayList]::new()
    foreach ($p in $Profiles) {
        $cap = [string](Get-UcpMember -Object $p -Key 'capability')
        if ($cap -ceq $Capability) { [void]$matched.Add($p) }
    }
    Write-UcpDebug("[UCP][Select-UcpProfiles] found $($matched.Count) profile(s) with capability '$Capability'.")
    return @($matched.ToArray())
}


# --- C6: ConvertFrom-UcpCredentials (parity: inline flatten, :13914-13929) ---
function ConvertFrom-UcpCredentials {
    # Flatten a credentials envelope into a single field dict. Look up
    # creds[creds.type]; fall back to creds when that is not a dict; then descend
    # one level into 'parameters' when present (e.g. passthrough). Returns an
    # [ordered] dict (possibly empty). Handles pscustomobject + hashtable inputs.
    param([object]$Credentials)
    $credValues = [ordered]@{}
    $credsDict = ConvertTo-UcpDictionary $Credentials
    if ($credsDict -isnot [System.Collections.IDictionary]) {
        Write-UcpDebug('[UCP][ConvertFrom-UcpCredentials] credentials did not normalize to a dict; returning empty.')
        return $credValues
    }

    $credType = Get-UcpMember -Object $credsDict -Key 'type'
    $typeData = $null
    if ($credType) { $typeData = Get-UcpMember -Object $credsDict -Key ([string]$credType) }
    $typeDataDict = ConvertTo-UcpDictionary $typeData
    if ($typeDataDict -is [System.Collections.IDictionary]) {
        $credValues = $typeDataDict
    } else {
        $credValues = $credsDict
    }
    # Descend into 'parameters' when present (passthrough wraps one level deeper).
    $innerParams = $null
    if ($credValues -is [System.Collections.IDictionary]) {
        $innerParams = Get-UcpMember -Object $credValues -Key 'parameters'
    }
    $innerDict = ConvertTo-UcpDictionary $innerParams
    if ($innerDict -is [System.Collections.IDictionary]) {
        $credValues = $innerDict
    }
    # Log field KEYS only (never values) to keep secrets out of logs.
    Write-UcpDebug("[UCP][ConvertFrom-UcpCredentials] type='$credType', flattened field keys=[$(@($credValues.Keys) -join ', ')]")
    return $credValues
}


# --- C7: Merge-UcpDeep (parity: _deep_merge_dicts, :13951) ---
function Merge-UcpDeep {
    # Recursively merge $Source into $Target IN PLACE. Recurse only when both
    # sides are dicts; otherwise incoming overwrites. Target-only keys preserved;
    # source-only keys added. Returns the SAME $Target object (identity preserved).
    param(
        [System.Collections.IDictionary]$Target,
        [System.Collections.IDictionary]$Source
    )
    # Iterate over a COPY of the keys: mutating a hashtable during its own
    # enumeration throws in PowerShell.
    foreach ($key in @($Source.Keys)) {
        $sourceValue = $Source[$key]
        $targetValue = $null
        if ($Target.Contains($key)) { $targetValue = $Target[$key] }
        if (($targetValue -is [System.Collections.IDictionary]) -and ($sourceValue -is [System.Collections.IDictionary])) {
            Merge-UcpDeep -Target $targetValue -Source $sourceValue | Out-Null
        } else {
            $Target[$key] = $sourceValue
        }
    }
    return $Target
}


# --- Profile matching building blocks (parity: :14142-14255) ---

function Get-UcpProfiles {
    # Return connectionProfiles from UCP metadata or throw [UcpException].
    $connectorInfo = $demisto.UnifiedConnectorMetadata()
    if (-not $connectorInfo) {
        Write-UcpError('[UCP][CommonServerPowerShell.ps1] Get-UcpProfiles: UnifiedConnectorMetadata() returned empty.')
        throw [UcpException]::new()
    }
    $profiles = Get-UcpMember -Object $connectorInfo -Key 'connectionProfiles'
    if (-not $profiles) {
        Write-UcpError('[UCP][CommonServerPowerShell.ps1] Get-UcpProfiles: No connection profiles found in connector metadata.')
        throw [UcpException]::new()
    }
    return $profiles
}

function Find-UcpProfileBySubCapability {
    # First profile's method_unique_id whose sub_capabilities list contains
    # $SubCapability, else $null.
    param([object]$Profiles, [string]$SubCapability)
    $matches = [System.Collections.ArrayList]::new()
    foreach ($p in $Profiles) {
        $subs = Get-UcpMember -Object $p -Key 'sub_capabilities'
        if ($null -ne $subs) {
            foreach ($s in @($subs)) {
                if ([string]$s -ceq $SubCapability) { [void]$matches.Add($p); break }
            }
        }
    }
    if ($matches.Count -eq 0) { return $null }
    if ($matches.Count -gt 1) {
        Write-UcpDebug("[UCP][CommonServerPowerShell.ps1] Find-UcpProfileBySubCapability: Multiple profiles ($($matches.Count)) match sub_capability='$SubCapability'. Using first.")
    }
    return [string](Get-UcpMember -Object $matches[0] -Key 'method_unique_id')
}

function Find-UcpProfileByCapability {
    # First profile's method_unique_id whose capability equals $Capability
    # (case-sensitive), else $null.
    param([object]$Profiles, [string]$Capability)
    $matches = [System.Collections.ArrayList]::new()
    foreach ($p in $Profiles) {
        $cap = [string](Get-UcpMember -Object $p -Key 'capability')
        if ($cap -ceq $Capability) { [void]$matches.Add($p) }
    }
    if ($matches.Count -eq 0) { return $null }
    if ($matches.Count -gt 1) {
        Write-UcpDebug("[UCP][CommonServerPowerShell.ps1] Find-UcpProfileByCapability: Multiple profiles ($($matches.Count)) match capability=`"$Capability`". Using first.")
    }
    return [string](Get-UcpMember -Object $matches[0] -Key 'method_unique_id')
}

function Get-UcpMethodUniqueId {
    # Resolution priority: 1) sub_capability, 2) capability, 3) first profile.
    param([object]$Capability, [object]$SubCapability)
    $profiles = Get-UcpProfiles

    if ($SubCapability) {
        $methodId = Find-UcpProfileBySubCapability -Profiles $profiles -SubCapability ([string]$SubCapability)
        if ($methodId) {
            Write-UcpDebug("[UCP][Get-UcpMethodUniqueId] resolved via sub_capability -> '$methodId'")
            return $methodId
        }
    }

    if (-not $Capability) { $Capability = Resolve-UcpCapability }
    $methodId = Find-UcpProfileByCapability -Profiles $profiles -Capability ([string]$Capability)
    if ($methodId) {
        Write-UcpDebug("[UCP][Get-UcpMethodUniqueId] resolved via capability='$Capability' -> '$methodId'")
        return $methodId
    }

    $first = @($profiles)[0]
    $firstId = Get-UcpMember -Object $first -Key 'method_unique_id'
    if ($null -eq $firstId) {
        Write-UcpDebug('[UCP][Get-UcpMethodUniqueId] no match and first profile has no method_unique_id; returning empty.')
        return ''
    }
    Write-UcpDebug("[UCP][Get-UcpMethodUniqueId] fell back to first profile -> '$firstId'")
    return [string]$firstId
}


# --- C10: Get-UcpExpiry (parity: _extract_ucp_expiry, :14047) ---
function Get-UcpExpiry {
    # Extract expiry as a Unix-epoch [double] from a credentials dict. Look up
    # 'expires_at' top-level first, then inside creds[creds.type]. Returns $null
    # when absent; falls back to (now + 300) on parse failure. Uses
    # [datetimeoffset] (locale-independent), NOT Get-Date.
    param([object]$Credentials)
    $creds = ConvertTo-UcpDictionary $Credentials
    if ($creds -isnot [System.Collections.IDictionary]) { return $null }
    $credType = Get-UcpMember -Object $creds -Key 'type'
    $typeData = $null
    if ($credType) { $typeData = ConvertTo-UcpDictionary (Get-UcpMember -Object $creds -Key ([string]$credType)) }
    $expiresAtStr = Get-UcpMember -Object $creds -Key 'expires_at'
    if (-not $expiresAtStr -and ($typeData -is [System.Collections.IDictionary])) {
        $expiresAtStr = Get-UcpMember -Object $typeData -Key 'expires_at'
    }
    if (-not $expiresAtStr) {
        return $null
    }
    try {
        $normalized = ([string]$expiresAtStr).Replace('Z', '+00:00')
        $dto = [System.DateTimeOffset]::Parse($normalized, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
        return [double]$dto.ToUnixTimeSeconds()
    } catch {
        Write-UcpError('[UCP][CommonServerPowerShell.ps1] Get-UcpExpiry: Failed to parse UCP credentials expiry time. Defaulting to 5 minutes from now.')
        return ([double][System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) + 300
    }
}


# --- C10: Get-UcpCredentials (parity: get_ucp_credentials, :14261) ---
function Get-UcpCredentials {
    # Fetch UCP credentials with an in-process TTL cache keyed by method_unique_id.
    # A refresh is triggered $script:UcpRefreshThresholdSeconds before expiry.
    # Deviation: passes fromCache=$false to the host (Python uses from_cache=False)
    # so the host does NOT serve its own params-based cache -- our TTL cache owns
    # freshness. method_unique_id resolves via Get-UcpMethodUniqueId when omitted.
    param([object]$MethodUniqueId, [object]$Body)
    if (-not $MethodUniqueId) { $MethodUniqueId = Get-UcpMethodUniqueId }
    $key = [string]$MethodUniqueId

    $now = [double][System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($script:UcpCredsCache.ContainsKey($key)) {
        $entry = $script:UcpCredsCache[$key]
        $expiry = $entry['expiry']
        if ($null -eq $expiry -or $now -lt ($expiry - $script:UcpRefreshThresholdSeconds)) {
            Write-UcpDebug("[UCP][Get-UcpCredentials] cache HIT (fresh) for '$key'.")
            return $entry['result']
        }
        Write-UcpDebug("[UCP][Get-UcpCredentials] cache entry STALE for '$key'; re-fetching.")
        # Stale -- fall through to re-fetch.
    }

    $creds = $demisto.GetUCPCredentials($key, $false, $Body)
    $expiry = Get-UcpExpiry -Credentials $creds
    Write-UcpDebug("[UCP][Get-UcpCredentials] fetched fresh credentials for '$key' (expiry=$expiry); caching.")
    $script:UcpCredsCache[$key] = @{ result = $creds; expiry = $expiry }
    return $creds
}


# --- C16: Clear-UcpCredentialEntry (parity: invalidate_ucp_credentials, :14310) ---
function Clear-UcpCredentialEntry {
    param([string]$MethodUniqueId)
    if ($script:UcpCredsCache.ContainsKey($MethodUniqueId)) {
        $script:UcpCredsCache.Remove($MethodUniqueId) | Out-Null
    }
    Write-UcpDebug("[UCP][CommonServerPowerShell.ps1] Invalidated cached credentials for method_unique_id=$MethodUniqueId")
}


# --- C9: Build-UcpParams (parity: build_ucp_params, :13832) ---
function Build-UcpParams {
    # Pure, side-effect-free core. metadata -> reshaped params [ordered] dict.
    # Resolve capability if not given; read connectionProfiles; select by
    # capability; per profile read metadata.xsoar.interpolation_mapping, parse,
    # fetch creds, generic-flatten, canonical-alias, Set-UcpByPath. Skip ONLY
    # $null field values ('' / 0 / $false ARE placed). Last-wins across profiles.
    param([object]$ConnectorMetadata, [object]$Capability)
    $result = [ordered]@{}
    if (-not $ConnectorMetadata) {
        Write-UcpDebug('[UCP][Build-UcpParams] ConnectorMetadata is empty; returning empty result.')
        return $result
    }

    if ($null -eq $Capability) { $Capability = Resolve-UcpCapability }

    $profiles = Get-UcpMember -Object $ConnectorMetadata -Key 'connectionProfiles'
    if (-not $profiles) { $profiles = @() }

    $selected = Select-UcpProfiles -Profiles $profiles -Capability ([string]$Capability)
    Write-UcpDebug("[UCP][Build-UcpParams] capability='$Capability', selected $(@($selected).Count) of $(@($profiles).Count) profile(s).")

    foreach ($profile in $selected) {
        $methodUniqueId = Get-UcpMember -Object $profile -Key 'method_unique_id'
        # interpolation_mapping lives at profile.metadata.xsoar.interpolation_mapping.
        $metaNode = Get-UcpMember -Object $profile -Key 'metadata'
        $xsoarNode = Get-UcpMember -Object $metaNode -Key 'xsoar'
        $interpolationMapping = Get-UcpMember -Object $xsoarNode -Key 'interpolation_mapping'

        $pairs = ConvertFrom-UcpParamMap -ParamMap $interpolationMapping
        if (@($pairs).Count -eq 0) {
            Write-UcpDebug("[UCP][Build-UcpParams] no interpolation pairs for profile '$methodUniqueId'; skipping.")
            continue
        }
        $credentials = Get-UcpCredentials -MethodUniqueId $methodUniqueId
        $credValues = ConvertFrom-UcpCredentials -Credentials $credentials

        $credsDict = ConvertTo-UcpDictionary $credentials
        $credType = $null
        if ($credsDict -is [System.Collections.IDictionary]) { $credType = Get-UcpMember -Object $credsDict -Key 'type' }

        # Canonical alias table for fixed-schema types (api_key/plain); free-form
        # (passthrough) falls back to a generic field_id lookup.
        $canonicalKeys = $null
        if ($credType -and $script:UcpCanonicalFieldKeys.ContainsKey([string]$credType)) {
            $canonicalKeys = $script:UcpCanonicalFieldKeys[[string]$credType]
        }
        foreach ($pair in $pairs) {
            $fieldId = $pair.FieldId
            $destination = $pair.Destination
            $lookupKey = $fieldId
            if ($null -ne $canonicalKeys -and $canonicalKeys.ContainsKey($fieldId)) {
                $lookupKey = $canonicalKeys[$fieldId]
            }
            $fieldValue = Get-UcpMember -Object $credValues -Key $lookupKey
            # Skip ONLY $null (parity: `if field_value is None`). '' / 0 / $false placed.
            # Log presence + type only -- NEVER the value (avoids leaking secrets).
            if ($null -eq $fieldValue) {
                Write-UcpDebug("[UCP][Build-UcpParams] profile '$methodUniqueId': missing value for field '$fieldId' (lookupKey '$lookupKey').")
                continue
            }
            Set-UcpByPath -Target $result -Path $destination -Value $fieldValue
        }
    }

    Write-UcpDebug("[UCP][Build-UcpParams] interpolated $(@($result.Keys).Count) top-level param(s) for capability='$Capability'.")
    return $result
}


# --- C11: Test-UcpEnabled (parity: is_ucp_enabled, :14083) ---
function Test-UcpEnabled {
    # $true when UnifiedConnectorMetadata() returns a non-empty descriptor.
    # Swallows all errors (e.g. method missing on the host / not in integration
    # mode -> the host method throws). Mirrors Python's try/except.
    try {
        $connectorInfo = $demisto.UnifiedConnectorMetadata()
        if ($connectorInfo) {
            # An empty hashtable @{} is the host's "absent" sentinel; treat as not enabled.
            if (($connectorInfo -is [System.Collections.IDictionary]) -and $connectorInfo.Count -eq 0) {
                return $false
            }
            return $true
        }
        return $false
    } catch {
        Write-UcpDebug('[UCP][CommonServerPowerShell.ps1] Test-UcpEnabled: UnifiedConnectorMetadata() unavailable or errored.')
        return $false
    }
}


# --- C11: Test-ShouldUseUcpAuth (parity: should_use_ucp_auth, :14107) ---
function Test-ShouldUseUcpAuth {
    # $true when UCP is enabled AND params were not already pre-injected.
    return ((Test-UcpEnabled) -and (-not $script:UcpAuthParamsInjected))
}


# --- C12: Invoke-UcpParamInterpolation (parity: interpolate_ucp_params, :13986) ---
function Invoke-UcpParamInterpolation {
    # Applier: fetch metadata (if not given) -> resolve capability -> Build-UcpParams
    # -> deep-merge into the params merge target -> set the injected flag. NEVER
    # throws (whole body wrapped). Returns [bool]: $true iff anything was merged.
    param([object]$ConnectorMetadata)
    try {
        if ($null -eq $ConnectorMetadata) {
            try {
                $ConnectorMetadata = $demisto.UnifiedConnectorMetadata()
            } catch {
                Write-UcpDebug('[UCP][Invoke-UcpParamInterpolation] UnifiedConnectorMetadata() not available; skipping.')
                return $false
            }
            # Host returns @{} (not $null) when absent -> not in UCP-land.
            if ($null -eq $ConnectorMetadata) {
                Write-UcpDebug('[UCP][Invoke-UcpParamInterpolation] ConnectorMetadata is $null; not in UCP-land.')
                return $false
            }
            if (($ConnectorMetadata -is [System.Collections.IDictionary]) -and $ConnectorMetadata.Count -eq 0) {
                Write-UcpDebug('[UCP][Invoke-UcpParamInterpolation] ConnectorMetadata is empty; not in UCP-land.')
                return $false
            }
        }

        $capability = $null
        try {
            $capability = Resolve-UcpCapability
        } catch {
            Write-UcpDebug('[UCP][Invoke-UcpParamInterpolation] could not resolve capability.')
        }

        $interpolated = Build-UcpParams -ConnectorMetadata $ConnectorMetadata -Capability $capability
        if (-not $interpolated -or @($interpolated.Keys).Count -eq 0) {
            Write-UcpDebug('[UCP][Invoke-UcpParamInterpolation] no params produced; nothing to merge.')
            return $false
        }

        $params = $demisto._ucpParamsMergeTarget()
        Merge-UcpDeep -Target $params -Source $interpolated | Out-Null
        $script:UcpAuthParamsInjected = $true
        Write-UcpDebug("[UCP][Invoke-UcpParamInterpolation] interpolated $(@($interpolated.Keys).Count) top-level param(s) for capability='$capability'.")
        return $true
    } catch {
        # Never let interpolation break the script lifecycle.
        Write-UcpError("[UCP][CommonServerPowerShell.ps1] Invoke-UcpParamInterpolation: swallowed error: $_")
        Write-UcpDebug("[UCP][Invoke-UcpParamInterpolation] exception detail: $($_ | Out-String)")
        return $false
    }
}


# --- C13: Module-tail never-throw bootstrap (parity: CommonServerPython.py:14332) ---
# Runs once after $demisto is initialized and every UCP helper is defined,
# BEFORE the integration script body executes. When not running under UCP / not
# an integration, the host methods throw and Test-UcpEnabled /
# Invoke-UcpParamInterpolation swallow it -> cheap no-op preserving legacy behavior.
try {
    if ($demisto.IsIntegration) {
        $bootstrapResult = Invoke-UcpParamInterpolation
        Write-UcpDebug("[UCP][bootstrap] interpolation result=$bootstrapResult, injected=$($script:UcpAuthParamsInjected).")
    }
} catch {
    # Import-time safety net: never let interpolation break module load.
    Write-UcpDebug("[UCP][bootstrap] swallowed error: $_")
}
