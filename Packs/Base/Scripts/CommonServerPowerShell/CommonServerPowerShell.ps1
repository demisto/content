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
