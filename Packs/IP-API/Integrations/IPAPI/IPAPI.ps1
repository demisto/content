. $PSScriptRoot\CommonServerPowerShell.ps1
Function ConvertTo-Markdown {
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [PSObject[]]$InputObject
    )

    Begin {
        $items = @()
        $columns = @{}
    }

    Process {
        ForEach($item in $InputObject) {
            $items += $item

            $item.PSObject.Properties | %{
                if($_.Value -ne $null){
                    if(-not $columns.ContainsKey($_.Name) -or $columns[$_.Name] -lt $_.Value.ToString().Length) {
                        $columns[$_.Name] = $_.Value.ToString().Length
                    }
                }
            }
        }
    }

    End {
        ForEach($key in $($columns.Keys)) {
            $columns[$key] = [Math]::Max($columns[$key], $key.Length)
        }

        $header = @()
        ForEach($key in $columns.Keys) {
            $header += ('{0,-' + $columns[$key] + '}') -f $key
        }
        $header -join ' | '

        $separator = @()
        ForEach($key in $columns.Keys) {
            $separator += '-' * $columns[$key]
        }
        $separator -join ' | '

        ForEach($item in $items) {
            $values = @()
            ForEach($key in $columns.Keys) {
                $values += ('{0,-' + $columns[$key] + '}') -f $item.($key)
            }
            $values -join ' | '
        }
    }
}

if ($demisto.Params().https) {
    $global:BASEURL = "https://pro.ip-api.com/json/"
} else {
    $global:BASEURL = "http://ip-api.com/json/"
}
$global:FIELDS = $demisto.Params().fields
$ip = $demisto.Args().ip
$demisto.Info("Current URL is: " + $global:BASEURL)

$global:BASECARD = @"
IP-API
======

Results from IP-API are placed into the context under the IPAPI.response node

"@

function Ip ()
{
    if ($demisto.Params().https) {
        $ApiEndPoint = $ip + "?fields=" + $global:FIELDS + "&key=" + $demisto.Params().apikey
    } else {
        $ApiEndPoint = $ip + "?fields=" + $global:FIELDS
    }
    $URI = $global:BASEURL + $ApiEndPoint
    $response = Invoke-WebRequest -Uri $URI
    $responseJSON = ConvertFrom-JSON $response
    $headers = $response.Headers
    $StatusCode = $response.StatusCode
    if ($StatusCode -eq 200) {
        $Context = @{
            IPAPI = @{
                BaseUri = $global:BASEURL;
                response = $responseJSON;
                Headers = $headers
            }
        }
        $result_as_markdown = ConvertTo-Markdown($responseJSON)
        $Result = @{
            Type = 1;
            ContentsFormat = "json";
            Contents = $responseJSON;
            EntryContext = $Context;
            ReadableContentsFormat = "markdown";
            HumanReadable = $global:BASECARD + $result_as_markdown
        }
        return $Result
    } else {
        $demisto.Error($StatusCode + " when calling IP-API")
    }
}

$demisto.Info("Current command is: " + $demisto.GetCommand())

if ($demisto.GetCommand() -eq 'test-module')
{
    if ($demisto.Params().https) {
        $ApiEndPoint = "?key=" + $demisto.Params().apikey
    } else {
        $ApiEndPoint = ""
    }
    $URI = $global:BASEURL + $ApiEndPoint
    $response = Invoke-WebRequest -Uri $URI
    $StatusCode = $response.StatusCode
    if ($StatusCode -eq 200) {
        $demisto.Results('ok')
    } else {
        $demisto.Results('error')
    }
}
if ($demisto.GetCommand() -eq 'ip')
{
    $Ip = Ip
    $demisto.Results($Ip)
}
