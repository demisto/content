# Install-Module -Name SelfSignedCertificate -AllowPrerelease -Force

function CreateCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$OutputPath,
        [Parameter(Mandatory)]
        [SecureString]$Password,
        [Parameter(Mandatory)]
        [int]$Days,

        [String]$Country,
        [String]$StateOrProvince,
        [String]$FriendlyName
    )
    $cmd_args = @{
        "OutCertPath" = $OutputPath
        "NotAfter" = (Get-Date).AddDays($Days)
        "Password" = $Password
        "Country" = $Country
        "StateOrProvince" = $StateOrProvince
        "FriendlyName" = $FriendlyName
    }
    @($cmd_args.keys) | % {
    if (-not $cmd_args[$_]) { $cmd_args.Remove($_) }
    }
    New-SelfSignedCertificate @cmd_args
}

function Main(){
    $pfx_path = "certificate.pfx"
    $public_key_cert_path = "publickey.cer"
    $dargs = $demisto.Args()
    $plain_pass = $dargs.password
    $password = (ConvertTo-SecureString -String $plain_pass -AsPlainText -Force)
    try
    {
        CreateCertificate -OutputPath $pfx_path -Password $password -Days $dargs.days -FriendlyName $dargs.friendly_name -Country $dargs.country -StateOrProvince $dargs.state_or_province
        openssl pkcs12 -in $pfx_path -out $public_key_cert_path -nokeys -clcerts -password pass:$plain_pass
        $File = [System.IO.File]::ReadAllBytes($pfx_path);
        # returns the base64 string
        $base_64_encoded = [System.Convert]::ToBase64String($File);

        $b64_name = "certificateBase64.txt"

        $unique = $demisto.UniqueFile()
        $b64_path = $demisto.Investigation().id + "_" + $unique
        [System.IO.File]::WriteAllText($b64_path, $base_64_encoded)
        $demisto.Results(
                @{
                    "Contents" = ''
                    "ContentsFormat" = [EntryFormats]::text.ToString()
                    "Type" = 3
                    "File" = $b64_name
                    "FileID" = $unique
                }
        )

        $unique = $demisto.UniqueFile()

        $public_key_content = [System.IO.File]::ReadAllText($public_key_cert_path)
        $public_key_temp_path = $demisto.Investigation().id + "_" + $unique
        [System.IO.File]::WriteAllText($public_key_temp_path, $public_key_content)

        $demisto.Results(
                @{
                    "Contents" = ''
                    "ContentsFormat" = [EntryFormats]::text.ToString()
                    "Type" = 3
                    "File" = $public_key_cert_path
                    "FileID" = $unique
                }
        )

        $pfx_content = [System.IO.File]::ReadAllBytes($pfx_path)
        $unique = $demisto.UniqueFile()
        $pfx_content_temp_path = $demisto.Investigation().id + "_" + $unique
        [System.IO.File]::WriteAllBytes($pfx_content_temp_path, $pfx_content)

        $demisto.Results(
                @{
                    "Contents" = ''
                    "ContentsFormat" = [EntryFormats]::text.ToString()
                    "Type" = 3
                    "File" = $pfx_path
                    "FileID" = $unique
                }
        )
    }finally{
        rm $pfx_path
    }
}

if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT $Test) {
    Main
}