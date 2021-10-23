Import-Module SelfSignedCertificate

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

        [String]$FriendlyName,
        [String]$Country,
        [String]$StateOrProvince
    )
    $cmd_args = @{
        "OutCertPath" = $OutputPath
        "NotAfter" = (Get-Date).AddDays($Days)
        "Password" = $Password
    }
    if (![string]::IsNullOrEmpty($FriendlyName)){
        $cmd_args.FriendlyName = $FriendlyName
    }
    if (![string]::IsNullOrEmpty($Country)){
        $cmd_args.Country = $Country
    }
    if (![string]::IsNullOrEmpty($StateOrProvince)){
        $cmd_args.StateOrProvince = $StateOrProvince
    }

    New-SelfSignedCertificate @cmd_args -WarningAction:SilentlyContinue > $null
}

function Main()
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
    param()
    $pfx_path = "certificate.pfx"
    $b64_path = "certificateBase64.txt"
    $public_key_cert_path = "publickey.cer"
    $dargs = $demisto.Args()
    $plain_pass = $dargs.password
    $password = (ConvertTo-SecureString -String $plain_pass -AsPlainText -Force)
    try
    {
        CreateCertificate -OutputPath $pfx_path -Password $password -Days $dargs.days -FriendlyName $dargs.friendly_name -Country $dargs.country -StateOrProvince $dargs.state_or_province
        openssl pkcs12 -in $pfx_path -out $public_key_cert_path -nokeys -clcerts -password pass:$plain_pass | Out-Null
        $File = [System.IO.File]::ReadAllBytes($pfx_path);
        # returns the base64 string
        $base_64_encoded = [System.Convert]::ToBase64String($File);

        $unique = $demisto.UniqueFile()
        $b64_temp_path = $demisto.Investigation().id + "_" + $unique
        [System.IO.File]::WriteAllText($b64_temp_path, $base_64_encoded)

        $demisto.Results(
                @{
                    "Contents" = ''
                    "ContentsFormat" = [EntryFormats]::text.ToString()
                    "Type" = 3
                    "File" = $b64_path
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
        $context = @{
            "Certificate" = @{
                "PrivateKey" = $pfx_path
                "PublicKey" = $public_key_cert_path
                "PrivateKeyBase64" = $b64_path
            }
        }
        $readable_output = TableToMarkdown $context.Certificate "Use those certificates to connect to the desired service."
        ReturnOutputs $readable_output $context $null | Out-Null
    }
    finally
    {
        Remove-Item -Path $pfx_path, $public_key_cert_path | Out-Null
    }
}

if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT$Test)
{
    Main
}