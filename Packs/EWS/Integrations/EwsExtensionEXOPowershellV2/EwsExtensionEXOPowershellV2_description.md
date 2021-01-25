## BaseIntegration Help

### App authentication
To use this integration you should connect an application with a certificate.
In order to create the app and certificate, you should use the [following guide](https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps).

After acquiring the .pfx certificate, you should encode it to base64 to use in the integration.
you can use this command:
```powershell
$pfx_path = "<path-to-file>.pfx"
$b65_path  "<output-path>.txt"
$bytes = [System.IO.File]::ReadAllBytes($pfx_path)
$base_64_encoded = [System.Convert]::ToBase64String($bytes);
[System.IO.File]::WriteAllText($b64_path, $base_64_encoded)
```
Take the .txt contents and paste it to the to Credential parameter.