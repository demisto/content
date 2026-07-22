. $PSScriptRoot\CommonServerPowerShell.ps1

# remove progress messages such as [oo  ] - used to hide archiving operations
$global:ProgressPreference = 'SilentlyContinue'

$script:INTEGRATION_NAME = "PowerShell Remoting"
$script:COMMAND_PREFIX = "ps-remote"
$script:INTEGRATION_ENTRY_CONTEXT = "PsRemote"
$script:INSECURE_WARNING = "Unix does not currently support CA or CN checks."
$script:ValidIpAddressRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

#### HELPER FUNCTIONS ####

function CreateNewSession {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope='Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Scope='Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope = 'Function')]
    param([string]$fqdn, [string]$username, [string]$password, [bool]$insecure, [bool]$ssl, [string]$auth_method)

    $credential = ConvertTo-SecureString "$password" -AsPlainText -Force
    $ps_credential = New-Object System.Management.Automation.PSCredential($username, $credential)

    $session_option_params = @{
        "SkipCACheck" = $insecure
        "SkipCNCheck" = $insecure
    }
    $session_options = New-PSSessionOption @session_option_params

    $sessions_params = @{
        "ComputerName" = $fqdn
        "Credential" = $ps_credential
        "SessionOption" = $session_options
        "Authentication" = $auth_method
        "ErrorAction" = "Stop"
        "WarningAction" = "SilentlyContinue"
        "UseSSL" = $ssl
    }
    try
    {
        $session = New-PSSession @sessions_params
    }
    catch
    {
        if ($_.Exception.Message -Match $script:INSECURE_WARNING)
        {
            throw "HTTPS certificate check isn't currently supported. Please enable 'Trust any certificate' or disable 'Use SSL'"
        }
        throw $_.Exception.Message
    }
    return $session
    <#
        .DESCRIPTION
        Creates new pssession using Negotiate authentication.

        .PARAMETER fqdn
        Fully qualified domain name (FQDN) to connect.

        .PARAMETER username
        Username is the name of a system user.

        .PARAMETER password
        Password of the system user.

        .PARAMETER insecure
        Wheter to trust any TLS/SSL Certificate) or not.

        .EXAMPLE
        CreateNewSession("myhost.example.com", "user", "pass")

        .OUTPUTS
        PSSession - PSSession object.

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7
    #>
}

class RemotingClient
{
    [string]$host
    [string]$fqdn
    [string]$username
    [string]$password
    [string]$domain
    [string]$dns
    [string]$auth_method
    [psobject]$session
    [bool]$insecure
    [bool]$ssl
    [bool]$proxy

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope = 'Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Scope='Function')]
    RemotingClient([string]$hosts, [string]$username, [string]$password, [string]$domain, [string]$dns,
                   [string]$auth_method, [bool]$insecure, [bool]$ssl, [bool]$proxy)
    {
        # set the container's resolv.conf to use to provided dns
        # http://manpages.ubuntu.com/manpages/xenial/man5/resolv.conf.5.html
        if ($dns)
        {
            "nameserver $dns" | Set-Content -Path \etc\resolv.conf
        }

        $this.domain = If ($domain) {".$domain"} Else {""}
        if (! ($hosts -match $script:ValidIpAddressRegex)) {
            # if not IP add the domain to the host
            $this.host = $hosts
            $this.fqdn = $hosts + $domain
        } else {
            $this.host = $hosts
            $this.fqdn = $hosts
        }

        $this.username = $username
        $this.password = $password
        $this.insecure = $insecure
        $this.ssl = $ssl
        $this.auth_method = $auth_method
        $this.proxy = $proxy
        <#
            .DESCRIPTION
            RemotingClient connect to a remote hostname and run processes on it remotely.

            .PARAMETER domain
            The host's domain.

            .PARAMETER dns
            Domain Name System (DNS) is the hierarchical and decentralized naming system for computers connected to the network.

            .PARAMETER username
            Username is the name of a system user.

            .PARAMETER password
            Password of the system user.

            .PARAMETER insecure
            Wheter to trust any TLS/SSL Certificate) or not.

            .PARAMETER ssl
            Wheter use SSL protocol to establish a connection.

            .PARAMETER auth_method
            Authentication method to use when creating a new session.

            .PARAMETER proxy
            Wheter to user system proxy configuration or not.

            .EXAMPLE
            $client = [RemotingClient]::new("MyComputer", "username", "password")
        #>
    }

    CreateSession()
    {
        $this.session = CreateNewSession -fqdn $this.fqdn -username $this.username -password $this.password -insecure $this.insecure -ssl $this.ssl $this.auth_method
        <#
            .DESCRIPTION
            This method is for internal use. It creates session to the remote hosts.

            .EXAMPLE
            $client.CreateSession()

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7
            https://docs.microsoft.com/en-us/powershell/partnercenter/multi-factor-auth?view=partnercenterps-3.0#exchange-online-powershell
        #>
    }

    CloseSession()
    {
        if ($this.session)
        {
            Remove-PSSession $this.session
        }
        <#
            .DESCRIPTION
            This method is for internal use. It removes an active session.

            .EXAMPLE
            $client.CloseSession()

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/remove-pssession?view=powershell-7
            https://docs.microsoft.com/en-us/powershell/partnercenter/multi-factor-auth?view=partnercenterps-3.0#exchange-online-powershell
        #>
    }


    [System.Array]InvokeCommandInSession([string]$remote_command)
    {
        if (!$this.session)
        {
            $this.CreateSession()
        }
        $temp = $script:Demisto.UniqueFile()
        $file_name = $script:Demisto.Investigation().id + "_" + $temp + ".ps1"
        $remote_command | Out-File -FilePath $file_name
        $result = Invoke-Command -Session $this.session -FilePath $file_name
        return $result
    <#
        .DESCRIPTION
        This method invokes a command in the session via a temporary file.

        .EXAMPLE
        $client.InvokeCommandInSession("$PSVersionTable")

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7.1
    #>
    }

    CopyItemFromSession([string]$path, [string]$file_name)
    {
        if (!$this.session)
        {
            $this.CreateSession()
        }
        Copy-Item -FromSession $this.session $path -Destination $file_name
    <#
        .DESCRIPTION
        This method copies an item from the session in specified path to the destination file_name.

        .EXAMPLE
        $client.CopyItemFromSession("remote\file.txt", "local\file.txt")

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/copy-item?view=powershell-7.1
    #>
    }

    CopyItemToSession([string]$path, [string]$file_name)
    {
        if (!$this.session)
        {
            $this.CreateSession()
        }
        Copy-Item -ToSession $this.session $path -Destination $file_name
    <#
        .DESCRIPTION
        This method copies an item from the local path to the session destination file_name.

        .EXAMPLE
        $client.CopyItemFromSession("remote\file.txt", "local\file.txt")

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/copy-item?view=powershell-7.1
    #>
    }

    [PSCustomObject]ExportMFT([string]$volume, [string]$output_file_path) {
        if (!$this.session)
        {
            $this.CreateSession()
        }
        $remote_script_block = {
            Param($volume, $output_file_path)

            if ($volume -ne 0)
            {
                $Win32_Volume = Get-CimInstance -Class Win32_Volume -Filter "DriveLetter LIKE '$( $volume ):'"
                if ($Win32_Volume.FileSystem -ne "NTFS")
                {
                    Write-Error "$volume is not an NTFS filesystem."
                    break
                }
            }
            else
            {
                $Win32_Volume = Get-CimInstance -Class Win32_Volume -Filter "DriveLetter LIKE '$( $env:SystemDrive )'"
                if ($Win32_Volume.FileSystem -ne "NTFS")
                {
                    Write-Error "$env:SystemDrive is not an NTFS filesystem."
                    break
                }
            }
            if (-not$output_file_path)
            {
                $output_file_path = $env:TEMP + "\$([IO.Path]::GetRandomFileName() )"
            }

            #region WinAPI

            $GENERIC_READWRITE = 0x80000000
            $FILE_SHARE_READWRITE = 0x02 -bor 0x01
            $OPEN_EXISTING = 0x03

            $DynAssembly = New-Object System.Reflection.AssemblyName('MFT')
            $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemory', $false)

            $TypeBuilder = $ModuleBuilder.DefineType('kernel32', 'Public, Class')
            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
            $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,
            @('kernel32.dll'),
            [Reflection.FieldInfo[]]@($SetLastError),
            @($True))

            #CreateFile
            $PInvokeMethodBuilder = $TypeBuilder.DefinePInvokeMethod('CreateFile', 'kernel32.dll',
                    ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
                    [Reflection.CallingConventions]::Standard,
                    [IntPtr],
                    [Type[]]@([String],[Int32],[UInt32],[IntPtr],[UInt32],[UInt32],[IntPtr]),
                    [Runtime.InteropServices.CallingConvention]::Winapi,
                    [Runtime.InteropServices.CharSet]::Ansi)
            $PInvokeMethodBuilder.SetCustomAttribute($SetLastErrorCustomAttribute)

            #CloseHandle
            $PInvokeMethodBuilder = $TypeBuilder.DefinePInvokeMethod('CloseHandle', 'kernel32.dll',
                    ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
                    [Reflection.CallingConventions]::Standard,
                    [Bool],
                    [Type[]]@([IntPtr]),
                    [Runtime.InteropServices.CallingConvention]::Winapi,
                    [Runtime.InteropServices.CharSet]::Auto)
            $PInvokeMethodBuilder.SetCustomAttribute($SetLastErrorCustomAttribute)

            $Kernel32 = $TypeBuilder.CreateType()

            #endregion WinAPI

            # Get handle to volume
            if ($volume -ne 0)
            {
                $VolumeHandle = $Kernel32::CreateFile(('\\.\' + $volume + ':'), $GENERIC_READWRITE, $FILE_SHARE_READWRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
            }
            else
            {
                $VolumeHandle = $Kernel32::CreateFile(('\\.\' + $env:SystemDrive), $GENERIC_READWRITE, $FILE_SHARE_READWRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
                $volume = ($env:SystemDrive).TrimEnd(':')
            }

            if ($VolumeHandle -eq -1)
            {
                Write-Error "Unable to obtain read handle for volume."
                break
            }

            # Create a FileStream to read from the volume handle
            $FileStream = New-Object IO.FileStream($VolumeHandle, [IO.FileAccess]::Read)

            # Read VBR from volume
            $VolumeBootRecord = New-Object Byte[](512)
            if ($FileStream.Read($VolumeBootRecord, 0, $VolumeBootRecord.Length) -ne 512)
            {
                Write-Error "Error reading volume boot record."
            }

            # Parse MFT offset from VBR and set stream to its location
            $MftOffset = [Bitconverter]::ToInt32($VolumeBootRecord[0x30..0x37], 0) * 0x1000
            $FileStream.Position = $MftOffset

            # Read MFT's file record header
            $MftFileRecordHeader = New-Object byte[](48)
            if ($FileStream.Read($MftFileRecordHeader, 0, $MftFileRecordHeader.Length) -ne $MftFileRecordHeader.Length)
            {
                Write-Error "Error reading MFT file record header."
            }

            # Parse values from MFT's file record header
            $OffsetToAttributes = [Bitconverter]::ToInt16($MftFileRecordHeader[0x14..0x15], 0)
            $AttributesRealSize = [Bitconverter]::ToInt32($MftFileRecordHeader[0x18..0x21], 0)

            # Read MFT's full file record
            $MftFileRecord = New-Object byte[]($AttributesRealSize)
            $FileStream.Position = $MftOffset
            if ($FileStream.Read($MftFileRecord, 0, $MftFileRecord.Length) -ne $AttributesRealSize)
            {
                Write-Error "Error reading MFT file record."
            }

            # Parse MFT's attributes from file record
            $Attributes = New-object byte[]($AttributesRealSize - $OffsetToAttributes)
            [Array]::Copy($MftFileRecord, $OffsetToAttributes, $Attributes, 0, $Attributes.Length)

            # Find Data attribute
            $CurrentOffset = 0
            do
            {
                $AttributeType = [Bitconverter]::ToInt32($Attributes[$CurrentOffset..$( $CurrentOffset + 3 )], 0)
                $AttributeSize = [Bitconverter]::ToInt32($Attributes[$( $CurrentOffset + 4 )..$( $CurrentOffset + 7 )], 0)
                $CurrentOffset += $AttributeSize
            } until ($AttributeType -eq 128)

            # Parse data attribute from all attributes
            $DataAttribute = $Attributes[$( $CurrentOffset - $AttributeSize )..$( $CurrentOffset - 1 )]

            # Parse MFT size from data attribute
            $MftSize = [Bitconverter]::ToUInt64($DataAttribute[0x30..0x37], 0)

            # Parse data runs from data attribute
            $OffsetToDataRuns = [Bitconverter]::ToInt16($DataAttribute[0x20..0x21], 0)
            $DataRuns = $DataAttribute[$OffsetToDataRuns..$( $DataAttribute.Length - 1 )]

            # Convert data run info to string[] for calculations
            $DataRunStrings = ([Bitconverter]::ToString($DataRuns)).Split('-')

            # Setup to read MFT
            $FileStreamOffset = 0
            $DataRunStringsOffset = 0
            $TotalBytesWritten = 0
            $MftData = New-Object byte[](0x1000)
            $OutputFileStream = [IO.File]::OpenWrite($output_file_path)

            do
            {
                $StartBytes = [int]($DataRunStrings[$DataRunStringsOffset][0]).ToString()
                $LengthBytes = [int]($DataRunStrings[$DataRunStringsOffset][1]).ToString()

                $DataRunStart = "0x"
                for ($i = $StartBytes; $i -gt 0; $i--) {
                    $DataRunStart += $DataRunStrings[($DataRunStringsOffset + $LengthBytes + $i)]
                }

                $DataRunLength = "0x"
                for ($i = $LengthBytes; $i -gt 0; $i--) {
                    $DataRunLength += $DataRunStrings[($DataRunStringsOffset + $i)]
                }

                $FileStreamOffset += ([int]$DataRunStart * 0x1000)
                $FileStream.Position = $FileStreamOffset

                for ($i = 0; $i -lt [int]$DataRunLength; $i++) {
                    if ($FileStream.Read($MftData, 0, $MftData.Length) -ne $MftData.Length)
                    {
                        Write-Warning "Possible error reading MFT data on $env:COMPUTERNAME."
                    }
                    $OutputFileStream.Write($MftData, 0, $MftData.Length)
                    $TotalBytesWritten += $MftData.Length
                }
                $DataRunStringsOffset += $StartBytes + $LengthBytes + 1
            } until ($TotalBytesWritten -eq $MftSize)

            $FileStream.Dispose()
            $OutputFileStream.Dispose()

            $Properties = @{
                NetworkPath = "\\$( $env:COMPUTERNAME )\C$\$($output_file_path.TrimStart('C:\') )"
                ComputerName = $env:COMPUTERNAME
                'MFT Size' = "$( $MftSize / 1024 / 1024 ) MB"
                'MFT Volume' = $volume
                'MFT File' = $output_file_path
            }
            New-Object -TypeName PSObject -Property $Properties
        }
        return Invoke-Command -Session $this.session -ScriptBlock $remote_script_block -ArgumentList @($volume, $output_file_path)
    }
}

function TestModuleCommand {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Scope='Function')]
    param([RemotingClient]$client)

    if ($client.ssl) {
        $res = Test-Connection -TcpPort 5986 -TargetName $client.fqdn -ErrorAction Stop
        if (-not $res) {
            throw 'Could not create connection for host ' + $client.fqdn + ' via port 5986.'
        }
    }
    else {
        $res = Test-Connection -TcpPort 5985 -TargetName $client.fqdn -ErrorAction Stop
        if (-not $res) {
            throw 'Could not create connection for host ' + $client.fqdn + ' via port 5985.'
        }
    }
    $tmp = $client.InvokeCommandInSession('$PSVersionTable')
    $client.CloseSession()

    $human_readable = "ok"

    return $human_readable, $null, $null
}

function CreatResultsMap {
    param([System.Array]$raw_result, [string]$command, [string]$fqdn, [string]$hosts)
    $now = Get-Date -Format "o"
    $results_map = @{
        Host = $hosts
        FQDN = $fqdn
        CommandName = $command
        UTCTime = $now
        CommandResult = [System.Collections.ArrayList]::new()
    }
    For ($i=0; $i -lt $raw_result.Length; $i++) {
        # base name
        if($raw_result[$i].GetType().Fullname -eq 'System.Management.Automation.PSObject') {
                $item = ($raw_result[$i] | select-object -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId)
        }
        elseif ($raw_result[$i].GetType().Fullname -eq 'System.String') {
            if ([string]::IsNullOrEmpty($raw_result[$i])) {
                continue
            }
            $item = ($raw_result[$i] | out-string)
        }
        $results_map['CommandResult'] += $item
    }
    return $results_map
    <#
        .DESCRIPTION
        Create result map from single computer result
    #>
}

function InvokeCommandCommand {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Scope='Function')]
    param([RemotingClient]$client, [string]$command)

    $title = "Result for PowerShell Remote Command: $command `n"
    $raw_result = $client.InvokeCommandInSession($command)
    $client.CloseSession()
    $results_map = CreatResultsMap -raw_result $raw_result -command $command -fqdn $client.fqdn -hosts $client.host
    # extract command results per computer
    if ($results_map) {
        $entry_context = @{
            $script:INTEGRATION_ENTRY_CONTEXT = $results_map
        }
        $human_readable = $title + $raw_result

        return $human_readable, $entry_context, $raw_result
    }
    else {
        return $title + 'No results', $null, $null
    }
    <#
        .DESCRIPTION
        Runs invoke-command on existing session.
    #>
}

function DownloadFileCommand([RemotingClient]$client, [string]$path, [string]$zip_file, [string]$check_hash, [bool]$host_as_prefix)
{
    $temp = $script:Demisto.UniqueFile()
    $file_name = $script:Demisto.Investigation().id + "_$temp"

    # assert file exists in the system
    $command = '[System.IO.File]::Exists("' + $path + '")'
    $raw_result = $client.InvokeCommandInSession($command)
    if (-Not $raw_result -or ($raw_result -eq $False))
    {
        $client.CloseSession()
        throw "$path was not found on the remote host."
    }

    if ($host_as_prefix -eq 'true')
    {
        $file_name_parent = Split-Path $path
        $pre_rename_leaf = Split-Path $path -leaf
        $file_name_leaf = $client.host + '_' + $pre_rename_leaf
        $command = "Rename-Item -Path $path -NewName $file_name_leaf"
        $client.InvokeCommandInSession($command)
        $path = "$file_name_parent/$file_name_leaf"
    }

    if ($zip_file -eq 'true')
    {
        # zip file at the host
        $pre_zip_path = $path
        $path = "$path.zip"
        $command = "Compress-Archive -Path $pre_zip_path -Update -DestinationPath $path"
        $client.InvokeCommandInSession($command)
    }

    if ($check_hash -eq 'true')
    {
        # save orig hash
        $command = "(Get-FileHash $path -Algorithm MD5).Hash"
        $src_hash = $client.InvokeCommandInSession($command)
    }

    $client.CopyItemFromSession($path, $file_name)
    if ($zip_file -eq 'true')
    {
        # clean zip from host
        $command = "Remove-Item $path"
        $client.InvokeCommandInSession($command)
    }

    if ($host_as_prefix -eq 'true')
    {
        if ($zip_file -eq 'true')
        {
            $command = "Rename-Item -Path $pre_zip_path -NewName $pre_rename_leaf"
        }
        else {
            $command = "Rename-Item -Path $path -NewName $pre_rename_leaf"
        }
        $client.InvokeCommandInSession($command)
    }

    $client.CloseSession()
    if ($check_hash -eq 'true')
    {
        # compare src-dst hashes
        $dst_hash = (Get-FileHash $file_name -Algorithm MD5).Hash
        if ($src_hash -ne $dst_hash)
        {
            throw "Failed check_hash: The downloaded file has a different hash than the file in the host. RemoteHostHash=$src_hash DownloadedHash=$dst_hash"
        }
    }

    # add file details to context
    $file_name_leaf = Split-Path $path -leaf
    $file_extension = [System.IO.Path]::GetExtension($file_name_leaf)
    $file_extension = If ($file_extension) {$file_extension.SubString(1, $file_extension.length - 1)} else {""}

    $entry_context = @{
        PsRemoteDownloadedFile = @{
            FQDN = $client.fqdn
            Host = $client.host
            FileName = $file_name_leaf
            FileSize = Get-Item $file_name | ForEach-Object { [math]::ceiling($_.length / 1kb) }
            FileSHA1 = (Get-FileHash $file_name -Algorithm SHA1).Hash
            FileSHA256 = (Get-FileHash $file_name -Algorithm SHA256).Hash
            FileMD5 = (Get-FileHash $file_name -Algorithm MD5).Hash
            FileExtension = $file_extension
        }
    }

    $demisto_results = @{
        Type = 3
        ContentsFormat = "text"
        Contents = ""
        File = $file_name_leaf
        FileID = $temp
        EntryContext = $entry_context
    }
    $script:Demisto.Results($demisto_results)
}

function StartETLCommand {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Scope='Function')]
    param([RemotingClient]$client, [string]$etl_path, [string]$etl_filter, [string]$etl_max_size, [string]$overwrite)
    $command = "netsh trace start capture=yes traceFile=$etl_path maxsize=$etl_max_size overwrite=$overwrite $etl_filter"
    $raw_result = $client.InvokeCommandInSession($command)
    $client.CloseSession()
    $results_map = CreatResultsMap -raw_result $raw_result -command $command -fqdn $client.fqdn -hosts $client.host
    if ($results_map) {
        $results_map['EtlFilePath'] = $etl_path
        $results_map['EtlFileName'] = Split-Path $etl_path -leaf
        $entry_context = @{
            $script:INTEGRATION_ENTRY_CONTEXT = $results_map
        }
        $human_readable = $title + $raw_result

        return $human_readable, $entry_context, $raw_result
    }
    else {
        return $title + 'No results', $null, $null
    }
}

function StopETLCommand([RemotingClient]$client)
{
    $command = 'netsh trace stop'
    $raw_results = $client.InvokeCommandInSession($command)
    $client.CloseSession()
    $etl_path = $raw_results | Select-String -Pattern "File location = "
    if ($etl_path)
    {
        # clean "File location = "
        $etl_path = $etl_path.ToString()
        $etl_path = $etl_path.Substring(16, $etl_path.Length - 16)
    }
    else
    {
        $etl_path = ""
    }
    if ($raw_results)
    {
        $raw_results = [string]$raw_results
    }
    $entry_context = @{
        $script:INTEGRATION_ENTRY_CONTEXT = @{
            FQDN = $client.fqdn
            Host = $client.host
            CommandName = $command
            CommandResult = $raw_results
            EtlFilePath = $etl_path
            EtlFileName = if ($etl_path) {Split-Path $etl_path -leaf} else {""}
        }
    }

    $human_readable = $raw_results

    return $human_readable, $entry_context, $raw_result
}

function ExportRegistryCommand([RemotingClient]$client, [string]$reg_key_hive, [string]$output_file_path)
{
    $command = if ($reg_key_hive -eq 'all') {"regedit /e $output_file_path"} else {"reg export $reg_key_hive $output_file_path"}
    $raw_results = $client.InvokeCommandInSession($command)
    Start-Sleep -Seconds 30
    $client.CloseSession()
    $title = "Ran Export Registry. `n"

    $entry_context = @{
        $script:INTEGRATION_ENTRY_CONTEXT = @{
            FQDN = $client.fqdn
            Host = $client.host
            CommandResult = $raw_results
            CommandName = $command
            RegistryFilePath = $output_file_path
            RegistryFileName = Split-Path $output_file_path -leaf
        }
    }

    $human_readable = $title + "Registry file expected path: $output_file_path"

    return $human_readable, $entry_context, $raw_results
}

function UploadFileCommand([RemotingClient]$client, [string]$entry_id, [string]$dst_path, [string]$zip_file, [string]$check_hash)
{
    $src_path = $script:Demisto.GetFilePath($entry_id).path
    $file_exists = Test-Path $src_path -PathType Leaf
    if (-Not $file_exists)
    {
        throw "Could not find $entry_id file, please make sure you entered it correctly."
    }
    if ($zip_file -eq 'true')
    {
        # compress file before upload
        $old_path = $src_path
        $src_path = "$src_path.zip"
        $dst_path = "$dst_path.zip"
        Compress-Archive -Path $old_path -Update -DestinationPath $src_path
    }
    if ($check_hash -eq 'true')
    {
        # save hash before upload
        $src_hash = (Get-FileHash $src_path -Algorithm MD5).Hash
    }
    $client.CopyItemToSession($src_path, $dst_path)
    if ($check_hash -eq 'true')
    {
        $command = "(Get-FileHash $dst_path -Algorithm MD5).Hash"
        $dst_hash = $client.InvokeCommandInSession($command)
        if ($src_hash -ne $dst_hash)
        {
            throw "Failed check_hash: The uploaded file has a different hash than the local file. LocalFileHash=$src_hash UploadedFileHash=$dst_hash"
        }
    }
    $client.CloseSession()

    $file_name_leaf = Split-Path $src_path -leaf
    $file_ext = [System.IO.Path]::GetExtension($file_name_leaf)
    $file_ext = If ($file_ext) {$file_ext.SubString(1, $file_ext.length - 1)} else {""}

    $entry_context = @{
        PsRemoteUploadedFile = @{
            FQDN = $client.fqdn
            Host = $client.host
            FilePath = $dst_path
            FileName = $file_name_leaf
            FileSize = Get-Item $src_path | ForEach-Object { [math]::ceiling($_.length / 1kb) }
            FileSHA1 = (Get-FileHash $src_path -Algorithm SHA1).Hash
            FileSHA256 = (Get-FileHash $src_path -Algorithm SHA256).Hash
            FileMD5 = (Get-FileHash $src_path -Algorithm MD5).Hash
            FileExtension = $file_ext
        }
    }
    $human_readable = "File $file_name_leaf was uploaded successfully as: $dst_path"

    return $human_readable, $entry_context, $null
}

function ExportMFTCommand([RemotingClient]$client, [string]$volume, [string]$output_file_path)
{
    $raw_response = $client.ExportMFT($volume, $output_file_path)
    $client.CloseSession()

    $entry_context = @{
        $script:INTEGRATION_ENTRY_CONTEXT = @{
            FQDN = $client.fqdn
            Host = $client.host
            ExportMFT = $raw_response
        }
    }
    $human_readable = TableToMarkdown $raw_response 'MFT Export results:'

    return $human_readable, $entry_context, $raw_result
}

function Main
{
    $command = $Demisto.GetCommand()
    $command_args = $Demisto.Args()
    $params = $Demisto.Params()
    <#
        Proxy currently isn't supported by PWSH New-Pssession, However further effort might yield an implementation,
        leaving this parameter for feature development if required.
    #>
    $no_proxy = $false
    $insecure = (ConvertTo-Boolean $params.insecure)
    $ssl = (ConvertTo-Boolean $params.ssl)

    try
    {
        $hosts = if ($command -eq 'test-module') {ArgToList $params.host } else {ArgToList $command_args.host}
        if ($hosts.Length -gt 1) {
            throw "too many hosts were provided. please provide just a single host"
        }
        $domain = if ($params.domain) {"." + $params.domain} else {""}
        $client = [RemotingClient]::new($hosts, $params.credentials.identifier, $params.credentials.password,
                                        $domain, $params.dns, $params.auth_method, $insecure, $ssl, $no_proxy)
        # Executing command
        $Demisto.Debug("Command being called is $command")
        switch ($command)
        {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand $client
            }
            "$script:COMMAND_PREFIX-command" {
                ($human_readable, $entry_context, $raw_response) = InvokeCommandCommand $client $command_args.command
            }
            "$script:COMMAND_PREFIX-download-file" {
                DownloadFileCommand -client $client -path $command_args.path -zip_file $command_args.zip_file -check_hash $command_args.check_hash -host_as_prefix (ConvertTo-Boolean $command_args.host_prefix)
                return
            }
            "$script:COMMAND_PREFIX-etl-create-start" {
                ($human_readable, $entry_context, $raw_response) = StartETLCommand -client $client -etl_path $command_args.etl_path -etl_filter $command_args.etl_filter -etl_max_size $command_args.etl_max_size -overwrite $command_args.overwrite
            }
            "$script:COMMAND_PREFIX-etl-create-stop" {
                ($human_readable, $entry_context, $raw_response) = StopETLCommand $client
            }
            "$script:COMMAND_PREFIX-export-registry" {
                ($human_readable, $entry_context, $raw_response) = ExportRegistryCommand -client $client -reg_key_hive $command_args.reg_key_hive -output_file_path $command_args.file_path
            }
            "$script:COMMAND_PREFIX-upload-file" {
                # to be tested
                ($human_readable, $entry_context, $raw_response) = UploadFileCommand -client $client -entry_id $command_args.entry_id -dst_path $command_args.path -zip_file $command_args.zip_file -check_hash $command_args.check_hash
            }
            "$script:COMMAND_PREFIX-export-mft" {
                ($human_readable, $entry_context, $raw_response) = ExportMFTCommand -client $client -volume $command_args.volume -output_file_path $command_args.output_path
            }
            Default {
                $Demisto.Error("Unsupported command was entered: $command.")
            }
        }
        # Return results to Demisto Server
        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
    }
    catch
    {
        $Demisto.debug("Integration: $script:INTEGRATION_NAME Command: $command Arguments: $( $command_args | ConvertTo-Json ) Error: $( $_.Exception.Message )")
        if ($command -ne "test-module")
        {
            ReturnError "Error:Integration: $script:INTEGRATION_NAME Command: $command Arguments: $( $command_args | ConvertTo-Json ) Error: $( $_.Exception )" | Out-Null
        }
        else
        {
            $err_msg = $_.Exception.Message
            if ($err_msg -match 'Authorization failed') {
                $err_msg = 'The integration was able to resolve and perform a connectivity test to the specified host. There seems to be an issue with the credentials or host settings.
                For further troubleshooting please refer to the Powershell Remoting article in https://xsoar.pan.dev/docs/reference/index.'
        }
            ReturnError $err_msg
        }
    }
}


# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT$Test)
{
    Main
}
