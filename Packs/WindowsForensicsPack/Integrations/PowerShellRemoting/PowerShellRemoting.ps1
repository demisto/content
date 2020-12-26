. $PSScriptRoot\CommonServerPowerShell.ps1

$script:INTEGRATION_NAME = "PowerShell Remoting"
$script:COMMAND_PREFIX = "ps-remote"
$script:INTEGRATION_ENTRY_CONTEX = "PsRemote"

#### HELPER FUNCTIONS ####

function CreateNewSession {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope = 'Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope = 'Function')]
    param([string]$fqdn_list, [string]$username, [string]$password, [bool]$insecure, [bool]$proxy)

    $credential = ConvertTo-SecureString "$password" -AsPlainText -Force
    $ps_credential = New-Object System.Management.Automation.PSCredential($username, $credential)

    $session_option_params = @{
        "SkipCACheck" = $insecure
        "SkipCNCheck" = $insecure
        "ProxyAccessType" = If ($proxy) {"IEConfig"} Else {"None"} # Needs to be further tested
    }
    $session_options = New-PSSessionOption @session_option_params
    $sessions_params = @{
        "ComputerName" = $fqdn_list
        "Credential" = $ps_credential
        "SessionOption" = $session_options
        "Authentication" = "Negotiate"
        "ErrorAction" = "Stop"
        "WarningAction" = "SilentlyContinue"
    }
    $session = New-PSSession @sessions_params

    return $session
    <#
        .DESCRIPTION
        Creates new pssession using Negotiate authentication.

        .PARAMETER fqdn_list
        List of Fully qualified domain name (FQDN) to connect.

        .PARAMETER username
        Username is the name of a system user.

        .PARAMETER password
        Password of the system user.

        .EXAMPLE proxy
        Wheter to user system proxy configuration or not.

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
    [string]$hostname
    [string]$username
    [string]$password
    [string]$domain
    [string]$dns
    [psobject]$session
    [bool]$insecure
    [bool]$proxy

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope = 'Function')]
    RemotingClient([string]$hostname, [string]$username, [string]$password, [string]$domain, [string]$dns,
                   [string]$ip_hosts, [bool]$insecure, [bool]$proxy)
    {
        # set the container's resolv.conf to use to provided dns
        if ($dns)
        {
            "nameserver $dns" | Set-Content -Path \etc\resolv.conf
        }

        $domain = If ($domain) {"." + $domain } Else {"" }
        # generically handle 0-* hosts fqdn
        $fqdn = $hostname | ForEach-Object -Process { $_ + $domain }
        if ($ip_hosts)
        {
            # single fqdn
            if ($fqdn -and ($fqdn.GetType().fullname -eq 'System.String'))
            {
                # TODO: Improve list creation
                $fqdn_list = [System.Collections.ArrayList]::new()
                $fqdn_list += $fqdn
                $fqdn = $fqdn_list + $ip_hosts
            }
            # no / multiple fqdn
            else
            {
                $fqdn += $ip_hosts
            }

        }

        $this.fqdn_list = $fqdn
        $this.username = $username
        $this.password = $password
        $this.insecure = $insecure
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

            .EXAMPLE proxy
            Wheter to user system proxy configuration or not.

            .EXAMPLE
            $client = [RemotingClient]::new("MyComputer", "username", "password")
        #>
    }

    CreateSession()
    {
        $this.session = CreateNewSession -fqdn_list $this.fqdn_list -username $this.username -password $this.password -insecure $this.insecure -proxy $this.proxy
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


    InvokeCommandInSession([string]$remote_command)
    {
        if (!$this.session)
        {
            $this.CreateSession()
        }
        $temp = $demisto.UniqueFile()
        $file_name = "$demisto.Investigation().id_$temp.ps1"
        echo $remote_command | Out-File -FilePath $file_name
        return Invoke-Command $this.session -FilePath $file_name
    <#
        .DESCRIPTION
        This method invokes a command in the session via a temporary file.

        .EXAMPLE
        $client.("$PSVersionTable")

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7.1
    #>
    }

    CopyItemInSession([string]$path, [string]$file_name)
    {
        if (!$this.session)
        {
            $this.CreateSession()
        }
        Copy-Item -FromSession $this.session $path -Destination $file_name
    }
}

function TestModuleCommand ([RemotingClient]$client, [string]$hostname) {
    client.InvokeCommandInSession('$PSVersionTable')

    $raw_response = $null
    $human_readable = "ok"
    $entry_context = $null

    return $human_readable, $entry_context, $raw_response
}

function InvokeCommandCommand([RemotingClient]$client, [string]$command, [string]$hostname, $ip_hosts)
{
    $title = "Result for PowerShell Remote Command: $command `n"
    $raw_result = $client.InvokeCommandInSession($command)
    $client.CloseSession()
    $context_result = @{
        Command = $command
        Result = $raw_result
    }
    $entry_context = @{
        script:INTEGRATION_ENTRY_CONTEX = @{ Command = $context_result }
    }
    $human_readable = $title + $raw_result

    return $human_readable, $entry_context, $raw_result
    <#
        .DESCRIPTION
        Runs invoke-command on existing session.
    #>
}

function DownloadFileCommand([RemotingClient]$client, [string]$path, [string]$hostname, [string]$ip_hosts, [string]$zip_file, [string]$check_hash)
{
    $temp = $demisto.UniqueFile()
    $file_name = "$demisto.Investigation().id_$temp"

    # assert file exists in the system
    $command = "[System.IO.File]::Exists($path)"
    $raw_result = $client.InvokeCommandInSession($command)
    if (!$raw_result)
    {
        $client.CloseSession()
        throw "$path was not found on the remote host."
    }

    if ($zip_file -eq 'true')
    {
        # zip file at the host
        $old_path = $path
        $path = "$path.zip"
        $command = "Compress-Archive -Path $old_path -Update -DestinationPath $path"
        $client.InvokeCommandInSession($command)
    }

    if ($check_hash -eq 'true')
    {
        # save orig hash
        $command = "(Get-FileHash $path -Algorithm MD5).Hash"
        $src_hash = $client.InvokeCommandInSession($command)
    }

    client.CopyItemInSession($path, $file_name)
    if ($zip_file -eq 'true')
    {
        # clean zip from host
        $command = "Remove-Item $path"
        client.InvokeCommandInSession($command)
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
    $file_extension = [System.IO.Path]::GetExtension($file_name_leaf)
    $file_extension = If ($file_extension) {$file_extension.SubString(1, $file_extension.length - 1)} else {""}

    $entry_context = [PSCustomObject]@{
        PsRemoteDownloadedFile = [PSCustomObject]@{
            FileName = $file_name_leaf;
            FileSize = Get-Item $file_name | % { [math]::ceiling($_.length / 1kb) };
            FileSHA1 = (Get-FileHash $file_name -Algorithm SHA1).Hash;
            FileSHA256 = (Get-FileHash $file_name -Algorithm SHA256).Hash;
            FileMD5 = (Get-FileHash $file_name -Algorithm MD5).Hash;
            FileExtension = $file_extension
        }
    }

    $file_name_leaf = Split-Path $path -leaf
    $demisto_results = @{
        Type = 3
        ContentsFormat = "text"
        Contents = ""
        File = $file_name_leaf
        FileID = $temp
        EntryContext = $entry_context
    }
    $demisto.Results($demisto_results)
}

function StartETLCommand([RemotingClient]$client, [string]$hostname, [string]$ip_hosts, [string]$etl_path,
                         [string]$etl_filter, [string]$etl_max_size, [string]$etl_time_lim, [string]$overwrite)
{
    $command = "netsh trace start capture=yes traceFile=$etl_path maxsize=$etl_max_size overwrite=$overwrite $etl_filter"
    $raw_result = client.InvokeCommandInSession($command)
    $client.CloseSession()
    $title = "You have executed the start ETL command successfully `n"
    $EntryContext = @{
        $script:INTEGRATION_ENTRY_CONTEX = @{
            CommandResult = $raw_result
            EtlFilePath = $etl_path
            EtlFileName = Split-Path $etl_path -leaf
        }
    }

    $human_readable = $title + $raw_result

    return $human_readable, $entry_context, $raw_result
}

function StopETL($Hostname, $IPHosts)
{
    #
    $Command = 'netsh trace stop'
    $Session = CreateSession $Hostname $IPHosts
    $Contents = InvokeCommandInSession $Command $Session
    $Session | Remove-PSsession
    $EtlPath = echo $Contents | Select-String -Pattern "File location = "
    if ($EtlPath)
    {
        $EtlPath = $EtlPath.ToString()
        $EtlPath = $EtlPath.Substring(16, $EtlPath.Length - 16)
    }
    else
    {
        $EtlPath = ""
    }
    if ($Contents)
    {
        $Contents = [string]$Contents
    }
    $EntryContext = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{ CommandResult = $Contents; EtlFilePath = $EtlPath; EtlFileName = If ($EtlPath)
        {
            Split-Path $EtlPath -leaf
        }
        else
        {
            ""
        } }
    }

    $DemistoResult = @{
        Type = 1;
        ContentsFormat = "json";
        Contents = $Contents;
        EntryContext = $EntryContext;
        ReadableContentsFormat = "markdown";
        HumanReadable = $Contents;
    }

    return $DemistoResult
}

function ExportRegistry($Hostname, $IPHosts, $RegKeyHive, $FilePath)
{
    $command = If ($RegKeyHive -eq 'all')
    {
        'regedit /e '
    }
    Else
    {
        'reg export ' + $RegKeyHive + ' '
    }
    $command = $command + $FilePath
    $Title = "Ran Export Registry. `n"
    $Session = CreateSession $Hostname $IPHosts
    $Contents = InvokeCommandInSession $Command $Session
    $EntryContext = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{ CommandResult = $Contents; RegistryFilePath = $FilePath; RegistryFileName = Split-Path $FilePath -leaf }
    }

    $DemistoResult = @{
        Type = 1;
        ContentsFormat = "json";
        Contents = $Contents;
        EntryContext = $EntryContext;
        ReadableContentsFormat = "markdown";
        HumanReadable = $Title + $Contents;
    }

    return $DemistoResult
}

function UploadFile($EntryId, $DstPath, $Hostname, $IPHosts, $ZipFile, $CheckHash)
{
    $Session = CreateSession $Hostname $IPHosts
    $SrcPath = $demisto.GetFilePath($EntryId).path
    if ($ZipFile -eq 'true')
    {
        $OldPath = $SrcPath
        $SrcPath = $SrcPath + ".zip"
        Compress-Archive -Path $OldPath -Update -DestinationPath $SrcPath
    }
    if ($CheckHash -eq 'true')
    {
        $SrcHash = (Get-FileHash $SrcPath -Algorithm MD5).Hash
    }
    Copy-Item -ToSession $Session $SrcPath -Destination $DstPath
    if ($CheckHash -eq 'true')
    {
        $command = '(Get-FileHash ' + $DstPath + ' -Algorithm MD5).Hash'
        $DstHash = InvokeCommandInSession $command $Session
        if ($SrcHash -ne $DstHash)
        {
            ReturnError('Failed check_hash: The uploaded file has a different hash than the local file. LocalFileHash=' + $SrcHash + ' UploadedFileHash=' + $DstHash)
            exit(0)
        }
    }
    $Session | Remove-PSsession

    $FileNameLeaf = Split-Path $SrcPath -leaf
    $FileExtension = [System.IO.Path]::GetExtension($FileNameLeaf)
    $FileExtension = If ($FileExtension)
    {
        $FileExtension.SubString(1, $FileExtension.length - 1)
    }
    else
    {
        ""
    }

    $EntryContext = [PSCustomObject]@{
        PsRemoteDownloadedFile = [PSCustomObject]@{
            FileName = $FileNameLeaf;
            FileSize = Get-Item $SrcPath | % { [math]::ceiling($_.length / 1kb) };
            FileSHA1 = (Get-FileHash $SrcPath -Algorithm SHA1).Hash;
            FileSHA256 = (Get-FileHash $SrcPath -Algorithm SHA256).Hash;
            FileMD5 = (Get-FileHash $SrcPath -Algorithm MD5).Hash;
            FileExtension = $FileExtension
        }
    }
    return $DemistoResult = @{
        Type = 1;
        ContentsFormat = "text";
        Contents = "";
        EntryContext = $EntryContext;
        HumanReadable = "File upload command finished execution."
    }
}

function ExportMFT($Hostname, $IPHosts, $Volume, $OutPutFilePath)
{
    $RemoteScriptBlock = {
        Param($Volume, $OutPutFilePath)

        if ($Volume -ne 0)
        {
            $Win32_Volume = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter LIKE '$( $Volume ):'"
            if ($Win32_Volume.FileSystem -ne "NTFS")
            {
                Write-Error "$Volume is not an NTFS filesystem."
                break
            }
        }
        else
        {
            $Win32_Volume = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter LIKE '$( $env:SystemDrive )'"
            if ($Win32_Volume.FileSystem -ne "NTFS")
            {
                Write-Error "$env:SystemDrive is not an NTFS filesystem."
                break
            }
        }
        if (-not$OutputFilePath)
        {
            $OutputFilePath = $env:TEMP + "\$([IO.Path]::GetRandomFileName() )"
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
        if ($Volume -ne 0)
        {
            $VolumeHandle = $Kernel32::CreateFile(('\\.\' + $Volume + ':'), $GENERIC_READWRITE, $FILE_SHARE_READWRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
        }
        else
        {
            $VolumeHandle = $Kernel32::CreateFile(('\\.\' + $env:SystemDrive), $GENERIC_READWRITE, $FILE_SHARE_READWRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
            $Volume = ($env:SystemDrive).TrimEnd(':')
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
        $OutputFileStream = [IO.File]::OpenWrite($OutputFilePath)

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
            NetworkPath = "\\$( $env:COMPUTERNAME )\C$\$($OutputFilePath.TrimStart('C:\') )"
            ComputerName = $env:COMPUTERNAME
            'MFT Size' = "$( $MftSize / 1024 / 1024 ) MB"
            'MFT Volume' = $Volume
            'MFT File' = $OutputFilePath
        }
        New-Object -TypeName PSObject -Property $Properties
    }
    $Session = CreateSession $Hostname $IPHosts
    $ReturnedObjects = Invoke-Command -Session $Session -ScriptBlock $RemoteScriptBlock -ArgumentList @($Volume, $OutPutFilePath)
    $Session | Remove-PSsession

    $ReturnedObjects = $ReturnedObjects | Add-Member -NotePropertyMembers @{ Host = ($Hostname + $IPHosts) } -PassThru
    $Context = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{ ExportMFT = $ReturnedObjects }
    }
    $HumanReadable = 'MFT Export results: `n' + $ReturnedObjects
    return $DemistoResult = @{
        Type = 1;
        ContentsFormat = "json";
        Contents = $ReturnedObjects;
        EntryContext = $Context;
        ReadableContentsFormat = "markdown";
        HumanReadable = $HumanReadable
    }
}

function Main
{
    #TODO: Handle this block
    $command = $Demisto.GetCommand()
    $args = $Demisto.Args()
    $params = $Demisto.Params()
    <#
        Proxy currently isn't supported by PWSH New-Pssession, However further effort might yield an implementation,
        leaving this parameter for feature development if required.
    #>
    $no_proxy = $false
    $insecure = (ConvertTo-Boolean $params.insecure)

    try
    {
        $hostname = if ($command -eq 'test-module') {ArgToList $params.hostname } else {ArgToList $args.host}
        # ip_hosts is expected as an optional input for every command other than test-module
        $ip_hosts = args.ip
        if (-not($ip_hosts -or $ip_hosts)) {
            throw 'Please provide "hostname" or "ip"".'
        }
        # Creating Remoting client
        $cs_client = [RemotingClient]::new($params.hostname, $params.credentials.identifier, $params.credentials.password,
                                           $params.domain, $params.dns, $ip_hosts, $insecure, $no_proxy)
        # Executing command
        $Demisto.Debug("Command being called is $command")
        switch ($comand)
        {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand $cs_client $hostname
            }
            "$script:COMMAND_PREFIX-command" {
                ($human_readable, $entry_context, $raw_response) = InvokeCommandCommand $cs_client $args.command $hostname $ip_hosts
            }
            "$script:COMMAND_PREFIX-download-file" {
                $FileResult = DownloadFileCommand $cs_client $args.path $hostname $ip_hosts $args.zip_file $args.check_hash
                return
            }
            "$script:COMMAND_PREFIX-etl-create-start" {
                ($human_readable, $entry_context, $raw_response) = StartETLCommand $cs_client $hostname $ip_hosts $args.etl_path $args.etl_filter $args.etl_max_size $args.etl_time_limit $args.overwrite
            }
            "$script:COMMAND_PREFIX-etl-create-stop" {
                $Hostname = ArgToList $demisto.Args().host

                $EtlStopResult = StopETL $Hostname $IPHosts
                $demisto.Results($EtlStopResult); Break
            }
            "$script:COMMAND_PREFIX-export-registry" {
                $RegKeyHive = $demisto.Args().reg_key_hive
                $FilePath = $demisto.Args().file_path

                $result = ExportRegistry $Hostname $IPHosts $RegKeyHive $FilePath
                $demisto.Results($result); Break
            }
            "$script:COMMAND_PREFIX-upload-file" {
                $EntryId = $demisto.Args().entry_id
                $Path = $demisto.Args().path
                $ZipFile = $demisto.Args().zip_file
                $CheckHash = $demisto.Args().check_hash

                $Result = UploadFile $EntryId $Path $Hostname $IPHosts $ZipFile $CheckHash
                $demisto.Results($Result); Break
            }
            "$script:COMMAND_PREFIX-export-mft" {
                $Volume = $demisto.Args().volume
                $OutPutFilePath = $demisto.Args().output_path

                $Result = ExportMFT $Hostname $IPHosts $Volume $OutPutFilePath
                $demisto.Results($Result); Break
            }
            Default {
                $demisto.Error('Unsupported command was entered.')
            }
        }
        # Return results to Demisto Server
        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
    }
    catch
    {
        $Demisto.debug("Integration: $script:INTEGRATION_NAME Command: $command Arguments: $( $args | ConvertTo-Json ) Error: $( $_.Exception.Message )")
        if ($command -ne "test-module")
        {
            ReturnError "Error:Integration: $script:INTEGRATION_NAME Command: $command Arguments: $( $args | ConvertTo-Json ) Error: $( $_.Exception )" | Out-Null
        }
        else
        {
            ReturnError $_.Exception.Message
        }
    }
}


# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT$Test)
{
    Main
}
