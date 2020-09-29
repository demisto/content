. $PSScriptRoot\CommonServerPowerShell.ps1
$global:DOMAIN = If ($demisto.Params().domain) {"." + $demisto.Params().domain} Else {""}
$global:HOSTNAME = $demisto.Params().hostname
$global:USERNAME = $demisto.Params().credentials.identifier
$global:PASSWORD = $demisto.Params().credentials.password
$global:DNS = $demisto.Params().dns
$global:COMMAND = $demisto.GetCommand()

if($global:DNS) {
    "nameserver $global:DNS" | Set-Content -Path \etc\resolv.conf
}

function CreateSession ($Hostname, $IPHosts)
{
    <#
    .Description
    Creates a session to target machine using hostname, username and password
    #>
    $user = $global:USERNAME
    $password=ConvertTo-SecureString $global:PASSWORD –asplaintext –force
    $fqdn = $Hostname | ForEach-Object -Process {$_ + $global:DOMAIN}
    if($IPHosts) {
        if($fqdn -and ($fqdn.GetType().fullname -eq 'System.String')) {
            $x = [System.Collections.ArrayList]::new()
            $x += $fqdn
            $fqdn = $x + $IPHosts
        }
        else {
            $fqdn += $IPHosts
        }
    }
    $Creds = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $password
    $Session = New-PSSession -ComputerName $fqdn -Authentication Negotiate -credential $Creds -ErrorAction Stop
    return $Session
}

function InvokeCommand ($Command, $Hostname, $IPHosts)
{
    <#
    .Description
    Runs invoke-command on existing session.
    .Example
    Get-Process powershell
    #>
    $Title = "Result for PowerShell Remote Command: $Command `n"
    $Session = CreateSession $Hostname $IPHosts
    $Result = InvokeCommandInSession $Command $Session
    $Session | Remove-PSsession
    $EntryContext = [PSCustomObject]@{Command = $Command;Result = $Result}
    $Context = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{Command=$EntryContext}
    }
    $Contents = $Title + $Result

    $DemistoResult = @{
        Type = 1;
        ContentsFormat = "json";
        Contents = $Contents;
        EntryContext = $Context;
        ReadableContentsFormat = "markdown";
        HumanReadable = $Contents
    }
    return $DemistoResult
}

function InvokeCommandInSession ($Command, $Session)
{
    $Temp = $demisto.UniqueFile()
    $FileName = $demisto.Investigation().id + "_" + $Temp + ".ps1"
    echo $Command | Out-File -FilePath $FileName
    return Invoke-Command $Session -FilePath $FileName
}

function DownloadFile ($Path, $Hostname, $IPHosts, $ZipFile, $CheckHash)
{
    $Temp = $demisto.UniqueFile()
    $FileName = $demisto.Investigation().id + "_" + $Temp
    $Session = CreateSession $Hostname $IPHosts
    $Command = '[System.IO.File]::Exists("' + $Path + '")'
    $Result = InvokeCommandInSession $Command $Session
    if(-Not $Result) {
        $Session | Remove-PSsession
        ReturnError($Path + " was not found on the remote host.")
        exit(0)
    }

    if($ZipFile -eq 'true') {
        $OldPath = $Path
        $Path = $Path + ".zip"
        $command = 'Compress-Archive -Path ' + $OldPath + ' -Update -DestinationPath ' + $Path
        InvokeCommandInSession $command $Session
    }
    if($CheckHash -eq 'true') {
         $command = '(Get-FileHash ' + $Path + ' -Algorithm MD5).Hash'
         $SrcHash = InvokeCommandInSession $command $Session
    }
    Copy-Item -FromSession $Session $Path -Destination $FileName
    if($ZipFile -eq 'true') {
        $command = 'Remove-Item ' + $Path
        InvokeCommandInSession $command $Session
    }
    $Session | Remove-PSsession
    if($CheckHash -eq 'true') {
         $DstHash = (Get-FileHash $FileName -Algorithm MD5).Hash
         if($SrcHash -ne $DstHash) {
            ReturnError('Failed check_hash: The downloaded file has a different hash than the file in the host. RemoteHostHash=' + $SrcHash + ' DownloadedHash=' + $DstHash)
            exit(0)
         }
    }
    $FileNameLeaf = Split-Path $Path -leaf

    $DemistoResult = @{
       Type = 3;
       ContentsFormat = "text";
       Contents = "";
       File = $FileNameLeaf;
       FileID = $Temp
    }
    $demisto.Results($DemistoResult)

    $FileExtension = [System.IO.Path]::GetExtension($FileNameLeaf)
    $FileExtension = If ($FileExtension) {$FileExtension.SubString(1, $FileExtension.length - 1)} else {""}

    $EntryContext = [PSCustomObject]@{
        PsRemoteDownloadedFile = [PSCustomObject]@{
            FileName = $FileNameLeaf;
            FileSize = Get-Item $FileName | % {[math]::ceiling($_.length / 1kb)};
            FileSHA1 = (Get-FileHash $FileName -Algorithm SHA1).Hash;
            FileSHA256 = (Get-FileHash $FileName -Algorithm SHA256).Hash;
            FileMD5 = (Get-FileHash $FileName -Algorithm MD5).Hash;
            FileExtension = $FileExtension
          }
    }
    return $DemistoResult = @{
       Type = 1;
       ContentsFormat = "text";
       Contents = "";
       EntryContext = $EntryContext;
    }
}

function StartETL ($Hostname, $IPHosts, $EtlPath, $EtlFilter, $EtlMaxSize, $EtlTimeLim, $Overwrite)
{
    $Title = "You have executed the start ETL command successfully `n"
    $Command = 'netsh trace start capture=yes traceFile=' + $EtlPath + ' maxsize=' + $EtlMaxSize + ' overwrite=' + $Overwrite + ' ' + $EtlFilter
    $Session = CreateSession $Hostname $IPHosts
    $Contents = InvokeCommandInSession $Command $Session
    $Session | Remove-PSsession
    $EntryContext = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{CommandResult = $Contents; EtlFilePath = $EtlPath; EtlFileName = Split-Path $EtlPath -leaf}
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

function StopETL ($Hostname, $IPHosts)
{
    $Command = 'netsh trace stop'
    $Session = CreateSession $Hostname $IPHosts
    $Contents = InvokeCommandInSession $Command $Session
    $Session | Remove-PSsession
    $EtlPath = echo $Contents | Select-String -Pattern "File location = "
    if($EtlPath) {
        $EtlPath = $EtlPath.ToString()
        $EtlPath = $EtlPath.Substring(16, $EtlPath.Length - 16)
    } else {
        $EtlPath = ""
    }
    if($Contents) {
        $Contents = [string]$Contents
    }
    $EntryContext = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{CommandResult = $Contents; EtlFilePath = $EtlPath; EtlFileName = If ($EtlPath) {Split-Path $EtlPath -leaf} else {""}}
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

function ExportRegistry ($Hostname, $IPHosts, $RegKeyHive, $FilePath)
{
    $command = If ($RegKeyHive -eq 'all') {'regedit /e '} Else {'reg export ' + $RegKeyHive + ' '}
    $command = $command + $FilePath
    $Title = "Ran Export Registry. `n"
    $Session = CreateSession $Hostname $IPHosts
    $Contents = InvokeCommandInSession $Command $Session
    $EntryContext = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{CommandResult = $Contents; RegistryFilePath = $FilePath; RegistryFileName = Split-Path $FilePath -leaf}
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

function UploadFile ($EntryId, $DstPath, $Hostname, $IPHosts, $ZipFile, $CheckHash)
{
    $Session = CreateSession $Hostname $IPHosts
    $SrcPath = $demisto.GetFilePath($EntryId).path
    if($ZipFile -eq 'true') {
        $OldPath = $SrcPath
        $SrcPath = $SrcPath + ".zip"
        Compress-Archive -Path $OldPath -Update -DestinationPath $SrcPath
    }
    if($CheckHash -eq 'true') {
         $SrcHash = (Get-FileHash $SrcPath -Algorithm MD5).Hash
    }
    Copy-Item -ToSession $Session $SrcPath -Destination $DstPath
    if($CheckHash -eq 'true') {
         $command = '(Get-FileHash ' + $DstPath + ' -Algorithm MD5).Hash'
         $DstHash = InvokeCommandInSession $command $Session
         if($SrcHash -ne $DstHash) {
            ReturnError('Failed check_hash: The uploaded file has a different hash than the local file. LocalFileHash=' + $SrcHash + ' UploadedFileHash=' + $DstHash)
            exit(0)
         }
    }
    $Session | Remove-PSsession

    $FileNameLeaf = Split-Path $SrcPath -leaf
    $FileExtension = [System.IO.Path]::GetExtension($FileNameLeaf)
    $FileExtension = If ($FileExtension) {$FileExtension.SubString(1, $FileExtension.length - 1)} else {""}

    $EntryContext = [PSCustomObject]@{
        PsRemoteDownloadedFile = [PSCustomObject]@{
            FileName = $FileNameLeaf;
            FileSize = Get-Item $SrcPath | % {[math]::ceiling($_.length / 1kb)};
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

function ExportMFT ($Hostname, $IPHosts, $Volume, $OutPutFilePath)
{
    $RemoteScriptBlock = {
        Param($Volume, $OutPutFilePath)

        if ($Volume -ne 0) {
            $Win32_Volume = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter LIKE '$($Volume):'"
            if ($Win32_Volume.FileSystem -ne "NTFS") {
                Write-Error "$Volume is not an NTFS filesystem."
                break
            }
        }
        else {
            $Win32_Volume = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter LIKE '$($env:SystemDrive)'"
            if ($Win32_Volume.FileSystem -ne "NTFS") {
                Write-Error "$env:SystemDrive is not an NTFS filesystem."
                break
            }
        }
        if(-not $OutputFilePath) {
            $OutputFilePath = $env:TEMP + "\$([IO.Path]::GetRandomFileName())"
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
            [Type[]]@([String], [Int32], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr]),
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
        if ($Volume -ne 0) { $VolumeHandle = $Kernel32::CreateFile(('\\.\' + $Volume + ':'), $GENERIC_READWRITE, $FILE_SHARE_READWRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero) }
        else {
            $VolumeHandle = $Kernel32::CreateFile(('\\.\' + $env:SystemDrive), $GENERIC_READWRITE, $FILE_SHARE_READWRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
            $Volume = ($env:SystemDrive).TrimEnd(':')
        }

        if ($VolumeHandle -eq -1) {
            Write-Error "Unable to obtain read handle for volume."
            break
        }

        # Create a FileStream to read from the volume handle
        $FileStream = New-Object IO.FileStream($VolumeHandle, [IO.FileAccess]::Read)

        # Read VBR from volume
        $VolumeBootRecord = New-Object Byte[](512)
        if ($FileStream.Read($VolumeBootRecord, 0, $VolumeBootRecord.Length) -ne 512) { Write-Error "Error reading volume boot record." }

        # Parse MFT offset from VBR and set stream to its location
        $MftOffset = [Bitconverter]::ToInt32($VolumeBootRecord[0x30..0x37], 0) * 0x1000
        $FileStream.Position = $MftOffset

        # Read MFT's file record header
        $MftFileRecordHeader = New-Object byte[](48)
        if ($FileStream.Read($MftFileRecordHeader, 0, $MftFileRecordHeader.Length) -ne $MftFileRecordHeader.Length) { Write-Error "Error reading MFT file record header." }

        # Parse values from MFT's file record header
        $OffsetToAttributes = [Bitconverter]::ToInt16($MftFileRecordHeader[0x14..0x15], 0)
        $AttributesRealSize = [Bitconverter]::ToInt32($MftFileRecordHeader[0x18..0x21], 0)

        # Read MFT's full file record
        $MftFileRecord = New-Object byte[]($AttributesRealSize)
        $FileStream.Position = $MftOffset
        if ($FileStream.Read($MftFileRecord, 0, $MftFileRecord.Length) -ne $AttributesRealSize) { Write-Error "Error reading MFT file record." }

        # Parse MFT's attributes from file record
        $Attributes = New-object byte[]($AttributesRealSize - $OffsetToAttributes)
        [Array]::Copy($MftFileRecord, $OffsetToAttributes, $Attributes, 0, $Attributes.Length)

        # Find Data attribute
        $CurrentOffset = 0
        do {
            $AttributeType = [Bitconverter]::ToInt32($Attributes[$CurrentOffset..$($CurrentOffset + 3)], 0)
            $AttributeSize = [Bitconverter]::ToInt32($Attributes[$($CurrentOffset + 4)..$($CurrentOffset + 7)], 0)
            $CurrentOffset += $AttributeSize
        } until ($AttributeType -eq 128)

        # Parse data attribute from all attributes
        $DataAttribute = $Attributes[$($CurrentOffset - $AttributeSize)..$($CurrentOffset - 1)]

        # Parse MFT size from data attribute
        $MftSize = [Bitconverter]::ToUInt64($DataAttribute[0x30..0x37], 0)

        # Parse data runs from data attribute
        $OffsetToDataRuns = [Bitconverter]::ToInt16($DataAttribute[0x20..0x21], 0)
        $DataRuns = $DataAttribute[$OffsetToDataRuns..$($DataAttribute.Length -1)]

        # Convert data run info to string[] for calculations
        $DataRunStrings = ([Bitconverter]::ToString($DataRuns)).Split('-')

        # Setup to read MFT
        $FileStreamOffset = 0
        $DataRunStringsOffset = 0
        $TotalBytesWritten = 0
        $MftData = New-Object byte[](0x1000)
        $OutputFileStream = [IO.File]::OpenWrite($OutputFilePath)

        do {
            $StartBytes = [int]($DataRunStrings[$DataRunStringsOffset][0]).ToString()
            $LengthBytes = [int]($DataRunStrings[$DataRunStringsOffset][1]).ToString()

            $DataRunStart = "0x"
            for ($i = $StartBytes; $i -gt 0; $i--) { $DataRunStart += $DataRunStrings[($DataRunStringsOffset + $LengthBytes + $i)] }

            $DataRunLength = "0x"
            for ($i = $LengthBytes; $i -gt 0; $i--) { $DataRunLength += $DataRunStrings[($DataRunStringsOffset + $i)] }

            $FileStreamOffset += ([int]$DataRunStart * 0x1000)
            $FileStream.Position = $FileStreamOffset

            for ($i = 0; $i -lt [int]$DataRunLength; $i++) {
                if ($FileStream.Read($MftData, 0, $MftData.Length) -ne $MftData.Length) {
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
            NetworkPath = "\\$($env:COMPUTERNAME)\C$\$($OutputFilePath.TrimStart('C:\'))"
            ComputerName = $env:COMPUTERNAME
            'MFT Size' = "$($MftSize / 1024 / 1024) MB"
            'MFT Volume' = $Volume
            'MFT File' = $OutputFilePath
        }
        New-Object -TypeName PSObject -Property $Properties
    }
    $Session = CreateSession $Hostname $IPHosts
    $ReturnedObjects = Invoke-Command -Session $Session -ScriptBlock $RemoteScriptBlock -ArgumentList @($Volume, $OutPutFilePath)
    $Session | Remove-PSsession

    $ReturnedObjects = $ReturnedObjects | Add-Member -NotePropertyMembers @{Host=($Hostname + $IPHosts)} -PassThru
    $Context = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{ExportMFT=$ReturnedObjects}
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

$demisto.Info("Current command is: " + $global:COMMAND)

$Hostname = if($global:COMMAND -eq 'test-module') {ArgToList $global:HOSTNAME} else {ArgToList $demisto.Args().host}
$IPHosts = ArgToList $demisto.Args().ip

if(-not ($Hostname -or $IPHosts)) {
    ReturnError('Please provide either a host name or host ip address.')
}
else {
    switch -Exact ($global:COMMAND)
    {
        'test-module' {
            $Hostname = ArgToList $global:HOSTNAME
            $TestConnection = InvokeCommand '$PSVersionTable' $Hostname
            $demisto.Results('ok'); Break
        }
        'ps-remote-command' {
            $Command = $demisto.Args().command

            $RunCommand = InvokeCommand $Command $Hostname $IPHosts
            $demisto.Results($RunCommand); Break
        }
        'ps-remote-download-file' {
            $Path = $demisto.Args().path
            $ZipFile = $demisto.Args().zip_file
            $CheckHash = $demisto.Args().check_hash

            $FileResult = DownloadFile $Path $Hostname $IPHosts $ZipFile $CheckHash
            $demisto.Results($FileResult); Break
        }
        'ps-remote-etl-create-start' {
            $EtlPath = $demisto.Args().etl_path
            $EtlFilter = $demisto.Args().etl_filter
            $EtlMaxSize = $demisto.Args().etl_max_size
            $EtlTimeLim = $demisto.Args().etl_time_limit
            $Overwrite = $demisto.Args().overwrite

            $EtlStartResult = StartETL $Hostname $IPHosts $EtlPath $EtlFilter $EtlMaxSize $EtlTimeLim $Overwrite
            $demisto.Results($EtlStartResult); Break
        }
        'ps-remote-etl-create-stop' {
            $Hostname = ArgToList $demisto.Args().host

            $EtlStopResult = StopETL $Hostname $IPHosts
            $demisto.Results($EtlStopResult); Break
        }
        'ps-remote-export-registry' {
            $RegKeyHive = $demisto.Args().reg_key_hive
            $FilePath = $demisto.Args().file_path

            $result = ExportRegistry $Hostname $IPHosts $RegKeyHive $FilePath
            $demisto.Results($result); Break
        }
        'ps-remote-upload-file' {
            $EntryId = $demisto.Args().entry_id
            $Path = $demisto.Args().path
            $ZipFile = $demisto.Args().zip_file
            $CheckHash = $demisto.Args().check_hash

            $Result = UploadFile $EntryId $Path $Hostname $IPHosts $ZipFile $CheckHash
            $demisto.Results($Result); Break
        }
        'ps-remote-export-mft' {
            $Volume = $demisto.Args().volume
            $OutPutFilePath = $demisto.Args().output_path

            $Result = ExportMFT $Hostname $IPHosts $Volume $OutPutFilePath
            $demisto.Results($Result); Break
        }
        Default {
            $demisto.Error('Unsupported command was entered.')
        }
    }
}
