
function hardwareLinux() {
    packOutput('lshw');
}
function hardwareDarwin(){
    packOutput('system_profiler');
}
function hardwareWindows() {
    pack(wmi_query('select Name,FileSystem, FreeSpace,Size,VolumeName,VolumeSerialNumber from Win32_LogicalDisk'),'table');
    pack(wmi_query('select Description, Manufacturer, Name, SMBIOSBIOSVersion,Version from Win32_Bios'),'table');
    pack(wmi_query('select Version, SerialNumber,SocketDesignation, Name, Description, Manufacturer, AddressWidth from Win32_Processor'),'table');
    pack(wmi_query('select Manufacturer, Model, SystemType, UserName from Win32_ComputerSystem'),'table');
}
try {
    if (env.OS=== "windows") {
        hardwareWindows();
    } else if (env.OS==="linux") {
        hardwareLinux();
    } else {
        hardwareDarwin();
    }
} catch (ex) {
    pack("Error: " + ex);
}
