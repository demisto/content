Uses the Python pywinrm library and commands to execute either a process or using Powershell scripts.
This integration was integrated and tested with Windows Remote Management
## Configure Windows Remote Management in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Credentials |  | True |
| Default Host |  | True |
| Authentication Type |  | True |
| Realm | Default realm to use for Kerberos based authentication | False |
| Decode codec (default is utf_8) | Decode codec to use when decoding command outputs \(defaults to 'utf_8'\) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### winrm-run-process
***
Executes a command on the host


#### Base Command

`winrm-run-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The hostname to run the command on. This will override the default hostname specified in the instance. | Optional | 
| command | Command to execute. | Required | 
| arguments | Comma separate list of arguments. | Optional | 
| decode | Decode codec to use when decoding command outputs (overrides value set in the instance). Possible values are: ascii, big5, big5hkscs, cp037, cp424, cp437, cp500, cp737, cp775, cp850, cp852, cp855, cp856, cp857, cp860, cp861, cp862, cp863, cp864, cp865, cp866, cp869, cp874, cp875, cp932, cp949, cp950, cp1006, cp1026, cp1140, cp1250, cp1251, cp1252, cp1253, cp1254, cp1255, cp1256, cp1257, cp1258, euc_jp, euc_jis_2004, euc_jisx0213, euc_kr, gb2312, gbk, gb18030, hz, iso2022_jp, iso2022_jp_1, iso2022_jp_2, iso2022_jp_2004, iso2022_jp_3, iso2022_jp_ext, iso2022_kr, latin_1, iso8859_2, iso8859_3, iso8859_4, iso8859_5, iso8859_6, iso8859_7, iso8859_8, iso8859_9, iso8859_10, iso8859_13, iso8859_14, iso8859_15, johab, koi8_r, koi8_u, mac_cyrillic, mac_greek, mac_iceland, mac_latin2, mac_roman, mac_turkish, ptcp154, shift_jis, shift_jis_2004, shift_jisx0213, utf_16, utf_16_be, utf_16_le, utf_7, utf_8. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WinRM.Process | unknown | Process object of the WinRM command | 
| WinRM.Process.Output | unknown | STDOUT of the WinRM command | 
| WinRM.Process.Error | unknown | STDERR of the WinRM command | 
| WinRM.Process.Status | unknown | Status code of the WInRM command | 

#### Context Example
```
"WinRM": {
    "Process": {
        "Error": "#SomeError",
        "Output": "Hello DBot!",
        "Status": 0
    }
}
```

#### Command Example
```
!winrm-run-process command=`HelloWorldProcess` arguments="DBot"
```

#### Human Readable Output
"Hello DBot!"


### winrm-run-powershell
***
Executes a Powershell script on the endpoint


#### Base Command

`winrm-run-powershell`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The hostname to run the command on. This will override the default hostname specified in the instance. | Optional | 
| entryID | The entry ID of the powershell script to run (overrides scriptname and script). | Optional | 
| script | The powershell script to execute (requires code, not a file input). | Optional | 
| scriptname | Name of the script (optional). | Optional | 
| decode | Decode codec to use when decoding command outputs (overrides value set in the instance). Possible values are: ascii, big5, big5hkscs, cp037, cp424, cp437, cp500, cp737, cp775, cp850, cp852, cp855, cp856, cp857, cp860, cp861, cp862, cp863, cp864, cp865, cp866, cp869, cp874, cp875, cp932, cp949, cp950, cp1006, cp1026, cp1140, cp1250, cp1251, cp1252, cp1253, cp1254, cp1255, cp1256, cp1257, cp1258, euc_jp, euc_jis_2004, euc_jisx0213, euc_kr, gb2312, gbk, gb18030, hz, iso2022_jp, iso2022_jp_1, iso2022_jp_2, iso2022_jp_2004, iso2022_jp_3, iso2022_jp_ext, iso2022_kr, latin_1, iso8859_2, iso8859_3, iso8859_4, iso8859_5, iso8859_6, iso8859_7, iso8859_8, iso8859_9, iso8859_10, iso8859_13, iso8859_14, iso8859_15, johab, koi8_r, koi8_u, mac_cyrillic, mac_greek, mac_iceland, mac_latin2, mac_roman, mac_turkish, ptcp154, shift_jis, shift_jis_2004, shift_jisx0213, utf_16, utf_16_be, utf_16_le, utf_7, utf_8. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WinRM.Powershell.Output | unknown | STDOUT of the WinRM command | 
| WinRM.Powershell.Error | unknown | STDERR of the WinRM command | 
| WinRM.Powershell.Status | unknown | Status code of the WInRM command | 

#### Context Example
```
"WinRM": {
    "Script": {
        "error": "#SomeError",
        "hostname": 8.8.8.8,
        "output": "Hello, World!"
    }
    "script": "Hello",
    "status": 0
}
```

#### Command Example
```
!winrm-run-powershell script=`Write-Host "Hello, World!"` scriptname="Hello"
```

#### Human Readable Output
Hello, World!
