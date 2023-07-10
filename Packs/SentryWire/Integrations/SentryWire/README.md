# Configure SentryWire on Cortex xSOAR
1. Navigate to **Settings** > **Integrations**.

2. Search for SentryWire.

3. Click **Add Instance** and configure a new integration instance.

| Parameter    | Description                                                    | Required |
|--------------|----------------------------------------------------------------|----------|
| Name         | Identifier for instance.                                       | True     |
| Unit Address | ip/hostname of SentryWire unit e.g. 1.2.3.4 or sw.example.com. | True     |
| Username     |                                                                | True     |
| Password     |                                                                | True     |

4. Click **Test** to validate connectivity to SentryWire unit.

# Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

## sentrywire-create-search
___
Create a search on the SentryWire unit using specified arguments.
### Base Command
```
sentrywire-create-search
```
### Input
| Argument      | Description                                                                                                                         | Required |
|---------------|-------------------------------------------------------------------------------------------------------------------------------------|----------|
| search_name   |                                                                                                                                     | True     |
| search_filter | KQL Search Filter                                                                                                                   | True     |
| begin_time    | The earliest date time a search should target (ISO 8601 format) UTC time - YYYY-MM-DD hh:mm:ss.                                     | True     |
| end_time      | The latest date time a search should target (ISO 8601 format) UTC time - YYYY-MM-DD hh:mm:ss.                                       | True     |
| max_packets   | Default: 0 => get all packets.                                                                                                      | False    |
| targetlist    | Controls the list of federated nodes this request is sent to. Default: send the request to all federated nodes monitored by the FM. | False    |
### Context Output
| Path                                    | Type   | Description                                             |
|-----------------------------------------|--------|---------------------------------------------------------|
| SentryWire.Investigator.Search.SearchID | String | ID of the search.                                       |
| SentryWire.Investigator.Search.NodeName | List   | List of the node ID(s) that the search was executed on. |
### Command Example
```
!sentrywire-create-search search_name="example_search" search_filter="http.client.os.name: windows AND dest_port: 8080" begin_time="2023-01-01 01:00:00" end_time="2023-01-02 01:00:00" max_packets="100"
```
### Context Example
```
{
    "SentryWire": {
        "Investigator": {
            "Search": {
                "NodeName": [
                    "exsw1",
                    "exsw2",
                    "exsw3",
                    "exsw4"
                ],
                "SearchID": "example_account_1675209608_43_example_search"
    }
}
```
### Human Readable Output
```
SearchID: example_account_1675209608_43_example_search
NodeName: exsw1, exsw2, exsw3, exsw4
```


## sentrywire-delete-search
___
Delete a previously run search from the SentryWire unit.
### Base Command
```
sentrywire-delete-search
```
### Input
| Argument | Description                                            | Required |
|----------|--------------------------------------------------------|----------|
| SearchID | ID provided by the "sentrywire-create-search" command. | True     |
### Context Output
| Path                                     | Type   | Description                      |
|------------------------------------------|--------|----------------------------------|
| SentryWire.Investigator.Deleted.SearchID | String | The ID of the search.            |
| SentryWire.Investigator.Deleted.message  | String | Message from the SentryWire unit |
### Command Example
```
!sentrywire-delete-search SearchID="example_account_1675209608_43_example_search"
```
### Context Example
```
{
    "SentryWire":{
        "Investigator": {
            "Deleted": {
                "message": "deleted search example_account_1675209608_43_example_search",
                "SearchID": "example_account_1675209608_43_example_search"
            }
        }
    }
}
```
### Human Readable Output
```
example_account_1675209608_43_example_search has been deleted!
```


## sentrywire-get-pcap
___
Download the pcap file of a search from the SentryWire unit.
### Base Command
```
sentrywire-get-pcap
```
### Input
| Argument | Description                                                | Required |
|----------|------------------------------------------------------------|----------|
| SearchID | Unique ID provided the "sentrywire-create-search" command. | True     |
| NodeName | Target node to check download PCAP from.                   | True     |
### Context Output
| Path           | Type   | Description                  |
|----------------|--------|------------------------------|
| File.Size      | Number | The size of the file.        |
| File.SHA1      | String | The SHA1 hash of the file.   |
| File.SHA256    | String | The SHA256 hash of the file. |
| File.Name      | String | The name of the file.        |
| File.SSDeep    | String | The SSDeep hash of the file. |
| File.EntryID   | String | The entry ID of the file.    |
| File.Info      | String | File information.            |
| File.Type      | String | The file type.               |
| File.MD5       | String | The MD5 hash of the file.    |
| File.Extension | String | The file extension.          |
### Command Example
```
!sentrywire-get-pcap url="https://1.2.3.4:41395/v3/fnpcaps?rest_token=abcdefgh-1234-ijkl-5678-mnopqrstuvwx&searchname=example_account_1675209608_43_example_search&nodename=ncvm1"
```
### Context Example
```
"File": {
    "EntryID": "123@456789ab-1234-cdef-5678-9ghijklmnopq",
    "Extension": "pcap",
    "Info": "application/vnd.tcpdump.pcap",
    "MD5": "e777ee76980a9e912d6464ff8bd31d06",
    "Name": "example_account_1675209608_43_example_search.pcap",
    "SHA1": "8ee5665baa5efed45293925f30aa9dafe42c916c",
    "SHA256": "59b55d37dfc0ae946238ab98aa040ab825da6d4d6b305a2cf0749f7423a102c4",
    "SHA512": "379a7696aebebc1974288ad980ec7913a9142d7a2bb630daf1f999c9c5bb24fbdd4a03047a9f6f1b69551a16deefc0f8e0395aeeaa80f9616fe9ba872ca3e8d3",
    "SSDeep": "98304:WHX0aNGsTD0ucYps10Sm+4Pz/BPrjN2h15CpzVc+:W30aM0DYys10D++zlx2h15CpzT",
    "Size": 4416449,
    "Type": "data"
}
```
### Human Readable Output
```
Uploaded file: example_account_1675209608_43_example_search.pcap
```


## sentrywire-get-metadata
___
Download the metadata of a search from the SentryWire unit
### Base Command
```
sentrywire-get-metadata
```
### Input
| Argument | Description                                                   | Required |
|----------|---------------------------------------------------------------|----------|
| SearchID | Unique ID provided the "sentrywire-create-search" command.    | True     |
| NodeName | Target node to check download ZIP (containing metadata) from. | True     |
### Context Output
| Path           | Type   | Description                  |
|----------------|--------|------------------------------|
| File.Size      | Number | The size of the file.        |
| File.SHA1      | String | The SHA1 hash of the file.   |
| File.SHA256    | String | The SHA256 hash of the file. |
| File.Name      | String | The name of the file.        |
| File.SSDeep    | String | The SSDeep hash of the file. |
| File.EntryID   | String | The entry ID of the file.    |
| File.Info      | String | File information.            |
| File.Type      | String | The file type.               |
| File.MD5       | String | The MD5 hash of the file.    |
| File.Extension | String | The file extension.          |


### Command Example
```
!sentrywire-get-metadata SearchID=example_account_1675209608_43_example_search NodeName=exsw1
```
### Context Example
```
"File": {
    "EntryID": "319@f51e3938-4446-47c4-8ced-92e7d1c02f38",
    "Extension": "zip",
    "Info": "application/zip",
    "MD5": "f9377771fe08464836db0005510ef999",
    "Name": "example_account_1675209608_43_example_search.zip",
    "SHA1": "7c85e6e36ded690a2ce72c286cd8654dbe6067fc",
    "SHA256": "59381cd490adc746b094bbc64f69ae4bd1badb355c6ade3932dd809e8b8d2e95",
    "SHA512": "1d7ce714f017481bb0be27563280772d51d3239d16c6fc74ef86808ed20ca4553a306e643557afefb0f2a73a95467054d33f6a895be8996c4383a03e5c70b5bc",
    "SSDeep": "3072:nIyYR65VdV3faJsTk0aWJ5WT4BGEbX58OQsJxbPfk2PPcYJE3nR0eXHNcR19:ndJBfRQ0n5D5wQFPflUYeR0e3WZ",
    "Size": 202477,
    "Type": "Zip archive data, at least v2.0 to extract"
}
```
### Human Readable Output
```
Uploaded file: example_account_1675209608_43_example_search.zip
```


## sentrywire-get-search-status
___
Get detailed information about a search conducted on the SentryWire unit
### Base Command
```
sentrywire-get-search-status
```
### Input
| Argument | Description                                                | Required |
|----------|------------------------------------------------------------|----------|
| SearchID | Unique ID provided the "sentrywire-create-search" command. | True     |
| NodeName | Target node to check search status.                        | True     |
### Context Output
| Path             | Type   | Description                                                                                     |
|------------------|--------|-------------------------------------------------------------------------------------------------|
| Begintime        | String | The earliest date time a search should target (ISO 8601 format) UTC time - YYYY-MM-DD hh:mm:ss. |
| Endtime          | String | The latest date time a search should target (ISO 8601 format) UTC time - YYYY-MM-DD hh:mm:ss.   |
| MaxPacketCount   | String |                                                                                                 |
| NodeName         | String | Node where status of search is being checked.                                                   |
| SearchFilter     | String | The filter being used by the search.                                                            |
| SearchID         | String | The ID of the search.                                                                           |
| SearchResult     | String | Results of the search being run.                                                                |
| SearchStatus     | String | Status of the search pending/completed/cancelled.                                               |

### Command Example
```
!sentrywire-get-search-status SearchID=example_account_1675209608_43_example_search NodeName=exsw1
```
### Context Example
Pending
```
{
    "SentryWire": {
        "Investigator": {
            "Status": {
                "Begintime": "2023-01-01 01:00:00",
                "Endtime": "2023-01-02 01:00:00",
                "MaxPacketCount": "100",
                "NodeName": "exsw1",
                "SearchFilter": "http.client.os.name: windows AND dest_port: 8080",
                "SearchStatus": "Pending",
                "SearchID": "example_account_1675209608_43_example_search"
            }
        }
    }
}
```
Completed
```
{
    "SentryWire": {
        "Investigator": {
            "Status": {
                "Begintime": "2023-02-06 07:00:00",
                "Endtime": "2023-02-07 10:00:00",
                "MaxPacketCount": "100",
                "NodeName": "exsw1",
                "SearchFilter": "http.client.os.name: windows AND dest_port: 8080",
                "SearchResult": "Pkts=114 Seconds=4 TotalSize=15KB",
                "SearchStatus": "Completed",
                "SearchID": "example_account_1675209608_43_example_search"
            }
        }
    }
}
```
Cancelled
```
{
    "SentryWire": {
        "Investigator": {
            "Status": {
                "Begintime": "2023-02-06 07:00:00",
                "Endtime": "2023-02-07 10:00:00",
                "MaxPacketCount": "100",
                "NodeName": "exsw1",
                "SearchFilter": "http.client.os.name: windows AND dest_port: 8080",
                "SearchResult": "Cancelled",
                "SearchStatus": "Pending",
                "SearchID": "example_account_1675209608_43_example_search"
            }
        }
    }
}
```
### Human Readable Output
Pending
```
Search status: Pending
```
Completed
```
Search completed: Pkts=114 Seconds=4 TotalSize=15KB
```
Cancelled
```
Search was cancelled
```