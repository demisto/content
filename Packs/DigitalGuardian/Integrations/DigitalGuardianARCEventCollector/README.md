This is the Digital Guardian ARC event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 3.10.0 of DigitalGuardianARCEventCollector

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Known Limitations

- By default, a maximum of **10,000** events can be retrieved per fetch for each Digital Guardian export profile. To increase the volume of fetched events beyond this value, set the "Number of Export Requests per Fetch" configuration parameter to greater than 1. For example, setting this parameter to 4 would fetch up to 40,000 events per export profile. Note that fetching a large number of events may result in exceeding the daily data ingestion quota in the Cortex XSIAM license plan.

- Events are fetched starting from the **Last Exported Record** timestamp of the export profile. When first configuring the event collector, it is highly recommended to adjust the value of this field in the selected export profile(s) to a recent timestamp to prevent the fetching of outdated events.

    If older events are still being fetched from the export profile despite updating this setting, you may need to contact [Digital Guardian Support](https://www.digitalguardian.com/services/support).

## Configure Digital Guardian ARC Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Auth Server URL (e.g. https://some_url.com) |  | True |
| Gateway Base URL (e.g. https://some_url.com) |  | True |
| Client ID |  | True |
| Client Secret | Client Secret | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Export Profiles | Internal document names or GUIDs of the Digital Guardian ARC export profiles. Custom export profiles are not officially supported. Default is defaultExportProfile. | True |
| Number of Export Requests per Fetch | Number of API calls per fetch to export events for each configured Digital Guardian ARC export profile. Use with extreme caution as this might impact data ingestion quota limits and performance. Consult with the engineering team before changing this value. Default is 1. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### digital-guardian-get-events

***
Gets events from the configured Digital Guardian ARC export profiles. This command is intended for development and debugging purposes and should be used with caution as it may create duplicate events.

#### Base Command

`digital-guardian-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum results to return per export profile. Default is 1000. | Optional | 

#### Command Example

```!digital-guardian-get-events limit=2 should_push_events=false```

#### Context Output

There is no context output for this command.

#### Human Readable Output

>### Events for Profile defaultExportProfile
>
>|dg_agent_version|dg_display|dg_file_size|dg_first|dg_guid|dg_hc|dg_machine_name|dg_machine_type|dg_mid|dg_parent_name|dg_processed_time|dg_src_dir|dg_src_file_ext|dg_src_file_name|dg_time|dg_utype|dg_wdb|dg_wrv|pi_nda|uad_sfc|
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
>| 7.9.4.0026 | Discovery Event | 51 B | True | 4a2c2692-044c-4f53-ac9b-f0fbd3b0ef3b | Yes | examplecompany\srt-test-dp1 | Windows | ffcd1683-7f92-1fd2-fb23-c16ff063bfb4 | (unknown) | 2024-12-11 04:37:16 PM | c:\windows\servicing\lcu\ouppolicy_resources\ | adml | autoplay.adml | 2024-12-11 04:37:16 PM | Discovery Event | No | No | No | Yes |
>| 7.9.4.0026 | Discovery Event | 27.5 KB | True | d343c704-7b1f-43c3-b558-178d7780fcd3 | Yes | examplecompany\srt-test-dp1 | Windows | ffcd1683-7f92-1fd2-fb23-c16ff063bfb4 | (unknown) | 2024-12-11 04:37:16 PM | c:\windows\servicing\lcu\package_for_rollupfix\ | dll | settingshandlers_user.dll | 2024-12-11 04:37:16 PM | Discovery Event | No | No | No | Yes |
