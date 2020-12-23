Sixgill's premium underground intelligence collection capabilities, real-time collection and advanced warning about IOCs to help you keep your edge against unknown threats.
This integration was integrated and tested with version 0.1.6 of sixgill clients
## Configure Sixgill_Darkfeed on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Sixgill DarkFeed Threat Intelligence.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| client_id | Sixgill API client ID. | True |
| client_secret | Sixgill API client secret. | True |
| feed | Fetch indicators. | False |
| feedReputation | The reputation to apply to the fetched indicators. | False |
| feedReliability | The reliability of the this feed. | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| maxIndicators | The maximum number of indicators to fetch. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### Fetch indicators
***
Fetching Sixgill DarkFeed indicators
##### Required Permissions
 - A valid Sixgill API client id and client secret.
##### Base Command

`sixgill-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!sixgill-get-indicators ```

##### Human Readable Output

### Indicators from Sixgill Dark Feed:
|value|type|rawJSON|score|
|---|---|---|---|
| https://dropmefiles.com/TgvuH | URL | `created: 2020-02-06T10:03:54.091Z description: Malware available for download from file-sharing sites external_reference: {'description': 'Mitre attack tactics and technique reference', 'mitre_attack_tactic': 'Build Capabilities', 'mitre_attack_tactic_id': 'TA0024', 'mitre_attack_tactic_url': 'https://attack.mitre.org/tactics/TA0024/', 'mitre_attack_technique': 'Obtain/re-use payloads', 'mitre_attack_technique_id': 'T1346', 'mitre_attack_technique_url': 'https://attack.mitre.org/techniques/T1346/', 'source_name': 'mitre-attack'} id: indicator--7a39257a-83d4-4f39-90d1-5b81ce1156e9 labels: malicious-activity, malware, Build Capabilities, Obtain/re-use payloads lang: en modified: 2020-02-06T10:03:54.091Z object_marking_refs: marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4, marking-definition--f88d31f6-486f-44da-b317-01333bde0b82 pattern: [url:value = 'https://dropmefiles.com/TgvuH'] sixgill_actor: vvv555 sixgill_confidence: 80 sixgill_feedid: darkfeed_010 sixgill_feedname: malware_download_urls sixgill_postid: 2f1dcc205421d20a4038b9f51b9d2c5b0b7451d1 sixgill_posttitle: SOCKS  socks4 sixgill_severity: 80 sixgill_source: forum_bhf spec_version: 2.0 type: indicator valid_from: 2020-01-06T03:00:59Z` | 3 |

### Output:
```[{
'value': 'https://dropmefiles.com/TgvuH', 
'type': 'URL', 
'rawJSON': 
    {'created': '2020-02-06T10:03:54.091Z', 
    'description': 'Malware available for download from file-sharing sites', 
    'external_reference': [{
        'description': 'Mitre attack tactics and technique reference', 
        'mitre_attack_tactic': 'Build Capabilities', 
        'mitre_attack_tactic_id': 'TA0024', 
        'mitre_attack_tactic_url': 'https://attack.mitre.org/tactics/TA0024/', 
        'mitre_attack_technique': 'Obtain/re-use payloads', 
        'mitre_attack_technique_id': 'T1346', 
        'mitre_attack_technique_url': 'https://attack.mitre.org/techniques/T1346/', 
        'source_name': 'mitre-attack'
        }], 
    'id': 'indicator--7a39257a-83d4-4f39-90d1-5b81ce1156e9', 
    'labels': ['malicious-activity', 'malware', 'Build Capabilities', 'Obtain/re-use payloads'], 
    'lang': 'en', 
    'modified': '2020-02-06T10:03:54.091Z', 
    'object_marking_refs': [
        'marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4', 
        'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'
        ], 
    'pattern': "[url:value = 'https://dropmefiles.com/TgvuH']", 
    'sixgill_actor': 'vvv555', 
    'sixgill_confidence': 80, 
    'sixgill_feedid': 'darkfeed_010', 
    'sixgill_feedname': 'malware_download_urls', 
    'sixgill_postid': '2f1dcc205421d20a4038b9f51b9d2c5b0b7451d1', 
    'sixgill_posttitle': 'SOCKS  socks4', 
    'sixgill_severity': 80, 
    'sixgill_source': 'forum_bhf', 
    'spec_version': '2.0', 
    'type': 'indicator', 
    'valid_from': '2020-01-06T03:00:59Z'
    }, 
'fields': {
    'source': 'forum_bhf', 
    'name': 'malware_download_urls', 
    'description': "description: Malware available for download from file-sharing sites\n
    feedid: darkfeed_010\n
    title: SOCKS  socks4\n
    post_id: 2f1dcc205421d20a4038b9f51b9d2c5b0b7451d1\n
    actor: vvv555\nlang: en\n
    labels: ['malicious-activity', 'malware', 'Build Capabilities', 'Obtain/re-use payloads']\n
    external_reference: [{'description': 'Mitre attack tactics and technique reference', 
    'mitre_attack_tactic': 'Build Capabilities', 
    'mitre_attack_tactic_id': 'TA0024', 
    'mitre_attack_tactic_url': 'https://attack.mitre.org/tactics/TA0024/', 
    'mitre_attack_technique': 'Obtain/re-use payloads', 
    'mitre_attack_technique_id': 'T1346', 
    'mitre_attack_technique_url': 'https://attack.mitre.org/techniques/T1346/', 
    'source_name': 'mitre-attack'}]"}, 
    'score': 3
}]```

## Additional Information
Contact us: sales@cybersixgill.com

