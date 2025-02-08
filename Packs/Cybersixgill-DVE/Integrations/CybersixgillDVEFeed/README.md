Powered by the broadest automated collection from the deep and dark web, Cybersixgill’s Dynamic Vulnerability Exploit (DVE) Score is a feed of common known vulnerabilities, scored by their probability of getting exploited. The DVE Score feed enables Cortex XSOAR users to track threats from vulnerabilities that others define as irrelevant, but have a higher probability of being exploited. It is the only solution that predicts the immediate risks of a vulnerability based on threat actors’ intent. 

DVE Score is also the most comprehensive CVE enrichment solution on the market: Cortex XSOAR users gain unparalleled context and can accelerate threat response and decision making, effectively giving security teams a head start on vulnerability management. 

·    Anticipate the exploitation of a vulnerability up to 90 days in advance
·    Track threats from CVEs that most others define as irrelevant or obsolete, but a higher probability of being exploited by active cyber threat actors.
·    Gain visibility as well as the ability to prioritize and articulate the remediation process across the organization - straight from Cortex XSOAR

To obtain access to Cybersixgill DVE Score feed via Cortex XSOAR, please contact Cybersixgill at getstarted@cybersixgill.com.

## Configure Sixgill_DVE_Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Client Id | Sixgill API client ID. | True |
| Client Secret | Sixgill API client secret. | True |
| Trust any certificate (not secure) | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at <https://us-cert.cisa.gov/tlp>  | False |
| Fetch indicators |  | False |
| Feed Fetch Interval |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Bypass exclusion list |  | False |
| Tags | Supports CSV values. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cybersixgill-get-indicators

***
Fetching Sixgill DVE Feed indicators


#### Base Command

`cybersixgill-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of records to display in War Room. Default is 5. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

``` ```

#### Human Readable Output
