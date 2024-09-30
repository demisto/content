Identify Malicious IP addresses with the CrowdSec CTI API.

## Configure CrowdSec in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Check the specified IP Address against the CrowdSec CTI.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP Address to check. | Required | 


#### Context Output

| **Path**                                                  | **Type** | **Description**                                                                                                              |
|-----------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------------------------------|
| CrowdSec.Info.ip_range_score                              | Number   | The score of the IP Range                                                                                                    | 
| CrowdSec.Info.ip                                          | String   | The IP address                                                                                                               | 
| CrowdSec.Info.ip_range                                    | String   | The IP range                                                                                                                 | 
| CrowdSec.Info.as_name                                     | String   | The AS name                                                                                                                  | 
| CrowdSec.Info.as_num                                      | Number   | The AS number                                                                                                                | 
| CrowdSec.Info.location.country                            | String   | The country of the IP                                                                                                        | 
| CrowdSec.Info.location.city                               | String   | The city of the IP                                                                                                           | 
| CrowdSec.Info.location.latitude                           | Number   | The latitude of the IP                                                                                                       | 
| CrowdSec.Info.location.longitude                          | Number   | The longitude of the IP                                                                                                      | 
| CrowdSec.Info.reverse_dns                                 | String   | The reverse DNS of the IP                                                                                                    | 
| CrowdSec.Info.behaviors                                   | Array    | List of IP behaviors                                                                                                         | 
| CrowdSec.Info.history.first_seen                          | Date     | Date of the first time this IP was reported                                                                                  | 
| CrowdSec.Info.history.last_seen                           | Date     | Date of the last time this IP was reported                                                                                   | 
| CrowdSec.Info.history.full_age                            | Number   | Delta in days between first seen and today                                                                                   | 
| CrowdSec.Info.history.days_age                            | Number   | Delta in days between first and last seen timestamps                                                                         | 
| CrowdSec.Info.classifications.classifications             | Array    | A list of categories associated with the IP. Those data can be sourced from 3rd parties \(i.e. tor exit nodes list\)         | 
| CrowdSec.Info.classifications.false_positives             | Array    | A list of false positives tags associated with the IP. Any IP with false_positives tags shouldn't be considered as malicious | 
| CrowdSec.Info.classifications.classifications.description | String   |                                                                                                                              | 
| CrowdSec.Info.attack_details                              | Array    | A more exhaustive list of the scenarios for which a given IP was reported                                                    | 
| CrowdSec.Info.target_countries                            | Object   | The top 10 reports repartition by country about the IP, as a percentage                                                      | 
| CrowdSec.Info.scores.overall.aggressiveness               | Number   | Overall aggressiveness score                                                                                                 | 
| CrowdSec.Info.scores.overall.threat                       | Number   | Overall threat score                                                                                                         | 
| CrowdSec.Info.scores.overall.trust                        | Number   | Overall trust score                                                                                                          | 
| CrowdSec.Info.scores.overall.anomaly                      | Number   | Overall anomaly score                                                                                                        | 
| CrowdSec.Info.scores.overall.total                        | Number   | Overall score                                                                                                                | 
| CrowdSec.Info.scores.last_day.aggressiveness              | Number   | Last day aggressiveness score                                                                                                | 
| CrowdSec.Info.scores.last_day.threat                      | Number   | Last day threat score                                                                                                        | 
| CrowdSec.Info.scores.last_day.trust                       | Number   | Last day trust score                                                                                                         | 
| CrowdSec.Info.scores.last_day.anomaly                     | Number   | Last day anomaly score                                                                                                       | 
| CrowdSec.Info.scores.last_day.total                       | Number   | Last day score                                                                                                               | 
| CrowdSec.Info.scores.last_week.aggressiveness             | Number   | Last week aggressiveness score                                                                                               | 
| CrowdSec.Info.scores.last_week.threat                     | Number   | Last week threat score                                                                                                       | 
| CrowdSec.Info.scores.last_week.trust                      | Number   | Last week trust score                                                                                                        | 
| CrowdSec.Info.scores.last_week.anomaly                    | Number   | Last week anomaly score                                                                                                      | 
| CrowdSec.Info.scores.last_week.total                      | Number   | Last week score                                                                                                              | 
| CrowdSec.Info.scores.last_month.aggressiveness            | Number   | Last month aggressiveness score                                                                                              | 
| CrowdSec.Info.scores.last_month.threat                    | Number   | Last month threat score                                                                                                      | 
| CrowdSec.Info.scores.last_month.trust                     | Number   | Last month trust score                                                                                                       | 
| CrowdSec.Info.scores.last_month.anomaly                   | Number   | Last month anomaly score                                                                                                     | 
| CrowdSec.Info.scores.last_month.total                     | Number   | Last month score                                                                                                             | 
| IP.Address                                                | String   | The IP Address |.                                                                                                             |
| DBotScore.Score                                           | number   | The actual score.                                                                                                            | 
| DBotScore.Vendor                                          | String   | The vendor used to calculate the score.                                                                                      | 
| DBotScore.Type                                            | String   | The indicator type.                                                                                                          | 
| DBotScore.Indicator                                       | String   | The indicator that was tested.                                                                                               | 

