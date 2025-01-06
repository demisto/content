PhishTank is a free community site where anyone can submit, verify, track and share phishing data.
This integration was integrated and tested with version 1.0.1 of PhishTank.

## Configure PhishTankV2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| use_https | Use HTTPS connection | False |
| Source Reliability | Reliability of the source providing the intelligence data. | B - Usually reliable |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |
| fetchIntervalHours | Database refresh interval \(hours\) | False |



## Best Practice

When using the PhishTank V2 integration, we recommend that you use an engine to run the integration instance,
and to use different engines for different tenants.
You should open a platform feature request (FR) to request separate egress IPs for the different tenants.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### url

***
Checks the reputation of the supplied URLs.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command


`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to check the reputation of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | A list of URLs with a bad reputation. | 
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that tagged the URL as malicious. | 
| URL.Malicious.Description | String | For malicious URLs, the reason the vendor tagged the URL as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example

```!url url=hxxp://login.rakuten.co.jp.reise```

#### Human Readable Output

>### PhishTankV2 Database - URL Query

>#### Found matches for URL hxxp://login.rakuten.co.jp.reise

>|online|phish_id|submission_time|target|verification_time|verified|
>|---|---|---|---|---|---|
>| yes | 6784982 | 2020-09-27T19:04:35+00:00 | Other | 2020-09-27T19:10:20+00:00 | yes |
>
>Additional details at <http://www.phishtank.com/phish_detail.php?phish_id=6784982> 

### phishtank-reload

***
Reload PhishTank database


#### Base Command

`phishtank-reload`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!phishtank-reload```

#### Human Readable Output

>PhishTankV2 Database reloaded
><br/>Total **13181** URLs loaded



### phishtank-status

***
Show PhishTank database status


#### Base Command

`phishtank-status`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!phishtank-status```

#### Human Readable Output

>PhishTankV2 Database Status
><br/>Total **13181** URLs loaded
><br/>Last Load time **Sun Oct 04 2020 09:43:01 (UTC)**

