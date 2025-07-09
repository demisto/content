Submit and monitor takedown requests for phishing domains, impersonating accounts, and other digital risks

## Configure SOCRadar Takedown in Cortex

| **Parameter** | **Required** |
| --- | --- |
| API Key | True |
| Company ID | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Reliability | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### socradar-submit-phishing-domain

***
Submits a takedown request for a phishing or malicious domain

#### Base Command

`socradar-submit-phishing-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The phishing domain to submit for takedown. | Required |
| abuse_type | Type of abuse (default is potential_phishing). Possible values are: potential_phishing, malware, fake_site. | Optional |
| type | Type of domain (default is phishing_domain). Possible values are: phishing_domain, malicious_domain. | Optional |
| notes | Additional information about the takedown request. | Optional |
| send_alarm | Whether to send an alarm (default is true). Possible values are: true, false. | Optional |
| email | Email to receive notifications about the takedown request. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarTakedown.PhishingDomain.Domain | string | The domain submitted for takedown |
| SOCRadarTakedown.PhishingDomain.AbuseType | string | Type of abuse |
| SOCRadarTakedown.PhishingDomain.Status | string | Status of the takedown request |
| SOCRadarTakedown.PhishingDomain.Message | string | Message returned from the API |
| SOCRadarTakedown.PhishingDomain.SendAlarm | boolean | Whether an alarm was sent |
| SOCRadarTakedown.PhishingDomain.Notes | string | Notes provided with the takedown request |

### socradar-submit-social-media-impersonation

***
Submits a takedown request for an impersonating social media account

#### Base Command

`socradar-submit-social-media-impersonation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username of the impersonating account. | Required |
| full_name | Full name shown on the impersonating account. | Required |
| account_type | Type of social media platform. Possible values are: facebook, twitter, instagram, linkedin, tiktok, youtube, other. | Required |
| description | Description or ID of the impersonation case. | Optional |
| followers | Number of followers (default is 0). | Optional |
| profile_picture | URL to the profile picture. | Optional |
| notes | Additional information about the takedown request. | Optional |
| send_alarm | Whether to send an alarm (default is false). Possible values are: true, false. | Optional |
| email | Email to receive notifications about the takedown request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarTakedown.SocialMediaImpersonation.Username | string | Username of the impersonating account |
| SOCRadarTakedown.SocialMediaImpersonation.FullName | string | Full name shown on the impersonating account |
| SOCRadarTakedown.SocialMediaImpersonation.AccountType | string | Type of social media platform |
| SOCRadarTakedown.SocialMediaImpersonation.Status | string | Status of the takedown request |
| SOCRadarTakedown.SocialMediaImpersonation.Message | string | Message returned from the API |
| SOCRadarTakedown.SocialMediaImpersonation.SendAlarm | boolean | Whether an alarm was sent |
| SOCRadarTakedown.SocialMediaImpersonation.Notes | string | Notes provided with the takedown request |

### socradar-get-takedown-progress

***
Gets the progress of a takedown request

#### Base Command

`socradar-get-takedown-progress`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The ID of the asset for which to check progress. | Required |
| type | Type of takedown request. Possible values are: phishing_domain, impersonating_accounts, source_code_leaks, rogue_mobile_apps. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarTakedown.Progress.AssetID | string | The ID of the asset |
| SOCRadarTakedown.Progress.Type | string | Type of takedown request |
| SOCRadarTakedown.Progress.Status | string | Status of the API request |
| SOCRadarTakedown.Progress.Data | unknown | Progress data returned from the API |
| SOCRadarTakedown.Progress.Message | string | Message returned from the API |

### socradar-submit-source-code-leak

***
Submits a takedown request for leaked source code

#### Base Command

`socradar-submit-source-code-leak`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the source code leak to takedown. | Required |
| notes | Additional information about the takedown request. | Optional |
| email | Email to receive notifications about the takedown request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarTakedown.SourceCodeLeak.LeakID | number | ID of the source code leak |
| SOCRadarTakedown.SourceCodeLeak.Status | string | Status of the takedown request |
| SOCRadarTakedown.SourceCodeLeak.Message | string | Message returned from the API |
| SOCRadarTakedown.SourceCodeLeak.Notes | string | Notes provided with the takedown request |
| SOCRadarTakedown.SourceCodeLeak.Email | string | Email provided for notifications |

### socradar-submit-rogue-app

***
Submits a takedown request for a rogue mobile app

#### Base Command

`socradar-submit-rogue-app`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the rogue mobile app to takedown. | Required |
| email | Email to receive notifications about the takedown request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarTakedown.RogueApp.AppID | string | ID of the rogue mobile app |
| SOCRadarTakedown.RogueApp.Status | string | Status of the takedown request |
| SOCRadarTakedown.RogueApp.Message | string | Message returned from the API |
| SOCRadarTakedown.RogueApp.Email | string | Email provided for notifications |
