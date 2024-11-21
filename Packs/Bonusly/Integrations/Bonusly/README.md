## Overview

Bonus.ly is an employee recognition platform which enterprises use to for employee recognition. We're building tools to help people feel a sense of purpose and progress at work. The platform which also has an API enables employees to recognize each other by providing a point based bonus system. Bonus.ly helps your employees feel connected, engaged, and aligned is mission critical right now. Bonusly makes employee recognition easy and fun, fostering community and creating company-wide alignment. It also provides employees with positive feedback in the work that they are doing. 

Use Cases

-Automate a bonus.ly when an employee completes an incident within the SLA time period. 
-Allow for command line bonus.ly recognitions
-Commands for bonuses like create, retrieve, update, delete



## Configure Bonusly in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. `https://bonus.ly/api/v1/` \) | True |
| api_key | API Key | True |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| application_name | Enter the name of the specific bonusly application if required. | False |
| limit | Limit the number of bonuses to fetch \(Default 20\) | False |
| user_email | Filter to receive only bonuses that match either a giver or receiver with this email. \(person@somewhere.com\) | False |
| hashtag | Filter based on a hashtag like %23teamwork | False |
| fetch_time | Start fetching from X days ago \(defaults to 1 day\) | False |
| isFetch | Fetch incidents | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bonusly-list-bonuses
***
Get a list of bonuses based on a filter


#### Base Command

`bonusly-list-bonuses`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of bonuses to retrieve (min: 1, max: 100) Default: 20. | Optional | 
| start-time | Example: 2015-10-28T21:26:50Z | Optional | 
| end-time | Example: 2015-10-28T21:26:50Z | Optional | 
| giver-email | Filter by email address of the person giving the bonusly | Optional | 
| receiver-email | Filter by email address of the person receiving the bonusly | Optional | 
| user-email | Filter to retrieve bonuses that have either giver or reciever with this email | Optional | 
| hashtag | Filter to get a list of bonusers by a hashtag Example: %23teamwork | Optional | 
| include-children | Includes any children responses to the bonusly  | Optional | 
| show-private-bonuses | If Admin API key you can list private bonuses | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bonusly.Bonus.id | String | ID of the bonusly bonus and can be used to gather further information on the bonus | 
| Bonusly.Bonus.created_at | Date | Date created IE: 2015\-10\-28T21:26:50Z | 
| Bonusly.Bonus.reason | String | Description of bonus given like For signing up for the world's favorite employee recognition solution\! \#problem\-solving | 
| Bonusly.Bonus.reason_html | String | HTML representation of the bonus | 
| Bonusly.Bonus.amount | Number | Number amount of the bonus | 
| Bonusly.Bonus.amount_with_currency | String | Amount with the points of the bonus | 
| Bonusly.Bonus.value | String | A hash tag like \#problem\-solving | 
| Bonusly.Bonus.giver.id | String | ID of the person giving the bonus | 
| Bonusly.Bonus.giver.short_name | String | Persons short name who gave the bonus | 
| Bonusly.Bonus.giver.display_name | String | Display name for who gave the bonus | 
| Bonusly.Bonus.giver.username | String | Username for who gave the bonus | 
| Bonusly.Bonus.giver.email | String | Email of the person who gave the bonus | 
| Bonusly.Bonus.giver.path | String | URL path for who gave the bonus | 
| Bonusly.Bonus.giver.full_pic_url | String | Full picture URL for who gave the bonus | 
| Bonusly.Bonus.giver.profile_pic_url | String | Profile Picture of the person who gave the bonus | 
| Bonusly.Bonus.giver.first_name | String | First name for the giver of the bonus | 
| Bonusly.Bonus.giver.last_name | String | Last name for the giver of the bonus | 
| Bonusly.Bonus.giver.last_active_at | Unknown | Last time giver was active when available | 
| Bonusly.Bonus.giver.external_unique_id | String | Unique ID for the giver externally | 
| Bonusly.Bonus.giver.budget_boost | Number | Whether there is a boost given for the bonus | 
| Bonusly.Bonus.giver.user_mode | String | Mode of the giver user | 
| Bonusly.Bonus.giver.country | String | Country of where the giver resides | 
| Bonusly.Bonus.giver.time_zone | String | Timezone for the giver America/Los\_Angeles | 
| Bonusly.Bonus.giver.*custom_property_name* | String | Any custom properties given | 
| Bonusly.Bonus.giver.can_give | Number | Whether the giver can give | 
| Bonusly.Bonus.giver.earning_balance | Number | Balance earning available | 
| Bonusly.Bonus.giver.earning_balance_with_currency | String | Earning balance with currency | 
| Bonusly.Bonus.giver.lifetime_earnings | Number | Lifetime earnings of giver overall | 
| Bonusly.Bonus.giver.lifetime_earnings_with_currency | String | Lifetime earnings of giver with currency | 
| Bonusly.Bonus.giver.can_receive | Number | Wether giver can receive or not | 
| Bonusly.Bonus.giver.giving_balance | Number | Number of balance available to give | 
| Bonusly.Bonus.giver.giving_balance_with_currency | String | Currency or points of giver balance | 
| Bonusly.Bonus.giver.status | String | Status like archived | 
| Bonusly.Bonus.receiver | Unknown | Unknown | 
| Bonusly.Bonus.child_count | Number | Cound of the child add on bonuses | 
| Bonusly.Bonus.via | String | Where the bonus came from like web etc | 
| Bonusly.Bonus.family_amount | Number | Amount family has | 


#### Command Example
```!bonusly-list-bonuses limit="20"```

#### Context Example
```
{
    "Bonusly": {
        "Bonus": [
            {
                "id": "24abcdef1234567890abcdef",
                "created_at": "2015-10-28T21:26:50Z",
                "reason": "For signing up for the world's favorite employee recognition solution! #problem-solving",
                "reason_html": "For signing up for the world&#39;s favorite employee-recognition solution! <a class=\"hashtag\" href=\"http://bonus.ly/company/hashtags/problem-solving\">#problem-solving</a>",
                "amount": 50,
                "amount_with_currency": "50 points",
                "value": "#problem-solving",
                "giver": {
                  "id": "24abcdef1234567890abcdef",
                  "short_name": "Bill",
                  "display_name": "Bill",
                  "username": "blumbergh",
                  "email": "blumbergh@initech56313d8f1ba2397878000004.com",
                  "path": "/company/users/56313d971ba23978780000c6",
                  "full_pic_url": "http://bonus.ly/avatar/blumbergh.png",
                  "profile_pic_url": "http://bonus.ly/avatar/blumbergh.png",
                  "first_name": "Bill",
                  "last_name": "Lumbergh",
                  "last_active_at": null,
                  "external_unique_id": "foo",
                  "budget_boost": 0,
                  "user_mode": "normal",
                  "country": "US",
                  "time_zone": "America/Los_Angeles",
                  "*custom_property_name*": "*custom_property_value*",
                  "can_give": true,
                  "earning_balance": 80,
                  "earning_balance_with_currency": "80 points",
                  "lifetime_earnings": 80,
                  "lifetime_earnings_with_currency": "80 points",
                  "can_receive": true,
                  "giving_balance": 42,
                  "giving_balance_with_currency": "42 points",
                  "status": "archived"
                },
                "receiver": null,
                "child_count": 42,
                "child_bonuses": [
                  {}
                ],
                "via": "web",
                "family_amount": 42
              }
        ]
    }
}
```

#### Human Readable Output

>### Latest Updates From Bonus.ly
>|amount|amount_with_currency|child_bonuses|created_at|editable_until|family_amount|giver|hashtag|id|parent_bonus_id|reason|reason_decoded|reason_html|receiver|receivers|value|via|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|


### bonusly-create-bonus
***
Creates a bonusly bonus


#### Base Command

`bonusly-create-bonus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| giver-email | The email address of the person giving the bonus like myemail@email.com | Required | 
| reason | <br/>+10 @george and @john for #execution with that customer #collaboration with the team, and #integrity on the known vulnerabilities to the application. <br/><br/>+10 @francesco because he is fast and detailed<br/> | Required | 
| parent-bonus-id | Allows you to associate to a parent bonus based on what you have created before. Example: 24abcdef1234567890abcdef | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bonusly.Bonus.id | String | ID of the bonusly bonus and can be used to gather further information on the bonus | 
| Bonusly.Bonus.created_at | Date | Date created IE: 2015\-10\-28T21:26:50Z | 
| Bonusly.Bonus.reason | String | Description of bonus given like For signing up for the world's favorite employee recognition solution\! \#problem\-solving | 
| Bonusly.Bonus.reason_html | String | HTML representation of the bonus | 
| Bonusly.Bonus.amount | Number | Number amount of the bonus | 
| Bonusly.Bonus.amount_with_currency | String | Amount with the points of the bonus | 
| Bonusly.Bonus.value | String | A hash tag like \#problem\-solving | 
| Bonusly.Bonus.giver.id | String | ID of the person giving the bonus | 
| Bonusly.Bonus.giver.short_name | String | Persons short name who gave the bonus | 
| Bonusly.Bonus.giver.display_name | String | Display name for who gave the bonus | 
| Bonusly.Bonus.giver.username | String | Username for who gave the bonus | 
| Bonusly.Bonus.giver.email | String | Email of the person who gave the bonus | 
| Bonusly.Bonus.giver.path | String | URL path for who gave the bonus | 
| Bonusly.Bonus.giver.full_pic_url | String | Full picture URL for who gave the bonus | 
| Bonusly.Bonus.giver.profile_pic_url | String | Profile Picture of the person who gave the bonus | 
| Bonusly.Bonus.giver.first_name | String | First name for the giver of the bonus | 
| Bonusly.Bonus.giver.last_name | String | Last name for the giver of the bonus | 
| Bonusly.Bonus.giver.last_active_at | Unknown | Last time giver was active when available | 
| Bonusly.Bonus.giver.external_unique_id | String | Unique ID for the giver externally | 
| Bonusly.Bonus.giver.budget_boost | Number | Whether there is a boost given for the bonus | 
| Bonusly.Bonus.giver.user_mode | String | Mode of the giver user | 
| Bonusly.Bonus.giver.country | String | Country of where the giver resides | 
| Bonusly.Bonus.giver.time_zone | String | Timezone for the giver America/Los\_Angeles | 
| Bonusly.Bonus.giver.*custom_property_name* | String | Any custom properties given | 
| Bonusly.Bonus.giver.can_give | Number | Whether the giver can give | 
| Bonusly.Bonus.giver.earning_balance | Number | Balance earning available | 
| Bonusly.Bonus.giver.earning_balance_with_currency | String | Earning balance with currency | 
| Bonusly.Bonus.giver.lifetime_earnings | Number | Lifetime earnings of giver overall | 
| Bonusly.Bonus.giver.lifetime_earnings_with_currency | String | Lifetime earnings of giver with currency | 
| Bonusly.Bonus.giver.can_receive | Number | Wether giver can receive or not | 
| Bonusly.Bonus.giver.giving_balance | Number | Number of balance available to give | 
| Bonusly.Bonus.giver.giving_balance_with_currency | String | Currency or points of giver balance | 
| Bonusly.Bonus.giver.status | String | Status like archived | 
| Bonusly.Bonus.receiver | Unknown | Unknown | 
| Bonusly.Bonus.child_count | Number | Cound of the child add on bonuses | 
| Bonusly.Bonus.via | String | Where the bonus came from like web etc | 
| Bonusly.Bonus.family_amount | Number | Amount family has | 


#### Command Example
```bonusly-get-bonus id="5ec263bb0e519c009a1ec0db"```

#### Human Readable Output



### bonusly-get-bonus
***
Get a bonusly based on an ID


#### Base Command

`bonusly-get-bonus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Id of bonus that you want to fetch  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bonusly.Bonus.id | String | ID of the bonusly bonus and can be used to gather further information on the bonus | 
| Bonusly.Bonus.created_at | Date | Date created IE: 2015\-10\-28T21:26:50Z | 
| Bonusly.Bonus.reason | String | Description of bonus given like For signing up for the world's favorite employee recognition solution\! \#problem\-solving | 
| Bonusly.Bonus.reason_html | String | HTML representation of the bonus | 
| Bonusly.Bonus.amount | Number | Number amount of the bonus | 
| Bonusly.Bonus.amount_with_currency | String | Amount with the points of the bonus | 
| Bonusly.Bonus.value | String | A hash tag like \#problem\-solving | 
| Bonusly.Bonus.giver.id | String | ID of the person giving the bonus | 
| Bonusly.Bonus.giver.short_name | String | Persons short name who gave the bonus | 
| Bonusly.Bonus.giver.display_name | String | Display name for who gave the bonus | 
| Bonusly.Bonus.giver.username | String | Username for who gave the bonus | 
| Bonusly.Bonus.giver.email | String | Email of the person who gave the bonus | 
| Bonusly.Bonus.giver.path | String | URL path for who gave the bonus | 
| Bonusly.Bonus.giver.full_pic_url | String | Full picture URL for who gave the bonus | 
| Bonusly.Bonus.giver.profile_pic_url | String | Profile Picture of the person who gave the bonus | 
| Bonusly.Bonus.giver.first_name | String | First name for the giver of the bonus | 
| Bonusly.Bonus.giver.last_name | String | Last name for the giver of the bonus | 
| Bonusly.Bonus.giver.last_active_at | Unknown | Last time giver was active when available | 
| Bonusly.Bonus.giver.external_unique_id | String | Unique ID for the giver externally | 
| Bonusly.Bonus.giver.budget_boost | Number | Whether there is a boost given for the bonus | 
| Bonusly.Bonus.giver.user_mode | String | Mode of the giver user | 
| Bonusly.Bonus.giver.country | String | Country of where the giver resides | 
| Bonusly.Bonus.giver.time_zone | String | Timezone for the giver America/Los\_Angeles | 
| Bonusly.Bonus.giver.*custom_property_name* | String | Any custom properties given | 
| Bonusly.Bonus.giver.can_give | Number | Whether the giver can give | 
| Bonusly.Bonus.giver.earning_balance | Number | Balance earning available | 
| Bonusly.Bonus.giver.earning_balance_with_currency | String | Earning balance with currency | 
| Bonusly.Bonus.giver.lifetime_earnings | Number | Lifetime earnings of giver overall | 
| Bonusly.Bonus.giver.lifetime_earnings_with_currency | String | Lifetime earnings of giver with currency | 
| Bonusly.Bonus.giver.can_receive | Number | Wether giver can receive or not | 
| Bonusly.Bonus.giver.giving_balance | Number | Number of balance available to give | 
| Bonusly.Bonus.giver.giving_balance_with_currency | String | Currency or points of giver balance | 
| Bonusly.Bonus.giver.status | String | Status like archived | 
| Bonusly.Bonus.receiver | Unknown | Unknown | 
| Bonusly.Bonus.child_count | Number | Cound of the child add on bonuses | 
| Bonusly.Bonus.via | String | Where the bonus came from like web etc | 
| Bonusly.Bonus.family_amount | Number | Amount family has | 


#### Command Example
```!bonusly-get-bonus id="24abcdef1234567890abcdef"```

#### Context Example
```
{
    "Bonusly": {
        "Bonus": {
                   "id": "24abcdef1234567890abcdef",
                   "created_at": "2015-10-28T21:26:50Z",
                   "reason": "For signing up for the world's favorite employee recognition solution! #problem-solving",
                   "reason_html": "For signing up for the world&#39;s favorite employee recognition solution! <a class=\"hashtag\" href=\"http://bonus.ly/company/hashtags/problem-solving\">#problem-solving</a>",
                   "amount": 50,
                   "amount_with_currency": "50 points",
                   "value": "#problem-solving",
                   "giver": {
                     "id": "24abcdef1234567890abcdef",
                     "short_name": "Bill",
                     "display_name": "Bill",
                     "username": "blumbergh",
                     "email": "blumbergh@initech56313d8f1ba2397878000004.com",
                     "path": "/company/users/56313d971ba23978780000c6",
                     "full_pic_url": "http://bonus.ly/avatar/blumbergh.png",
                     "profile_pic_url": "http://bonus.ly/avatar/blumbergh.png",
                     "first_name": "Bill",
                     "last_name": "Lumbergh",
                     "last_active_at": null,
                     "external_unique_id": "foo",
                     "budget_boost": 0,
                     "user_mode": "normal",
                     "country": "US",
                     "time_zone": "America/Los_Angeles",
                     "*custom_property_name*": "*custom_property_value*",
                     "can_give": true,
                     "earning_balance": 80,
                     "earning_balance_with_currency": "80 points",
                     "lifetime_earnings": 80,
                     "lifetime_earnings_with_currency": "80 points",
                     "can_receive": true,
                     "giving_balance": 42,
                     "giving_balance_with_currency": "42 points",
                     "status": "archived"
                   },
                   "receiver": null,
                   "child_count": 42,
                   "child_bonuses": [
                     {}
                   ],
                   "via": "web",
                   "family_amount": 42
                 }
    }
}
```

#### Human Readable Output

>### Latest Updates From Bonus.ly
>|amount|amount_with_currency|child_count|created_at|editable_until|family_amount|giver|hashtag|id|parent_bonus_id|reason|reason_decoded|reason_html|receiver|receivers|value|via|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|


### bonusly-update-bonus
***
Update a bonus to bonusly


#### Base Command

`bonusly-update-bonus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Id to update  | Required | 
| reason | Example +10 @francesco @bumblebee for #integrity #collaboration #execution | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bonusly.Bonus.id | String | ID of the bonusly bonus and can be used to gather further information on the bonus | 
| Bonusly.Bonus.created_at | Date | Date created IE: 2015\-10\-28T21:26:50Z | 
| Bonusly.Bonus.reason | String | Description of bonus given like For signing up for the world's favorite employee recognition solution\! \#problem\-solving | 
| Bonusly.Bonus.reason_html | String | HTML representation of the bonus | 
| Bonusly.Bonus.amount | Number | Number amount of the bonus | 
| Bonusly.Bonus.amount_with_currency | String | Amount with the points of the bonus | 
| Bonusly.Bonus.value | String | A hash tag like \#problem\-solving | 
| Bonusly.Bonus.giver.id | String | ID of the person giving the bonus | 
| Bonusly.Bonus.giver.short_name | String | Persons short name who gave the bonus | 
| Bonusly.Bonus.giver.display_name | String | Display name for who gave the bonus | 
| Bonusly.Bonus.giver.username | String | Username for who gave the bonus | 
| Bonusly.Bonus.giver.email | String | Email of the person who gave the bonus | 
| Bonusly.Bonus.giver.path | String | URL path for who gave the bonus | 
| Bonusly.Bonus.giver.full_pic_url | String | Full picture URL for who gave the bonus | 
| Bonusly.Bonus.giver.profile_pic_url | String | Profile Picture of the person who gave the bonus | 
| Bonusly.Bonus.giver.first_name | String | First name for the giver of the bonus | 
| Bonusly.Bonus.giver.last_name | String | Last name for the giver of the bonus | 
| Bonusly.Bonus.giver.last_active_at | Unknown | Last time giver was active when available | 
| Bonusly.Bonus.giver.external_unique_id | String | Unique ID for the giver externally | 
| Bonusly.Bonus.giver.budget_boost | Number | Whether there is a boost given for the bonus | 
| Bonusly.Bonus.giver.user_mode | String | Mode of the giver user | 
| Bonusly.Bonus.giver.country | String | Country of where the giver resides | 
| Bonusly.Bonus.giver.time_zone | String | Timezone for the giver America/Los\_Angeles | 
| Bonusly.Bonus.giver.*custom_property_name* | String | Any custom properties given | 
| Bonusly.Bonus.giver.can_give | Number | Whether the giver can give | 
| Bonusly.Bonus.giver.earning_balance | Number | Balance earning available | 
| Bonusly.Bonus.giver.earning_balance_with_currency | String | Earning balance with currency | 
| Bonusly.Bonus.giver.lifetime_earnings | Number | Lifetime earnings of giver overall | 
| Bonusly.Bonus.giver.lifetime_earnings_with_currency | String | Lifetime earnings of giver with currency | 
| Bonusly.Bonus.giver.can_receive | Number | Wether giver can receive or not | 
| Bonusly.Bonus.giver.giving_balance | Number | Number of balance available to give | 
| Bonusly.Bonus.giver.giving_balance_with_currency | String | Currency or points of giver balance | 
| Bonusly.Bonus.giver.status | String | Status like archived | 
| Bonusly.Bonus.receiver | Unknown | Unknown | 
| Bonusly.Bonus.child_count | Number | Cound of the child add on bonuses | 
| Bonusly.Bonus.via | String | Where the bonus came from like web etc | 
| Bonusly.Bonus.family_amount | Number | Amount family has | 


#### Command Example
```!bonusly-update-bonus id="5ec279591160850099b1ae3c" reason="Removing old archive"```

#### Human Readable Output
>|amount|amount_with_currency|child_count|created_at|editable_until|family_amount|giver|hashtag|id|parent_bonus_id|reason|reason_decoded|reason_html|receiver|receivers|value|via|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|


#### Context Example
```
{
    "Bonusly": {
        "Bonus": {
                   "id": "24abcdef1234567890abcdef",
                   "created_at": "2015-10-28T21:26:50Z",
                   "reason": "For signing up for the world's favorite employee recognition solution! #problem-solving",
                   "reason_html": "For signing up for the world&#39;s favorite employee recognition solution! <a class=\"hashtag\" href=\"http://bonus.ly/company/hashtags/problem-solving\">#problem-solving</a>",
                   "amount": 50,
                   "amount_with_currency": "50 points",
                   "value": "#problem-solving",
                   "giver": {
                     "id": "24abcdef1234567890abcdef",
                     "short_name": "Bill",
                     "display_name": "Bill",
                     "username": "blumbergh",
                     "email": "blumbergh@initech56313d8f1ba2397878000004.com",
                     "path": "/company/users/56313d971ba23978780000c6",
                     "full_pic_url": "http://bonus.ly/avatar/blumbergh.png",
                     "profile_pic_url": "http://bonus.ly/avatar/blumbergh.png",
                     "first_name": "Bill",
                     "last_name": "Lumbergh",
                     "last_active_at": null,
                     "external_unique_id": "foo",
                     "budget_boost": 0,
                     "user_mode": "normal",
                     "country": "US",
                     "time_zone": "America/Los_Angeles",
                     "*custom_property_name*": "*custom_property_value*",
                     "can_give": true,
                     "earning_balance": 80,
                     "earning_balance_with_currency": "80 points",
                     "lifetime_earnings": 80,
                     "lifetime_earnings_with_currency": "80 points",
                     "can_receive": true,
                     "giving_balance": 42,
                     "giving_balance_with_currency": "42 points",
                     "status": "archived"
                   },
                   "receiver": null,
                   "child_count": 42,
                   "child_bonuses": [
                     {}
                   ],
                   "via": "web",
                   "family_amount": 42
                 }
    }
}
```

### bonusly-delete-bonus
***
Delete a bonus based on an ID like 24abcdef1234567890abcdef


#### Base Command

`bonusly-delete-bonus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Delete a bonus based on an ID like 24abcdef1234567890abcdef | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bonusly.Bonus.message | Unknown | Message of result if deleted successfully | 


#### Command Example
```!bonusly-delete-bonus id="5ec279591160850099b1ae3c"```

#### Human Readable Output

Latest Updates From Bonus.ly
No entries.

#### Context Example
```
{
    "Bonusly": {
        "Bonus": {
            "message": "No entries"
         }
     }
}
```
=======
## Bonusly

Bonus.ly is an employee recognition platform which enterprises use to for employee recognition. We're building tools to help people feel a sense of purpose and progress at work. The platform which also has an API enables employees to recognize each other by providing a point based bonus system. Bonus.ly helps your employees feel connected, engaged, and aligned is mission critical right now. Bonusly makes employee recognition easy and fun, fostering community and creating company-wide alignment. It also provides employees with positive feedback in the work that they are doing. 