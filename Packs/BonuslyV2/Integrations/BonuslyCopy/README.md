The Bonusly integration is used to interact with the Bonusly platform through the API. Bonusly is an employee recognition platform which enterprises use to for employee recognition.
This integration was integrated and tested with version xx of Bonusly_copy

## Configure Bonusly_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Bonusly_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://bonus.ly/api/v1/) | True |
    | API Key | True |
    | Incident type | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Name of the specific Bonusly application (if required) | False |
    | Max. number of bonuses to fetch (Default is 20) | False |
    | Filter by user email address (given and received) | False |
    | Filter by hashtag (e.g., %23teamwork) | False |
    | Start fetching from X days ago (Defaults is 1 day) | False |
    | Fetch incidents | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bonusly-list-bonuses
***
Gets a list of bonuses based on the supplied filters.


#### Base Command

`bonusly-list-bonuses`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of bonuses to retrieve (min: 1, max: 100) Default: 20. Default is 20. | Optional | 
| start-time | The start time by which to filter returned bonuses. e.g., 2015-10-28T21:26:50Z. | Optional | 
| end-time | The end time by which to filter returned bonuses, e.g., 2015-10-28T21:26:50Z. | Optional | 
| giver-email | Email address of the bonus giver by which to filter results. | Optional | 
| receiver-email | Email address of the bonus receiver by which to filter results. | Optional | 
| user-email | Email address of the bonus giver or receiver by which to filter results. this email. | Optional | 
| hashtag | Filter to get a list of bonuses by a hashtag Example: %23teamwork. | Optional | 
| include-children | Whether to include child responses of the bonus. | Optional | 
| show-private-bonuses | Whether to show private bonuses. Requires Admin API key. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bonusly.Bonus.id | String | Bonus ID. | 
| Bonusly.Bonus.created_at | Date | Date the bonus was created \(given\), e.g., 2015-10-28T21:26:50Z. | 
| Bonusly.Bonus.reason | String | The bonus message, e.g., "For signing up for the world's favorite employee recognition solution\! \#problem-solving" | 
| Bonusly.Bonus.reason_html | String | HTML representation of the bonus. | 
| Bonusly.Bonus.amount | Number | Number of points given in the bonus. | 
| Bonusly.Bonus.amount_with_currency | String | Number and currency of points given in the bonus. | 
| Bonusly.Bonus.value | String | Hash tag included in the bonus, e.g., \#problem-solving. | 
| Bonusly.Bonus.giver.id | String | ID of the bonus giver. | 
| Bonusly.Bonus.giver.short_name | String | Short name of the bonus giver. | 
| Bonusly.Bonus.giver.display_name | String | Display name of the bonus giver. | 
| Bonusly.Bonus.giver.username | String | Username of the bonus giver. | 
| Bonusly.Bonus.giver.email | String | Email address of the bonus giver. | 
| Bonusly.Bonus.giver.path | String | URL path of the bonus giver. | 
| Bonusly.Bonus.giver.full_pic_url | String | URL path to the full picture of the bonus giver. | 
| Bonusly.Bonus.giver.profile_pic_url | String | URL path to the profile picture of the bonus giver. | 
| Bonusly.Bonus.giver.first_name | String | First name of the bonus giver. | 
| Bonusly.Bonus.giver.last_name | String | Last name of the bonus giver. | 
| Bonusly.Bonus.giver.last_active_at | Unknown | Last time the bonus giver was active when available. | 
| Bonusly.Bonus.giver.external_unique_id | String | Unique ID for the bonus giver \(external\). | 
| Bonusly.Bonus.giver.budget_boost | Number | Whether a boost was given for the bonus. | 
| Bonusly.Bonus.giver.user_mode | String | User mode of the bonus giver. | 
| Bonusly.Bonus.giver.country | String | Country where the bonus giver resides. | 
| Bonusly.Bonus.giver.time_zone | String | Timezone of the bonus giver, e.g., America/Los_Angeles. | 
| Bonusly.Bonus.giver.*custom_property_name* | String | Custom properties given in the bonus. | 
| Bonusly.Bonus.giver.can_give | Number | Whether the giver can give bonuses. | 
| Bonusly.Bonus.giver.earning_balance | Number | Available earning balance. | 
| Bonusly.Bonus.giver.earning_balance_with_currency | String | Earning balance of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.lifetime_earnings | Number | Lifetime earnings of the bonus giver. | 
| Bonusly.Bonus.giver.lifetime_earnings_with_currency | String | Lifetime earnings of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.can_receive | Boolean | Whether the bonus giver can receive bonuses. | 
| Bonusly.Bonus.giver.giving_balance | Number | Points balance of the bonus giver. | 
| Bonusly.Bonus.giver.giving_balance_with_currency | String | Points balance of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.status | String | Status of the bonus giver, e.g., archived. | 
| Bonusly.Bonus.receiver | Unknown | Bonus receiver. | 
| Bonusly.Bonus.child_count | Number | Count of the child add-on bonuses. | 
| Bonusly.Bonus.via | String | Bonus source, e.g., Web. | 
| Bonusly.Bonus.family_amount | Number | Family bonus balance. | 


#### Command Example
``` ```

#### Human Readable Output



### bonusly-create-bonus
***
Creates a Bonusly bonus.


#### Base Command

`bonusly-create-bonus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| giver-email | The email address of the bonus giver. | Required | 
| reason | The bonus message, e.g., <br/>+10 @george and @john for #execution with that customer #collaboration with the team, and #integrity on the known vulnerabilities to the application. <br/><br/>+10 @francesco because he is fast and detailed<br/>. | Required | 
| parent-bonus-id | The parent bonus ID with which to associate this bonus, e.g., 24abcdef1234567890abcdef. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bonusly.Bonus.id | String | Bonus ID. | 
| Bonusly.Bonus.created_at | Date | Date the bonus was created \(given\), e.g., 2015-10-28T21:26:50Z. | 
| Bonusly.Bonus.reason | String | The bonus message, e.g., "For signing up for the world's favorite employee recognition solution\! \#problem-solving" | 
| Bonusly.Bonus.reason_html | String | HTML representation of the bonus. | 
| Bonusly.Bonus.amount | Number | Number of points given in the bonus. | 
| Bonusly.Bonus.amount_with_currency | String | Number and currency of points given in the bonus. | 
| Bonusly.Bonus.value | String | Hash tag included in the bonus, e.g., \#problem-solving. | 
| Bonusly.Bonus.giver.id | String | ID of the bonus giver. | 
| Bonusly.Bonus.giver.short_name | String | Short name of the bonus giver. | 
| Bonusly.Bonus.giver.display_name | String | Display name of the bonus giver. | 
| Bonusly.Bonus.giver.username | String | Username of the bonus giver. | 
| Bonusly.Bonus.giver.email | String | Email address of the bonus giver. | 
| Bonusly.Bonus.giver.path | String | URL path of the bonus giver. | 
| Bonusly.Bonus.giver.full_pic_url | String | URL path to the full picture of the bonus giver. | 
| Bonusly.Bonus.giver.profile_pic_url | String | URL path to the profile picture of the bonus giver. | 
| Bonusly.Bonus.giver.first_name | String | First name of the bonus giver. | 
| Bonusly.Bonus.giver.last_name | String | Last name of the bonus giver. | 
| Bonusly.Bonus.giver.last_active_at | Unknown | Last time the bonus giver was active when available. | 
| Bonusly.Bonus.giver.external_unique_id | String | Unique ID for the bonus giver \(external\). | 
| Bonusly.Bonus.giver.budget_boost | Number | Whether a boost was given for the bonus. | 
| Bonusly.Bonus.giver.user_mode | String | User mode of the bonus giver. | 
| Bonusly.Bonus.giver.country | String | Country where the bonus giver resides. | 
| Bonusly.Bonus.giver.time_zone | String | Timezone of the bonus giver, e.g., America/Los_Angeles. | 
| Bonusly.Bonus.giver.*custom_property_name* | String | Custom properties given in the bonus. | 
| Bonusly.Bonus.giver.can_give | Number | Whether the giver can give bonuses. | 
| Bonusly.Bonus.giver.earning_balance | Number | Available earning balance | 
| Bonusly.Bonus.giver.earning_balance_with_currency | String | Earning balance of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.lifetime_earnings | Number | Lifetime earnings of the bonus giver. | 
| Bonusly.Bonus.giver.lifetime_earnings_with_currency | String | Lifetime earnings of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.can_receive | Number | Whether the bonus giver can receive bonuses. | 
| Bonusly.Bonus.giver.giving_balance | Number | Points balance of the bonus giver. | 
| Bonusly.Bonus.giver.giving_balance_with_currency | String | Points balance of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.status | String | Status of the bonus giver, e.g., archived. | 
| Bonusly.Bonus.receiver | Unknown | Bonus receiver. | 
| Bonusly.Bonus.child_count | Number | Count of the child add-on bonuses. | 
| Bonusly.Bonus.via | String | Bonus source, e.g., Web. | 
| Bonusly.Bonus.family_amount | Number | Family bonus balance. | 


#### Command Example
``` ```

#### Human Readable Output



### bonusly-get-bonus
***
Gets a bonus by bonus ID.


#### Base Command

`bonusly-get-bonus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the bonus to get information for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bonusly.Bonus.id | String | Bonus ID. | 
| Bonusly.Bonus.created_at | Date | Date the bonus was created \(given\), e.g., 2015-10-28T21:26:50Z. | 
| Bonusly.Bonus.reason | String | The bonus message, e.g., "For signing up for the world's favorite employee recognition solution\! \#problem-solving" | 
| Bonusly.Bonus.reason_html | String | HTML representation of the bonus. | 
| Bonusly.Bonus.amount | Number | Number of points given in the bonus. | 
| Bonusly.Bonus.amount_with_currency | String | Number and currency of points given in the bonus. | 
| Bonusly.Bonus.value | String | Hash tag included in the bonus, e.g., \#problem-solving. | 
| Bonusly.Bonus.giver.id | String | ID of the bonus giver. | 
| Bonusly.Bonus.giver.short_name | String | Short name of the bonus giver. | 
| Bonusly.Bonus.giver.display_name | String | Display name of the bonus giver. | 
| Bonusly.Bonus.giver.username | String | Username of the bonus giver. | 
| Bonusly.Bonus.giver.email | String | Email address of the bonus giver. | 
| Bonusly.Bonus.giver.path | String | URL path of the bonus giver. | 
| Bonusly.Bonus.giver.full_pic_url | String | URL path to the full picture of the bonus giver. | 
| Bonusly.Bonus.giver.profile_pic_url | String | URL path to the profile picture of the bonus giver. | 
| Bonusly.Bonus.giver.first_name | String | First name of the bonus giver. | 
| Bonusly.Bonus.giver.last_name | String | Last name of the bonus giver. | 
| Bonusly.Bonus.giver.last_active_at | Unknown | Last time the bonus giver was active when available. | 
| Bonusly.Bonus.giver.external_unique_id | String | Unique ID of the bonus giver \(external\). | 
| Bonusly.Bonus.giver.budget_boost | Number | Whether a boost was given for the bonus. | 
| Bonusly.Bonus.giver.user_mode | String | User mode of the bonus giver. | 
| Bonusly.Bonus.giver.country | String | Country where the bonus giver resides. | 
| Bonusly.Bonus.giver.time_zone | String | Timezone of the bonus giver, e.g., America/Los_Angeles. | 
| Bonusly.Bonus.giver.*custom_property_name* | String | Custom properties given in the bonus. | 
| Bonusly.Bonus.giver.can_give | Number | Whether the giver can give bonuses. | 
| Bonusly.Bonus.giver.earning_balance | Number | Available earning balance. | 
| Bonusly.Bonus.giver.earning_balance_with_currency | String | Earning balance of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.lifetime_earnings | Number | Lifetime earnings of the bonus giver. | 
| Bonusly.Bonus.giver.lifetime_earnings_with_currency | String | Lifetime earnings of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.can_receive | Number | Whether the bonus giver can receive bonuses. | 
| Bonusly.Bonus.giver.giving_balance | Number | Points balance of the bonus giver. | 
| Bonusly.Bonus.giver.giving_balance_with_currency | String | Points balance of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.status | String | Status of the bonus giver, e.g., archived. | 
| Bonusly.Bonus.receiver | Unknown | Bonus receiver. | 
| Bonusly.Bonus.child_count | Number | Count of the child add-on bonuses. | 
| Bonusly.Bonus.via | String | Bonus source, e.g., Web. | 
| Bonusly.Bonus.family_amount | Number | Family bonus balance. | 


#### Command Example
``` ```

#### Human Readable Output



### bonusly-update-bonus
***
Updates a bonus.


#### Base Command

`bonusly-update-bonus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the bonus to update. . | Required | 
| reason | Example +10 @francesco @bumblebee for #integrity #collaboration #execution. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bonusly.Bonus.id | String | Bonus ID. | 
| Bonusly.Bonus.created_at | Date | Date the bonus was created \(given\), e.g., 2015-10-28T21:26:50Z. | 
| Bonusly.Bonus.reason | String | The bonus message, e.g., "For signing up for the world's favorite employee recognition solution\! \#problem-solving" | 
| Bonusly.Bonus.reason_html | String | HTML representation of the bonus. | 
| Bonusly.Bonus.amount | Number | Number of points given in the bonus. | 
| Bonusly.Bonus.amount_with_currency | String | Number and currency of points given in the bonus. | 
| Bonusly.Bonus.value | String | Hash tag included in the bonus, e.g., \#problem-solving. | 
| Bonusly.Bonus.giver.id | String | ID of the bonus giver. | 
| Bonusly.Bonus.giver.short_name | String | Short name of the bonus giver. | 
| Bonusly.Bonus.giver.display_name | String | Display name of the bonus giver. | 
| Bonusly.Bonus.giver.username | String | Username of the bonus giver. | 
| Bonusly.Bonus.giver.email | String | Email address of the bonus giver. | 
| Bonusly.Bonus.giver.path | String | URL path of the bonus giver. | 
| Bonusly.Bonus.giver.full_pic_url | String | URL path to the full picture of the bonus giver. | 
| Bonusly.Bonus.giver.profile_pic_url | String | URL path to the profile picture of the bonus giver. | 
| Bonusly.Bonus.giver.first_name | String | First name of the bonus giver. | 
| Bonusly.Bonus.giver.last_name | String | Last name of the bonus giver. | 
| Bonusly.Bonus.giver.last_active_at | Unknown | Last time the bonus giver was active when available. | 
| Bonusly.Bonus.giver.external_unique_id | String | Unique ID for the bonus giver \(external\). | 
| Bonusly.Bonus.giver.budget_boost | Number | Whether a boost was given for the bonus. | 
| Bonusly.Bonus.giver.user_mode | String | User mode of the bonus giver. | 
| Bonusly.Bonus.giver.country | String | Country where the bonus giver resides. | 
| Bonusly.Bonus.giver.time_zone | String | Timezone of the bonus giver, e.g., America/Los_Angeles. | 
| Bonusly.Bonus.giver.*custom_property_name* | String | Custom properties given in the bonus. | 
| Bonusly.Bonus.giver.can_give | Number | Whether the giver can give bonuses. | 
| Bonusly.Bonus.giver.earning_balance | Number | Available earning balance. | 
| Bonusly.Bonus.giver.earning_balance_with_currency | String | Earning balance of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.lifetime_earnings | Number | Lifetime earnings of the bonus giver. | 
| Bonusly.Bonus.giver.lifetime_earnings_with_currency | String | Lifetime earnings of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.can_receive | Number | Whether the bonus giver can receive bonuses. | 
| Bonusly.Bonus.giver.giving_balance | Number | Points balance of the bonus giver. | 
| Bonusly.Bonus.giver.giving_balance_with_currency | String | Points balance of the bonus giver \(with currency\). | 
| Bonusly.Bonus.giver.status | String | Status of the bonus giver, e.g., archived. | 
| Bonusly.Bonus.receiver | Unknown | Bonus receiver. | 
| Bonusly.Bonus.child_count | Number | Count of the child add-on bonuses. | 
| Bonusly.Bonus.via | String | Bonus source, e.g., Web. | 
| Bonusly.Bonus.family_amount | Number | Family bonus balance. | 


#### Command Example
``` ```

#### Human Readable Output



### bonusly-delete-bonus
***
Deletes a bonus by bonus ID.


#### Base Command

`bonusly-delete-bonus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the bonus to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bonusly.Bonus.message | Unknown | Message | 


#### Command Example
``` ```

#### Human Readable Output


