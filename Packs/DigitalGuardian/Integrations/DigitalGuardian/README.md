# Digital Guardian ARC Watchlist Integration

This integration was integrated and tested with version 2.11.0 of Digital Guardian ARC

## Configure Digital Guardian in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| auth_url | auth_url | True |
| arc_url | arc_url | True |
| insecure | Allow Insecure HTTPS | False |
| client_id | client_id | True |
| client_secret | client_secret | True |
| export_profile | export_profile | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### digitalguardian-add-watchlist-entry
***
Add Watchlist Entry


##### Base Command

`digitalguardian-add-watchlist-entry`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | Watchlist Name | Required | 
| watchlist_entry | Watchlist Entry | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!digitalguardian-add-watchlist-entry watchlist_entry=playbook_test watchlist_name=atac_test```

##### Context Example
```
{}
```

##### Human Readable Output
added watchlist entry (playbook_test) to watchlist name (atac_test)

### digitalguardian-check-watchlist-entry
***
Check Watchlist Entry


##### Base Command

`digitalguardian-check-watchlist-entry`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | Watchlist Name | Required | 
| watchlist_entry | Watchlist Entry | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalGuardian.Watchlist.Found | boolean | Watchlist Found | 


##### Command Example
```!digitalguardian-check-watchlist-entry watchlist_entry=playbook_test watchlist_name=atac_test```

##### Context Example
```
{
    "DigitalGuardian": {
        "Watchlist": {
            "Found": true
        }
    }
}
```

##### Human Readable Output
Watchlist found

### digitalguardian-remove-watchlist-entry
***
Remove Watchlist Entry


##### Base Command

`digitalguardian-remove-watchlist-entry`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | Watchlist Name | Required | 
| watchlist_entry | Watchlist Entry | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!digitalguardian-remove-watchlist-entry watchlist_entry=playbook_test watchlist_name=atac_test```

##### Context Example
```
{}
```

##### Human Readable Output
removed watchlist entry (playbook_test) from watchlist name (atac_test)

### digitalguardian-add-componentlist-entry
***
Add Componentlist Entry


##### Base Command

`digitalguardian-add-componentlist-entry`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| componentlist_name | Componentlist Name | Required | 
| componentlist_entry | Componentlist Entry | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!digitalguardian-add-componentlist-entry componentlist_entry=email@example.com componentlist_name="Test - JLL - Email Address Blacklist"```

##### Context Example
```
{}
```

##### Human Readable Output
added componentlist entry (email@example.com) to componentlist name (Test - JLL - Email Address Blacklist)

### digitalguardian-check-componentlist-entry
***
Check Componentlist Entry


##### Base Command

`digitalguardian-check-componentlist-entry`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| componentlist_name | Componentlist Name | Required | 
| componentlist_entry | Componentlist Entry | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalGuardian.Componentlist.Found | boolean | Componentlist Found | 


##### Command Example
```!digitalguardian-check-componentlist-entry componentlist_entry=email@example.com componentlist_name="Test - JLL - Email Address Blacklist"```

##### Context Example
```
{
    "DigitalGuardian": {
        "Componentlist": {
            "Found": true
        }
    }
}
```

##### Human Readable Output
Componentlist found

### digitalguardian-remove-componentlist-entry
***
Remove Componentlist Entry


##### Base Command

`digitalguardian-remove-componentlist-entry`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| componentlist_name | Componentlist Name | Required | 
| componentlist_entry | Componentlist Entry | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!digitalguardian-remove-componentlist-entry componentlist_entry=email@example.com componentlist_name="Test - JLL - Email Address Blacklist"```

##### Context Example
```
{}
```

##### Human Readable Output
removed componentlist entry (email@example.com) from componentlist name (Test - JLL - Email Address Blacklist)