
### mantis-get-issue-by-id

***
get details of the mantis issue

#### Base Command

`mantis-get-issue-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Mantis issue to get details of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mantis.Issue.id | String | id ofthe issue created | 
| Mantis.Issue.project | Unknown | project under which issue is created | 
| Mantis.Issue.category | Unknown | category under which issue is created | 
| Mantis.Issue.reporter | Unknown | reporter of the issue | 
| Mantis.Issue.status | Unknown | status of the issues created | 
| Mantis.Issue.created_at | Unknown | time  at which issue created | 
### mantis-create-issue

***
create a Mantis issue

#### Base Command

`mantis-create-issue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | project name to  create issue under. | Required | 
| category | category name for the issue. | Required | 
| summary | summary of the issue. | Required | 
| description | Description for the issue. | Required | 

#### Context Output

There is no context output for this command.
### mantis-get-issues

***
get a list of mantis issues

#### Base Command

`mantis-get-issues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | The number of issues to return per page. Default is 50 but overridable by configuration. Default is 10. | Optional | 
| page | The page number. Default is 1. | Optional | 

#### Context Output

There is no context output for this command.
### mantis-add-note

***
add Note to a Mantis issue

#### Base Command

`mantis-add-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Mantis issue to add a Note. | Required | 
| text | note text. | Required | 
| view_state | select view_state defailt is public. Possible values are: public, private. Default is public. | Required | 

#### Context Output

There is no context output for this command.
### mantis-close-issue

***
close a Mantis issue

#### Base Command

`mantis-close-issue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Mantis issue Id to close. | Required | 

#### Context Output

There is no context output for this command.