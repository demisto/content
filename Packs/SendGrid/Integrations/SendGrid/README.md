SendGrid provides a cloud-based service that assists businesses with email delivery. It allows companies to track email opens, unsubscribes, bounces, and spam reports. Our SendGrid pack utilize these SendGrid use cases to help you send and manage your emails.

## Configure SendGrid in Cortex


| **Parameter** | **Required** |
| --- | --- |
| API Key | True |
| From Email ID | True |
| From Sender Name | True |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### sg-send-email

***
Send an email.

#### Base Command

`sg-send-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ToEmails | A CSV list of to email recipients. Make sure To, Cc and Bcc emails are unique. | Required | 
| Subject | Email subject. | Required | 
| HtmlBody | html content of email. | Optional | 
| RawBody | Raw content of email. | Optional | 
| ReplyTo | Reply To email. | Optional | 
| Categories | List of categories. For example: cake,pie,baking. | Optional | 
| BatchID | An ID representing a batch of emails to be sent at the same time. | Optional | 
| SendAt | An UTC time allowing you to specify when you want your email to be delivered. Delivery cannot be scheduled more than 72 hours in advance. ISO format(UTC timezone): 2021-04-23T12:07:44. | Optional | 
| Asm | An object allowing you to specify how to handle unsubscribes. For example:  {"group_id": 12345,"groups_to_display":[1,2,3]}. | Optional | 
| IPPoolName | The IP Pool that you would like to send this email from. | Optional | 
| ClickTracking | Allows you to track if a recipient clicked a link in your email. For ex: {"enable": "True","enable_text": True}. | Optional | 
| GAnalytics | Allows you to enable tracking provided by Google Analytics. For ex: {"enable": "True","utm_campaign": "[NAME OF YOUR REFERRER SOURCE]","utm_content": "[USE THIS SPACE TO DIFFERENTIATE YOUR EMAIL FROM ADS]","utm_medium": "[NAME OF YOUR MARKETING MEDIUM e.g. email]","utm_name": "[NAME OF YOUR CAMPAIGN]","utm_term": "[IDENTIFY PAID KEYWORDS HERE]","utm_source":"[Name of the referrer source]"}. | Optional | 
| OpenTracking | Allows you to track if the email was opened by including a single pixel image in the body of the content. When the pixel is loaded, Twilio SendGrid can log that the email was opened. For ex: {"enable": "True","substitution_tag": "%opentrack"}. | Optional | 
| SubscriptionTracking | Allows you to insert a subscription management link at the bottom of the text and HTML bodies of your email. If you would like to specify the location of the link within your email, you may use the substitution_tag. For ex: {"enable": "True","html": "If you would like to unsubscribe and stop receiving these emails &lt;% clickhere %&gt;.","substitution_tag": "&lt;%click here%&gt;","text": "If you would like to unsubscribe and stop receiving these emails &lt;% click here %&gt;."}. | Optional | 
| BccSettings | Bcc email settings. For ex: {"email": "ben.doe@example.com", "enable": True }. | Optional | 
| BypassListManagement | Allows you to bypass all unsubscribe groups and suppressions to ensure that the email is delivered to every single recipient. Possible values are: True, False. | Optional | 
| SandboxMode | Sandbox Mode allows you to send a test email to ensure that your request body is valid and formatted correctly. Possible values are: True, False. | Optional | 
| Footer | The default footer that you would like included on every email. For ex: {"enable": "True","html": "&lt;p&gt;Thanks&lt;/br&gt;The SendGrid Team&lt;/p&gt;","text": "Thanks,/n The SendGrid Team"}. | Optional | 
| SpamCheck | Spam Check allows you to test the content of your email for spam. For ex: {"enable": "True","post_to_url": "http://example.com/compliance","threshold": 3}. | Optional | 
| Headers | A collection of JSON key/value pairs allowing you to specify handling instructions for your email. You may not overwrite the following headers: x-sg-id, x-sg-eid, received, dkim-signature, Content-Type, Content-Transfer-Encoding, To, From, Subject, Reply-To, CC, BCC. For ex: {"key1":"value1","key2":"value2","key3":"value3"}. | Optional | 
| TemplateID | An email template ID. A template that contains a subject and content — either text or html — will override any subject and content values specified at the personalisations or message level. | Optional | 
| CustomArgs | Values that are specific to this personalization that will be carried along with the email and its activity data. Substitutions will not be made on custom arguments, so any string that is entered into this parameter will be assumed to be the custom argument that you would like to be used. This field may not exceed 10,000 bytes. For Ex: {"marketing": "true","activationAttempt": "1","customerAccountNumber": "1234"}. | Optional | 
| AttachIDs | A CSV list of War Room entry IDs that contain files, and are used to attach files to the outgoing email. For example: attachIDs=15@8,19@8. | Optional | 
| AttachNames | A CSV list of names of attachments to send. Should be the same number of elements as attachIDs. | Optional | 
| Bcc | A CSV list of to email bcc recipients. Make sure To, Cc and Bcc emails are unique. | Optional | 
| Cc | A CSV list of to email cc recipients. Make sure To, Cc and Bcc emails are unique. | Optional | 

#### Context Output

There is no context output for this command.
### sg-get-global-email-stats

***
Retrieves all of your global email statistics between a given date range.

#### Base Command

`sg-get-global-email-stats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of results to return. | Optional | 
| offset | The point in the list to begin retrieving results. | Optional | 
| aggregated_by | How to group the statistics. Must be either "day", "week", or "month". Possible values are: day, week, month. | Optional | 
| start_date | The starting date of the statistics to retrieve. Must follow format YYYY-MM-DD. | Required | 
| end_date | The end date of the statistics to retrieve. Defaults to today. Must follow format YYYY-MM-DD. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). Available headers: blocks,bounce_drops,bounces,clicks,date,deferred,delivered,invalid_emails,opens,processed,requests,spam_report_drops,spam_reports,unique_clicks,unique_opens,unsubscribe_drops,unsubscribes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.GlobalEmailStats | unknown | List of email statistics day/week/month wise. | 

### sg-get-category-stats

***
Retrieves all of your email statistics for each of your categories.

#### Base Command

`sg-get-category-stats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | The starting date of the statistics to retrieve. Must follow format YYYY-MM-DD. | Required | 
| category | The individual category that you want to retrieve statistics for. | Required | 
| end_date | The end date of the statistics to retrieve. Defaults to today. Must follow format YYYY-MM-DD. | Optional | 
| aggregated_by | How to group the statistics. Must be either "day", "week", or "month". Possible values are: day, week, month. | Optional | 
| limit | The number of results to include.  default: 500 maximum: 500. | Optional | 
| offset | The number of results to skip. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). Available headers: blocks,bounce_drops,bounces,clicks,date,deferred,delivered,invalid_emails,opens,processed,requests,spam_report_drops,spam_reports,unique_clicks,unique_opens,unsubscribe_drops,unsubscribes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.CategoryStats | unknown | List of email category statistics day/week/month wise. | 

### sg-get-all-categories-stats

***
Retrieves the total sum of each email statistic for every category over the given date range. By default it returns only 5 categories. Use limit= argument to define the number of categories to return. 

#### Base Command

`sg-get-all-categories-stats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | The starting date of the statistics to retrieve. Must follow format YYYY-MM-DD. | Required | 
| end_date | The end date of the statistics to retrieve. Defaults to today. Must follow format YYYY-MM-DD. | Optional | 
| limit | The number of results to return. | Optional | 
| aggregated_by | How to group the statistics. Must be either "day", "week", or "month". Possible values are: day, week, month. | Optional | 
| sort_by_metric | The metric that you want to sort by. Must be a single metric.  default: delivered. Possible values are: blocks, bounce_drops, bounces, clicks, deferred, delivered, invalid_emails, opens, processed, requests, spam_report_drops, spam_reports, unique_clicks, unique_opens, unsubscribe_drops, unsubscribes. | Optional | 
| sort_by_direction | The direction you want to sort.  Allowed Values: desc, asc default: desc. Possible values are: asc, desc. | Optional | 
| offset | The point in the list to begin retrieving results. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). Available headers: blocks,bounce_drops,bounces,clicks,date,deferred,delivered,invalid_emails,opens,processed,requests,spam_report_drops,spam_reports,unique_clicks,unique_opens,unsubscribe_drops,unsubscribes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.AllCategoriesStats | unknown | List of all email statistics day/week/month wise. | 

### sg-list-categories

***
Retrieves a list of all of your categories.

#### Base Command

`sg-list-categories`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | Allows you to perform a prefix search on this particular category. | Optional | 
| limit | The number of categories to display per page. Default: 50. | Optional | 
| offset | The point in the list that you would like to begin displaying results. Default: 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.CategoriesList | unknown | List of categories. | 

### sg-create-batch-id

***
Generates a new batch ID.

#### Base Command

`sg-create-batch-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.BatchId | unknown | Returns a batch id, which can be used manage scheduled sends. | 

### sg-scheduled-status-change

***
Cancel or pause a scheduled send associated with a batch ID.

#### Base Command

`sg-scheduled-status-change`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| batch_id | ID to manage multiple scheduled sends. | Required | 
| status | The status of the send you would like to implement. This can be pause or cancel. Possible values are: pause, cancel. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.ScheduledSendStatus | unknown | The latest status of the scheduled send. | 

### sg-retrieve-all-scheduled-sends

***
Retrieves all cancelled and paused scheduled send information.

#### Base Command

`sg-retrieve-all-scheduled-sends`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.ScheduledSends | unknown | List of all paused/cancelled scheduled sends. | 

### sg-retrieve-scheduled-send

***
Retrieves the cancel/paused scheduled send information for a specific batch id.

#### Base Command

`sg-retrieve-scheduled-send`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| batch_id | ID to manage multiple scheduled sends. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.ScheduledSend | unknown | List of all paused/cancelled scheduled sends associated with the given batch id. | 

### sg-update-scheduled-send

***
Update the status of a scheduled send for the given batch id.

#### Base Command

`sg-update-scheduled-send`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| batch_id | ID to manage multiple scheduled sends. | Required | 
| status | The status of the send you would like to implement. This can be pause or cancel. Possible values are: pause, cancel. | Required | 

#### Context Output

There is no context output for this command.
### sg-delete-scheduled-send

***
Delete the cancellation/pause of a scheduled send.

#### Base Command

`sg-delete-scheduled-send`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| batch_id | ID to manage multiple scheduled sends. | Required | 

#### Context Output

There is no context output for this command.
### sg-get-email-activity-list

***
Retrieves the email activity list associated with the messages matching your query. If no query provided, it returns a list of most recent emails you've sent. NOTE: This Email Activity API returns email list up to last 30 days.

#### Base Command

`sg-get-email-activity-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of messages returned. This parameter must be greater than 0 and less than or equal to 1000. Default is 10. | Required | 
| query | Use the query syntax to filter your email activity.     For example: query to get email list for category - "Last Login": query=`(Contains(categories,"Last Login"))`     Document link for query samples: https://docs.sendgrid.com/for-developers/sending-email/getting-started-email-activity-api#query-reference. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). Available headers: clicks_count,from_email,last_event_time,msg_id,opens_count,status,subject,to_email. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.EmailList | unknown | Email activity list associated with the messages matching your query. | 

### sg-get-all-lists

***
Retrieves all of your recipient lists. If you don't have any lists, an empty array will be returned.

#### Base Command

`sg-get-all-lists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Maximum number of elements to return. returns 1000 max. default: 100. | Optional | 
| page_token | Token corresponding to a specific page of results, as provided by metadata. default: None. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). Available headers: id, name, contact_count, _metadata. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.Lists.Result | unknown | Array of your contact lists | 
| Sendgrid.Lists.Metadata | unknown | Metadata of returned set of result | 

### sg-get-list-by-id

***
Retrieves a single recipient list.

#### Base Command

`sg-get-list-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | ID of contact list. | Required | 
| contact_sample | Setting the optional parameter contact_sample=true returns the contact_sample in the response body. Up to fifty of the most recent contacts uploaded or attached to a list will be returned, sorted alphabetically, by email address. Default:False. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.List | unknown | Contact list details | 

### sg-create-list

***
Creates a new contacts list

#### Base Command

`sg-create-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | Name for your list. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.NewList | unknown | Newly created List details | 

### sg-get-list-contact-count-by-id

***
Returns the number of contacts on a specific list

#### Base Command

`sg-get-list-contact-count-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | ID of contact list. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.ListCount | unknown | List contact count details | 

### sg-update-list-name

***
Updates the name of a list

#### Base Command

`sg-update-list-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | ID of contact list. | Required | 
| updated_list_name | New name for your list. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.updatedList | unknown | Updated list details | 

### sg-delete-list

***
Deletes a specific list

#### Base Command

`sg-delete-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | ID of contact list or job Id. | Required | 
| delete_contacts | Flag indicates that all contacts on the list are also to be deleted. default: False. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sendgrid.DeleteListJobId | unknown | Job id of the async job | 