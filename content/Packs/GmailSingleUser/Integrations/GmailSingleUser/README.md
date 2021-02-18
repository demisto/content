Use the Gmail Single User integration to send emails and fetch emails as incidents to Cortex XSOAR. 

**Note:** We recommend using this integration if you only want to fetch and send emails from a single user's mailbox. If you require accessing multiple users' mailboxes, use the [GMail Integration](https://xsoar.pan.dev/docs/reference/integrations/gmail).

## Application Authorization Flow

To allow Cortex XSOAR to access Gmail, the user has to approve the Demisto App using an OAuth 2.0 authorization flow. Follow these steps to authorize the Demisto app in Gmail.

1. Create and save an integration instance of the Gmail Single User integration. Do not fill in the *Auth Code* field, this will be obtained in the next steps.
2. To obtain the **Auth Code** run the following command in the playground: ***!gmail-auth-link***. Access the link you receive to authenticate your Gmail account. 
3. Complete the authentication process and copy the received code to the **Auth Code** configuration parameter of the integration instance. 
4. Save the instance.
5. To verify that authentication was configured correctly, run the ***!gmail-auth-test***.

**NOTE:** The Demisto App is going through the Google verification process. During the verification process the app is not fully verified, and you may receive from Google an "unverified app" warning in the authorization flow.

**GSuite Admins:** You can choose to trust the Demisto App so your users can configure the App. Instructions:
* Go to [App Access Control](https://admin.google.com/ac/owl/list?tab=apps)
* Choose: `Configure new app` -> `OAuth App Name Or Client ID`. 
  ![GSuite App Configurations](doc_imgs/gsuite-configure-app.png)
* Enter the following Client ID: `391797357217-pa6jda1554dbmlt3hbji2bivphl0j616.apps.googleusercontent.com`
* You will see the `Demisto App` in the results page.
  ![Demisto App](doc_imgs/demisto-app-result.png)
* Select the App and grant the App access as `Trusted`. 

Additional info available at: https://support.google.com/a/answer/7281227

**Optional:** You can use your own Google App instead of the default Demisto App. To create your own app, follow the [Google instructions for Desktop Apps](https://developers.google.com/identity/protocols/OAuth2InstalledApp#prerequisites). 
* Go to the developers credentials page: https://console.developers.google.com/apis/credentials (you may need to setup a new project if you haven't done so in the past).
* If needed, configure the Consent Screen. Fill in the Consent Screen information you would like to display to your users.
* In the credentials page choose: `Create Credentials` -> `OAuth client ID`.
  ![Create Credentials](doc_imgs/create-credentials.png)
* When creating the OAuth client ID, select **iOS** as the type (this type allows Apps to work only with a client id).
* Name the App and Bundle. You can choose a dummy bundle id such as: `com.demisto.app`.
  ![OAuth App](doc_imgs/oauth-app.png)
* Make sure to enable the GMail API at: https://console.developers.google.com/apis/api/gmail.googleapis.com/overview
* After you create the app, copy the *client id* to the integration configuration. Proceed with the OAuth 2.0 authorization flow detailed above.


## Configure Gmail Single User on Cortex XSOAR

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Gmail Single User.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Email of user__
    * __Auth Code (run the !gmail-auth-link command to start the auth flow - see Detailed Instructions (?) section)__
    * __Client ID (Optional: use your own app - see Detailed Instructions (?)__
    * __Incident type__
    * __Fetch incidents__
    * __First fetch timestamp, in days.__
    * __Events query (e.g. "from:example@demisto.com")__
    * __Maximum number of emails to pull per fetch__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
* Incident Name
* Occurred
* Owner
* Type
* Severity
* Email From
* Email Message ID
* Email Subject
* Email To
* Attachment Extension
* Attachment Name
* Email Body
* Email Body Format

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. Send email: send-mail
2. Get an authentication link: gmail-auth-link
3. Test authorization: gmail-auth-test
### 1. Send email
---
Sends an email using Gmail.

##### Base Command

`send-mail`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | The email addresses of the receiver. | Required | 
| body | The contents (body) of the email to be sent in plain text. | Optional | 
| subject | The subject of the email to be sent. | Required | 
| attachIDs | A comma-separated list of IDs of War Room entries that contain files, which need be attached to the email. | Optional | 
| cc | The additional recipient email address (CC). | Optional | 
| bcc | The additional recipient email address (BCC). | Optional | 
| htmlBody | The contents (body) of the email to be sent in HTML format. | Optional | 
| replyTo | The email address used to reply to the message. | Optional | 
| attachNames | A comma-separated list of new names to renamfor existing attachments, which relates to the order that they were attached to the email. For example, rename the first and third file attachNames=new_fileName1,,new_fileName3 To rename the second and fifth files, attachNames=,new_fileName2,,,new_fileName5 | Optional | 
| attachCIDs | A comma-separated list of CID images to embed attachments to the email. | Optional | 
| transientFile | The textual name for an attached file. Multiple files are supported as a comma-separated list. For example, transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz". | Optional | 
| transientFileContent | The content for the attached file. Multiple files are supported as a comma-separated list. For example, transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz". | Optional | 
| transientFileCID | The CID image for an attached file to include within the email body. Multiple files are supported as comma-separated list. For example, transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz". | Optional | 
| additionalHeader | A comma-separated list of additional headers in the format: headerName=headerValue. For example, "headerName1=headerValue1,headerName2=headerValue2". | Optional | 
| templateParams | 'Replaces {varname} variables with values from this parameter. Expected values are in the form of a JSON document. For example, {"varname" :{"value" "some  value", "key": "context key"}}. Each var name can either be provided with  the value or a context key to retrieve the value.' | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.SentMail.ID | String | The immutable ID of the message. | 
| Gmail.SentMail.Labels | String | List of IDs of labels applied to this message. | 
| Gmail.SentMail.ThreadId | String | The ID of the thread in which the message belongs. | 
| Gmail.SentMail.To | String | The recipient of the email. | 
| Gmail.SentMail.From | Unknown | The sender of the email. | 
| Gmail.SentMail.Cc | String | Additional recipient email address (CC). | 
| Gmail.SentMail.Bcc | String | Additional recipient email address (BCC). | 
| Gmail.SentMail.Subject | String | The subject of the email. | 
| Gmail.SentMail.Body | Unknown | The plain-text version of the email. | 
| Gmail.SentMail.MailBox | String | The mailbox from which the mail was sent. | 


##### Command Example
```!send-mail subject="this is the subject" to=test@demistodev.com body="this is the body"```
##### Context Example
```
{
    "Gmail.SentMail": [
 {
     "Body": "this is the body", 
     "From": "example@demisto.com", 
     "Cc": null, 
     "Labels": [
  "SENT"
     ], 
     "Bcc": null, 
     "To": "test@demistodev.com", 
     "ThreadId": "16f662789d3a2972", 
     "Mailbox": "test@demistodev.com", 
     "Type": "Gmail", 
     "ID": "16f662789d3a2972", 
     "Subject": "this is the subject"
 }
    ]
}
```
##### Human Readable Output
> ### Email sent:
> |Type|ID|To|From|Subject|Body|Labels|ThreadId|
> |---|---|---|---|---|---|---|---|
> | Gmail | 16f662789d3a2972 | test@demistodev.com | example@demisto.com | this is the subject | this is the body | SENT |  16f662789d3a2972 |
### 2. Get an authentication link
---
Returns a link to use to authenticate to Gmail. It starts the OAuth2 process. 
##### Base Command
`gmail-auth-link`
##### Input
There is no input for this command.
##### Context Output
There is no context output for this command.
##### Command Example
```!gmail-auth-link```
##### Human Readable Output
> ## Gmail Auth Link
> Please follow the following **link**.
> After Completing the authentication process, copy the received code
>to the **Auth Code** configuration parameter of the integration instance.
> Save the integration instance and then run *!gmail-auth-test* to test that
> the authentication is properly set.
    
### 3. Test authorization
---
Tests that Gmail auth is properly configured. Use this command after completing the OAuth2 authentication process.
##### Base Command
`gmail-auth-test`
##### Input
There is no input for this command.
##### Context Output
There is no context output for this command.
##### Command Example
```!gmail-auth-test```
##### Human Readable Output
Authentication test completed successfully.
