Gophish is a powerful, open-source phishing framework that makes it easy to test your organization's exposure to phishing. For Free

This integration was integrated and tested with version 0.11.0 of gophish
## Configure gophish in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| apikey | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gophish-get-users
***
Gets all users from gophish


#### Base Command

`gophish-get-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.Users | String | All users details | 


#### Command Example
```!gophish-get-users```

#### Context Example
```
{
    "Gophish": {
        "Users": [
            {
                "api_key": "c805d2ec901b09b0d6bc8d12ed12f9c7e1f630f1a2115f1649f15b1d36082585",
                "id": 1,
                "password_change_required": false,
                "role": {
                    "description": "System administrator with full permissions",
                    "name": "Admin",
                    "slug": "admin"
                },
                "username": "admin"
            },
            {
                "api_key": "d5d97dc332924ee141f936a8f54e5f553cf574e415b0313a98506eb100a01e77",
                "id": 5,
                "password_change_required": false,
                "role": {
                    "description": "System administrator with full permissions",
                    "name": "Admin",
                    "slug": "admin"
                },
                "username": "modifyuser"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|api_key|id|password_change_required|role|username|
>|---|---|---|---|---|
>| c805d2ec901b09b0d6bc8d12ed12f9c7e1f630f1a2115f1649f15b1d36082585 | 1 | false | slug: admin<br/>name: Admin<br/>description: System administrator with full permissions | admin |
>| d5d97dc332924ee141f936a8f54e5f553cf574e415b0313a98506eb100a01e77 | 5 | false | slug: admin<br/>name: Admin<br/>description: System administrator with full permissions | modifyuser |


### gophish-get-user
***
Get single user details from gophish


#### Base Command

`gophish-get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the user as an integer | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.User | string | User details | 


#### Command Example
```!gophish-get-user id=1```

#### Context Example
```
{
    "Gophish": {
        "User": {
            "api_key": "c805d2ec901b09b0d6bc8d12ed12f9c7e1f630f1a2115f1649f15b1d36082585",
            "id": 1,
            "password_change_required": false,
            "role": {
                "description": "System administrator with full permissions",
                "name": "Admin",
                "slug": "admin"
            },
            "username": "admin"
        }
    }
}
```

#### Human Readable Output

>### Results
>|api_key|id|password_change_required|role|username|
>|---|---|---|---|---|
>| c805d2ec901b09b0d6bc8d12ed12f9c7e1f630f1a2115f1649f15b1d36082585 | 1 | false | slug: admin<br/>name: Admin<br/>description: System administrator with full permissions | admin |


### gophish-create-user
***
Creates a new user


#### Base Command

`gophish-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role | Role of the user to be created | Required | 
| username | Username for the new user | Required | 
| password | Password for the new user | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.NewUser | String | New user details that was created | 


#### Command Example
```!gophish-create-user role=admin username=Thisistheusername password=password```

#### Context Example
```
{
    "Gophish": {
        "NewUser": {
            "api_key": "457f41db94228d9c3bbde2394115bbfa420bc4239ac7ba3dd8a3f011e20e45cc",
            "id": 6,
            "password_change_required": false,
            "role": {
                "description": "System administrator with full permissions",
                "name": "Admin",
                "slug": "admin"
            },
            "username": "Thisistheusername"
        }
    }
}
```

#### Human Readable Output

>### Results
>|api_key|id|password_change_required|role|username|
>|---|---|---|---|---|
>| 457f41db94228d9c3bbde2394115bbfa420bc4239ac7ba3dd8a3f011e20e45cc | 6 | false | slug: admin<br/>name: Admin<br/>description: System administrator with full permissions | Thisistheusername |


### gophish-modify-user
***
Modifies a user account. This can be used to change the role, reset the password, or change the username.


#### Base Command

`gophish-modify-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user ID | Required | 
| role | The role slug to use for the account | Optional | 
| password | The password to set for the account | Optional | 
| username | The username for the account | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.ModifiedUser | String | Modified user details | 


#### Command Example
```!gophish-modify-user role=admin username=newusername password=newpassword id=5```

#### Context Example
```
{
    "Gophish": {
        "ModifiedUser": {
            "api_key": "d5d97dc332924ee141f936a8f54e5f553cf574e415b0313a98506eb100a01e77",
            "id": 5,
            "password_change_required": false,
            "role": {
                "description": "System administrator with full permissions",
                "name": "Admin",
                "slug": "admin"
            },
            "username": "newusername"
        }
    }
}
```

#### Human Readable Output

>### Results
>|api_key|id|password_change_required|role|username|
>|---|---|---|---|---|
>| d5d97dc332924ee141f936a8f54e5f553cf574e415b0313a98506eb100a01e77 | 5 | false | slug: admin<br/>name: Admin<br/>description: System administrator with full permissions | newusername |


### gophish-delete-user
***
Deletes a user, as well as every object (landing page, template, etc.) and campaign they've created.


#### Base Command

`gophish-delete-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.DeletedUser | string | Info about the deleted user | 


#### Command Example
```!gophish-delete-user id=5```

#### Context Example
```
{
    "Gophish": {
        "DeletedUser": {
            "data": null,
            "message": "User deleted Successfully!",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|data|message|success|
>|---|---|---|
>|  | User deleted Successfully! | true |


### gophish-get-all-sending-profiles
***
Gets a list of the sending profiles created by the authenticated user.


#### Base Command

`gophish-get-all-sending-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.AllSendingProfiles | String | Sending profiles information | 


#### Command Example
```!gophish-get-all-sending-profiles```

#### Context Example
```
{
    "Gophish": {
        "AllSendingProfiles": [
            {
                "from_address": "Phil emailaddress",
                "headers": [],
                "host": "smtp.gmail.com:465",
                "id": 1,
                "ignore_cert_errors": true,
                "interface_type": "SMTP",
                "modified_date": "2020-09-03T08:07:35.811631358Z",
                "name": "Google",
                "password": "password",
                "username": "emailaddress"
            },
            {
                "from_address": "John <john@acme.com>",
                "headers": [],
                "host": "testing.acme.com:25",
                "id": 4,
                "ignore_cert_errors": true,
                "interface_type": "SMTP",
                "modified_date": "2020-09-04T04:58:23.737180623Z",
                "name": "TestingCreation2",
                "password": "password",
                "username": "john"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|from_address|headers|host|id|ignore_cert_errors|interface_type|modified_date|name|password|username|
>|---|---|---|---|---|---|---|---|---|---|
>| Phil emailaddress |  | smtp.gmail.com:465 | 1 | true | SMTP | 2020-09-03T08:07:35.811631358Z | Google | password | emailaddress |
>| John <john@acme.com> |  | testing.acme.com:25 | 4 | true | SMTP | 2020-09-04T04:58:23.737180623Z | TestingCreation2 | password | john |


### gophish-get-sending-profile
***
Returns a sending profile given an ID, returning a 404 error if no sending profile with the provided ID is found.


#### Base Command

`gophish-get-sending-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sending profile ID to return | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.SendingProfile | String | info about the sending profile | 


#### Command Example
```!gophish-get-sending-profile id=1```

#### Context Example
```
{
    "Gophish": {
        "SendingProfile": {
            "from_address": "Phil emailaddress",
            "headers": [],
            "host": "smtp.gmail.com:465",
            "id": 1,
            "ignore_cert_errors": true,
            "interface_type": "SMTP",
            "modified_date": "2020-09-03T08:07:35.811631358Z",
            "name": "Google",
            "password": "password",
            "username": "emailaddress"
        }
    }
}
```

#### Human Readable Output

>### Results
>|from_address|headers|host|id|ignore_cert_errors|interface_type|modified_date|name|password|username|
>|---|---|---|---|---|---|---|---|---|---|
>| Phil emailaddress |  | smtp.gmail.com:465 | 1 | true | SMTP | 2020-09-03T08:07:35.811631358Z | Google | password | emailaddress |


### gophish-create-sending-profile
***
Creates a sending profile.


#### Base Command

`gophish-create-sending-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Profile name | Required | 
| from_address | From Address to use (John Doe &lt;john@example.com&gt;) | Required | 
| host | Host and port of the SMTP sender (smtp.example.com:25) | Required | 
| username | Username to use | Required | 
| password | Password to use | Required | 
| ignore_cert_errors | Ignore untrusted certificates | Required | 
| headers | Custom headers for the sending profile in format key1:value1,key2:value2 etc | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.CreatedSendingProfile | String | Info about the newly created Sendin Profile | 


#### Command Example
```!gophish-create-sending-profile name=TestingCreation from_address="John <john@acme.com>" host=testing.acme.com:25 username=john password=password ignore_cert_errors=True ```

#### Context Example
```
{
    "Gophish": {
        "CreatedSendingProfile": {
            "from_address": "John <john@acme.com>",
            "headers": null,
            "host": "testing.acme.com:25",
            "id": 5,
            "ignore_cert_errors": true,
            "interface_type": "SMTP",
            "modified_date": "2020-09-04T05:17:03.414841277Z",
            "name": "TestingCreation",
            "password": "password",
            "username": "john"
        }
    }
}
```

#### Human Readable Output

>### Results
>|from_address|headers|host|id|ignore_cert_errors|interface_type|modified_date|name|password|username|
>|---|---|---|---|---|---|---|---|---|---|
>| John <john@acme.com> |  | testing.acme.com:25 | 5 | true | SMTP | 2020-09-04T05:17:03.414841277Z | TestingCreation | password | john |


### gophish-delete-sending-profile
***
Deletes a sending profile by ID.


#### Base Command

`gophish-delete-sending-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile to be deleted | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.DeletedSendingProfile | String | This method returns a status message indicating the sending profile was deleted successfully. | 


#### Command Example
```!gophish-delete-sending-profile id=4```

#### Context Example
```
{
    "Gophish": {
        "DeletedSendingProfile": {
            "data": null,
            "message": "SMTP Deleted Successfully",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|data|message|success|
>|---|---|---|
>|  | SMTP Deleted Successfully | true |


### gophish-get-all-landing-pages
***
Returns a list of landing pages.


#### Base Command

`gophish-get-all-landing-pages`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.AllLandingPages | String | Returns a list of landing pages. | 


#### Command Example
```!gophish-get-all-landing-pages```

#### Context Example
```
{
    "Gophish": {
        "AllLandingPages": [
            {
                "capture_credentials": true,
                "capture_passwords": false,
                "html": "HTML GOES HERE",
                "id": 1,
                "modified_date": "2020-09-03T08:08:18.028831434Z",
                "name": "Outlook",
                "redirect_url": "https://urlhere"
            },
            {
                "capture_credentials": true,
                "capture_passwords": true,
                "html": "<html><head></head><body>here goes the html</body></html>",
                "id": 3,
                "modified_date": "2020-09-04T05:11:49.549173718Z",
                "name": "TestingCommands2",
                "redirect_url": "https://www.paloaltonetworks.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|capture_credentials|capture_passwords|html|id|modified_date|name|redirect_url|
>|---|---|---|---|---|---|---|
>| true | false | HTML GOES HERE | 1 | 2020-09-03T08:08:18.028831434Z | Outlook | https://urlhere |
>| true | true | <html><head></head><body>here goes the html</body></html> | 3 | 2020-09-04T05:11:49.549173718Z | TestingCommands2 | https://www.paloaltonetworks.com |


### gophish-create-landing-page
***
Creates a landing page.


#### Base Command

`gophish-create-landing-page`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the page | Required | 
| html | HTML of the page | Required | 
| capture_credentials | Capturing credentials is a powerful feature of Gophish. By setting certain flags, you have the ability to capture all user input, or just non-password input. | Required | 
| capture_passwords | If you want to capture passwords as well, set the capture_passwords attribute. | Required | 
| redirect_url | Gophish also provides the ability to redirect users to a URL after they submit credentials. This is controlled by setting the redirect_url attribute. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.CreatedLandingPage | String | info about the created page | 


#### Command Example
```!gophish-create-landing-page name=TestingCommands html="here goes the html" capture_credentials=True capture_passwords=True redirect_url=https://www.paloaltonetworks.com```

#### Context Example
```
{
    "Gophish": {
        "CreatedLandingPage": {
            "capture_credentials": true,
            "capture_passwords": true,
            "html": "<html><head></head><body>here goes the html</body></html>",
            "id": 4,
            "modified_date": "2020-09-04T05:17:10.247261753Z",
            "name": "TestingCommands",
            "redirect_url": "https://www.paloaltonetworks.com"
        }
    }
}
```

#### Human Readable Output

>### Results
>|capture_credentials|capture_passwords|html|id|modified_date|name|redirect_url|
>|---|---|---|---|---|---|---|
>| true | true | <html><head></head><body>here goes the html</body></html> | 4 | 2020-09-04T05:17:10.247261753Z | TestingCommands | https://www.paloaltonetworks.com |


### gophish-delete-landing-page
***
Deletes a landing page.


#### Base Command

`gophish-delete-landing-page`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the page to be deleted | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.DeletedLandingPage | String | Deletes a landing page. | 


#### Command Example
```!gophish-delete-landing-page id=3```

#### Context Example
```
{
    "Gophish": {
        "DeletedLandingPage": {
            "data": null,
            "message": "Page Deleted Successfully",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|data|message|success|
>|---|---|---|
>|  | Page Deleted Successfully | true |


### gophish-import-site-as-landing-page
***
Fetches a URL to be later imported as a landing page


#### Base Command

`gophish-import-site-as-landing-page`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to fetch (include http or https://) | Required | 
| include_resources | Whether or not to create a &lt;base&gt; tag in the resulting HTML to resolve static references (recommended: false) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.ImportedSite | String | This API endpoint doesn't actually create a new landing page. Instead, you can use the HTML returned from this endpoint as an input to the Create Landing Page method. | 


#### Command Example
```!gophish-import-site-as-landing-page url="https://xsoar.pan.dev" include_resources=False```

#### Context Example
```
{
    "Gophish": {
        "ImportedSite": {
            "HTML GOES HERE"
        }
    }
}
```

#### Human Readable Output

>### Results
>|html|
>|---|
>| HTML GOES HERE |


### gophish-get-all-templates
***
Returns a list of templates.


#### Base Command

`gophish-get-all-templates`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.AllTemplates | String | Info about all templates | 


#### Command Example
```!gophish-get-all-templates```

#### Context Example
```
{
    "Gophish": {
        "AllTemplates": [
            {
                "attachments": [],
                "html": "",
                "id": 1,
                "modified_date": "2020-09-03T08:08:43.392043833Z",
                "name": "Credentials",
                "subject": "Input your credentials here",
                "text": "Here {.URL}"
            },
            {
                "attachments": [],
                "html": "",
                "id": 3,
                "modified_date": "2020-09-04T05:12:08.022300211Z",
                "name": "TestingTemplates2",
                "subject": "Test",
                "text": "Test"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|attachments|html|id|modified_date|name|subject|text|
>|---|---|---|---|---|---|---|
>|  |  | 1 | 2020-09-03T08:08:43.392043833Z | Credentials | Input your credentials here | Here {.URL} |
>|  |  | 3 | 2020-09-04T05:12:08.022300211Z | TestingTemplates2 | Test | Test |


### gophish-get-template
***
Returns a template with the provided ID.Returns a 404: Not Found error if the specified template doesn't exist.


#### Base Command

`gophish-get-template`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The template ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.Template | String | Returns a template with the provided ID | 


#### Command Example
```!gophish-get-template id=1```

#### Context Example
```
{
    "Gophish": {
        "Template": {
            "attachments": [],
            "html": "",
            "id": 1,
            "modified_date": "2020-09-03T08:08:43.392043833Z",
            "name": "Credentials",
            "subject": "Input your credentials here",
            "text": "Here {.URL}"
        }
    }
}
```

#### Human Readable Output

>### Results
>|attachments|html|id|modified_date|name|subject|text|
>|---|---|---|---|---|---|---|
>|  |  | 1 | 2020-09-03T08:08:43.392043833Z | Credentials | Input your credentials here | Here {.URL} |


### gophish-delete-template
***
Deletes a template by ID.


#### Base Command

`gophish-delete-template`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The template ID to delete | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.DeletedTemplate | String | Deleted Template | 


#### Command Example
```!gophish-delete-template id=3```

#### Context Example
```
{
    "Gophish": {
        "DeletedTemplate": {
            "data": null,
            "message": "Template deleted successfully!",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|data|message|success|
>|---|---|---|
>|  | Template deleted successfully! | true |


### gophish-import-template
***
This method doesn't fully import the email as a template. Instead, it parses the email, returning a response that can be used with the "Create Template" endpoint.


#### Base Command

`gophish-import-template`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| convert_links | Whether or not to convert the links within the email to  automatically. | Required | 
| content | The original email content in RFC 2045 format, including the original headers. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.ImportedTemplate | string | Info about the imported template | 


#### Command Example
```!gophish-import-template convert_links=False content=contenthere```

#### Context Example
```
{
    "Gophish": {
        "ImportedTemplate": {
            "html": "<html><head></head><body></body></html>",
            "subject": "",
            "text": ""
        }
    }
}
```

#### Human Readable Output

>### Results
>|html|subject|text|
>|---|---|---|
>| <html><head></head><body></body></html> |  |  |


### gophish-create-template
***
Creates a new template from the provided data


#### Base Command

`gophish-create-template`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the template | Required | 
| subject | Subject to use: {{.FirstName}}, please reset your password. | Required | 
| text | Text formatted content: Please reset your password here: {{.URL}} | Optional | 
| html | HTML formatted content: &lt;html&gt;&lt;head&gt;&lt;/head&gt;&lt;body&gt;Please reset your password &lt;a href\"{{.URL}}\"&gt;here&lt;/a&gt;&lt;/body&gt;&lt;/html&gt;" | Optional | 
| attachmentContent | attachment is expected to be base64 encoded. | Optional | 
| attachmentType | Type of the attachment | Optional | 
| attachmentName | Name of the attachment | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.CreatedTemplate | string | Information about the created template | 


#### Command Example
```!gophish-create-template name=TestingTemplates subject=Test text=Test ```

#### Context Example
```
{
    "Gophish": {
        "CreatedTemplate": {
            "attachments": [],
            "html": "",
            "id": 4,
            "modified_date": "2020-09-04T05:17:14.823279988Z",
            "name": "TestingTemplates",
            "subject": "Test",
            "text": "Test"
        }
    }
}
```

#### Human Readable Output

>### Results
>|attachments|html|id|modified_date|name|subject|text|
>|---|---|---|---|---|---|---|
>|  |  | 4 | 2020-09-04T05:17:14.823279988Z | TestingTemplates | Test | Test |


### gophish-get-all-campaigns
***
Returns a list of campaigns.


#### Base Command

`gophish-get-all-campaigns`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.AllCampaigns | String | List of all campaigns | 


#### Command Example
```!gophish-get-all-campaigns```

#### Context Example
```
{
    "Gophish": {
        "AllCampaigns": [
            {
                "completed_date": "0001-01-01T00:00:00Z",
                "created_date": "2020-09-03T08:09:42.08969595Z",
                "id": 1,
                "launch_date": "2020-10-14T08:09:00Z",
                "name": "NewCampaign",
                "page": {
                    "capture_credentials": true,
                    "capture_passwords": false,
                    "html": "HTML GOES HERE",
                    "id": 1,
                    "modified_date": "2020-09-03T08:08:18.028831434Z",
                    "name": "Outlook",
                    "redirect_url": "https://urlhere"
                },
                "results": [
                    {
                        "email": "emailaddress",
                        "first_name": "Esko",
                        "id": "T2VJTQS",
                        "ip": "",
                        "last_name": "Eskola",
                        "latitude": 0,
                        "longitude": 0,
                        "modified_date": "2020-09-03T08:09:42.08969595Z",
                        "position": "CEO",
                        "reported": false,
                        "send_date": "2020-10-14T08:09:00Z",
                        "status": "Scheduled"
                    },
                    {
                        "email": "emailaddress",
                        "first_name": "Jorma",
                        "id": "E2DXw2D",
                        "ip": "",
                        "last_name": "Jormala",
                        "latitude": 0,
                        "longitude": 0,
                        "modified_date": "2020-09-03T08:09:42.08969595Z",
                        "position": "CFO",
                        "reported": false,
                        "send_date": "2020-10-14T08:09:00Z",
                        "status": "Scheduled"
                    }
                ],
                "send_by_date": "0001-01-01T00:00:00Z",
                "smtp": {
                    "from_address": "Phil emailaddress",
                    "headers": [],
                    "host": "smtp.gmail.com:465",
                    "id": 1,
                    "ignore_cert_errors": true,
                    "interface_type": "SMTP",
                    "modified_date": "2020-09-03T08:07:35.811631358Z",
                    "name": "Google",
                    "password": "password",
                    "username": "emailaddress"
                },
                "status": "Queued",
                "template": {
                    "attachments": [],
                    "html": "",
                    "id": 1,
                    "modified_date": "2020-09-03T08:08:43.392043833Z",
                    "name": "Credentials",
                    "subject": "Input your credentials here",
                    "text": "Here {.URL}"
                },
                "timeline": [
                    {
                        "campaign_id": 1,
                        "details": "",
                        "email": "",
                        "message": "Campaign Created",
                        "time": "2020-09-03T08:09:42.104751093Z"
                    }
                ],
                "url": "https://192.168.1.21:80"
            },
            {
                "completed_date": "0001-01-01T00:00:00Z",
                "created_date": "2020-09-04T05:13:31.036755648Z",
                "id": 3,
                "launch_date": "2020-09-05T05:13:31Z",
                "name": "TestingCommands2",
                "page": {
                    "capture_credentials": true,
                    "capture_passwords": false,
                    "html": "HTML GOES HERE",
                    "id": 1,
                    "modified_date": "2020-09-03T08:08:18.028831434Z",
                    "name": "Outlook",
                    "redirect_url": "https://urlhere"
                },
                "results": [
                    {
                        "email": "emailaddress",
                        "first_name": "Esko",
                        "id": "004ElYP",
                        "ip": "",
                        "last_name": "Eskola",
                        "latitude": 0,
                        "longitude": 0,
                        "modified_date": "2020-09-04T05:13:31.036755648Z",
                        "position": "CEO",
                        "reported": false,
                        "send_date": "2020-09-05T05:13:31Z",
                        "status": "Scheduled"
                    },
                    {
                        "email": "emailaddress",
                        "first_name": "Jorma",
                        "id": "VnfTc5i",
                        "ip": "",
                        "last_name": "Jormala",
                        "latitude": 0,
                        "longitude": 0,
                        "modified_date": "2020-09-04T05:13:31.036755648Z",
                        "position": "CFO",
                        "reported": false,
                        "send_date": "2020-09-05T05:13:31Z",
                        "status": "Scheduled"
                    }
                ],
                "send_by_date": "0001-01-01T00:00:00Z",
                "smtp": {
                    "from_address": "Phil emailaddress",
                    "headers": [],
                    "host": "smtp.gmail.com:465",
                    "id": 1,
                    "ignore_cert_errors": true,
                    "interface_type": "SMTP",
                    "modified_date": "2020-09-03T08:07:35.811631358Z",
                    "name": "Google",
                    "password": "password",
                    "username": "emailaddress"
                },
                "status": "Queued",
                "template": {
                    "attachments": [],
                    "html": "",
                    "id": 1,
                    "modified_date": "2020-09-03T08:08:43.392043833Z",
                    "name": "Credentials",
                    "subject": "Input your credentials here",
                    "text": "Here {.URL}"
                },
                "timeline": [
                    {
                        "campaign_id": 3,
                        "details": "",
                        "email": "",
                        "message": "Campaign Created",
                        "time": "2020-09-04T05:13:31.046378362Z"
                    }
                ],
                "url": "https://192.168.1.1:80"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|completed_date|created_date|id|launch_date|name|page|results|send_by_date|smtp|status|template|timeline|url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0001-01-01T00:00:00Z | 2020-09-03T08:09:42.08969595Z | 1 | 2020-10-14T08:09:00Z | NewCampaign | id: 1<br/>name: Outlook<br/>html: HTML GOES HERE<br/>capture_credentials: true<br/>capture_passwords: false<br/>redirect_url: https://urlhere<br/>modified_date: 2020-09-03T08:08:18.028831434Z | {'id': '004ElYP', 'status': 'Scheduled', 'ip': '', 'latitude': 0, 'longitude': 0, 'send_date': '2020-09-05T05:13:31Z', 'reported': False, 'modified_date': '2020-09-04T05:13:31.036755648Z', 'email': 'emailaddress', 'first_name': 'Esko', 'last_name': 'Eskola', 'position': 'CEO'},<br/>{'id': 'VnfTc5i', 'status': 'Scheduled', 'ip': '', 'latitude': 0, 'longitude': 0, 'send_date': '2020-09-05T05:13:31Z', 'reported': False, 'modified_date': '2020-09-04T05:13:31.036755648Z', 'email': 'emailaddress', 'first_name': 'Jorma', 'last_name': 'Jormala', 'position': 'CFO'} | 0001-01-01T00:00:00Z | id: 1<br/>interface_type: SMTP<br/>name: Google<br/>host: smtp.gmail.com:465<br/>username: emailaddress<br/>password: password<br/>from_address: Phil emailaddress<br/>ignore_cert_errors: true<br/>headers: <br/>modified_date: 2020-09-03T08:07:35.811631358Z | Queued | id: 1<br/>name: Credentials<br/>subject: Input your credentials here<br/>text: Here {.URL}<br/>html: <br/>modified_date: 2020-09-03T08:08:43.392043833Z<br/>attachments:  | {'campaign_id': 3, 'email': '', 'time': '2020-09-04T05:13:31.046378362Z', 'message': 'Campaign Created', 'details': ''} | https://192.168.1.1:80 |


### gophish-get-campaign-details
***
Returns a campaign given an ID.


#### Base Command

`gophish-get-campaign-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The campaign ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.CampaignDetails | string | info about the campaign details | 


#### Command Example
```!gophish-get-campaign-details id=1```

#### Context Example
```
{
    "Gophish": {
        "CampaignDetails": {
            "completed_date": "0001-01-01T00:00:00Z",
            "created_date": "2020-09-03T08:09:42.08969595Z",
            "id": 1,
            "launch_date": "2020-10-14T08:09:00Z",
            "name": "NewCampaign",
            "page": {
                "capture_credentials": true,
                "capture_passwords": false,
                "html": "HTML GOES HERE",
                "id": 1,
                "modified_date": "2020-09-03T08:08:18.028831434Z",
                "name": "Outlook",
                "redirect_url": "https://urlhere"
            },
            "results": [
                {
                    "email": "emailaddress",
                    "first_name": "Esko",
                    "id": "T2VJTQS",
                    "ip": "",
                    "last_name": "Eskola",
                    "latitude": 0,
                    "longitude": 0,
                    "modified_date": "2020-09-03T08:09:42.08969595Z",
                    "position": "CEO",
                    "reported": false,
                    "send_date": "2020-10-14T08:09:00Z",
                    "status": "Scheduled"
                },
                {
                    "email": "emailaddress",
                    "first_name": "Jorma",
                    "id": "E2DXw2D",
                    "ip": "",
                    "last_name": "Jormala",
                    "latitude": 0,
                    "longitude": 0,
                    "modified_date": "2020-09-03T08:09:42.08969595Z",
                    "position": "CFO",
                    "reported": false,
                    "send_date": "2020-10-14T08:09:00Z",
                    "status": "Scheduled"
                }
            ],
            "send_by_date": "0001-01-01T00:00:00Z",
            "smtp": {
                "from_address": "Phil emailaddress",
                "headers": [],
                "host": "smtp.gmail.com:465",
                "id": 1,
                "ignore_cert_errors": true,
                "interface_type": "SMTP",
                "modified_date": "2020-09-03T08:07:35.811631358Z",
                "name": "Google",
                "password": "password",
                "username": "emailaddress"
            },
            "status": "Queued",
            "template": {
                "attachments": [],
                "html": "",
                "id": 1,
                "modified_date": "2020-09-03T08:08:43.392043833Z",
                "name": "Credentials",
                "subject": "Input your credentials here",
                "text": "Here {.URL}"
            },
            "timeline": [
                {
                    "campaign_id": 1,
                    "details": "",
                    "email": "",
                    "message": "Campaign Created",
                    "time": "2020-09-03T08:09:42.104751093Z"
                }
            ],
            "url": "https://192.168.1.21:80"
        }
    }
}
```

#### Human Readable Output

>### Results
>|completed_date|created_date|id|launch_date|name|page|results|send_by_date|smtp|status|template|timeline|url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0001-01-01T00:00:00Z | 2020-09-03T08:09:42.08969595Z | 1 | 2020-10-14T08:09:00Z | NewCampaign | id: 1<br/>name: Outlook<br/>html: HTML GOES HERE<br/>capture_credentials: true<br/>capture_passwords: false<br/>redirect_url: https://urlhere<br/>modified_date: 2020-09-03T08:08:18.028831434Z | {'id': 'T2VJTQS', 'status': 'Scheduled', 'ip': '', 'latitude': 0, 'longitude': 0, 'send_date': '2020-10-14T08:09:00Z', 'reported': False, 'modified_date': '2020-09-03T08:09:42.08969595Z', 'email': 'emailaddress', 'first_name': 'Esko', 'last_name': 'Eskola', 'position': 'CEO'},<br/>{'id': 'E2DXw2D', 'status': 'Scheduled', 'ip': '', 'latitude': 0, 'longitude': 0, 'send_date': '2020-10-14T08:09:00Z', 'reported': False, 'modified_date': '2020-09-03T08:09:42.08969595Z', 'email': 'emailaddress', 'first_name': 'Jorma', 'last_name': 'Jormala', 'position': 'CFO'} | 0001-01-01T00:00:00Z | id: 1<br/>interface_type: SMTP<br/>name: Google<br/>host: smtp.gmail.com:465<br/>username: emailaddress<br/>password: password<br/>from_address: Phil emailaddress<br/>ignore_cert_errors: true<br/>headers: <br/>modified_date: 2020-09-03T08:07:35.811631358Z | Queued | id: 1<br/>name: Credentials<br/>subject: Input your credentials here<br/>text: Here {.URL}<br/>html: <br/>modified_date: 2020-09-03T08:08:43.392043833Z<br/>attachments:  | {'campaign_id': 1, 'email': '', 'time': '2020-09-03T08:09:42.104751093Z', 'message': 'Campaign Created', 'details': ''} | https://192.168.1.21:80 |


### gophish-get-campaign-results
***
Gets the results for a campaign.


#### Base Command

`gophish-get-campaign-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The campaign ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.CampaignResults | String | Results of the campaign | 


#### Command Example
```!gophish-get-campaign-results id=1```

#### Context Example
```
{
    "Gophish": {
        "CampaignResults": {
            "id": 1,
            "name": "NewCampaign",
            "results": [
                {
                    "email": "emailaddress",
                    "first_name": "Esko",
                    "id": "T2VJTQS",
                    "ip": "",
                    "last_name": "Eskola",
                    "latitude": 0,
                    "longitude": 0,
                    "modified_date": "2020-09-03T08:09:42.08969595Z",
                    "position": "CEO",
                    "reported": false,
                    "send_date": "2020-10-14T08:09:00Z",
                    "status": "Scheduled"
                },
                {
                    "email": "emailaddress",
                    "first_name": "Jorma",
                    "id": "E2DXw2D",
                    "ip": "",
                    "last_name": "Jormala",
                    "latitude": 0,
                    "longitude": 0,
                    "modified_date": "2020-09-03T08:09:42.08969595Z",
                    "position": "CFO",
                    "reported": false,
                    "send_date": "2020-10-14T08:09:00Z",
                    "status": "Scheduled"
                }
            ],
            "status": "Queued",
            "timeline": [
                {
                    "campaign_id": 1,
                    "details": "",
                    "email": "",
                    "message": "Campaign Created",
                    "time": "2020-09-03T08:09:42.104751093Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|name|results|status|timeline|
>|---|---|---|---|---|
>| 1 | NewCampaign | {'id': 'T2VJTQS', 'status': 'Scheduled', 'ip': '', 'latitude': 0, 'longitude': 0, 'send_date': '2020-10-14T08:09:00Z', 'reported': False, 'modified_date': '2020-09-03T08:09:42.08969595Z', 'email': 'emailaddress', 'first_name': 'Esko', 'last_name': 'Eskola', 'position': 'CEO'},<br/>{'id': 'E2DXw2D', 'status': 'Scheduled', 'ip': '', 'latitude': 0, 'longitude': 0, 'send_date': '2020-10-14T08:09:00Z', 'reported': False, 'modified_date': '2020-09-03T08:09:42.08969595Z', 'email': 'emailaddress', 'first_name': 'Jorma', 'last_name': 'Jormala', 'position': 'CFO'} | Queued | {'campaign_id': 1, 'email': '', 'time': '2020-09-03T08:09:42.104751093Z', 'message': 'Campaign Created', 'details': ''} |


### gophish-get-campaign-summary
***
Returns summary information about a campaign.


#### Base Command

`gophish-get-campaign-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The campaign ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.CampaignSummary | String | Summary stats of the campaign | 


#### Command Example
```!gophish-get-campaign-summary id=1```

#### Context Example
```
{
    "Gophish": {
        "CampaignSummary": {
            "completed_date": "0001-01-01T00:00:00Z",
            "created_date": "2020-09-03T08:09:42.08969595Z",
            "id": 1,
            "launch_date": "2020-10-14T08:09:00Z",
            "name": "NewCampaign",
            "send_by_date": "0001-01-01T00:00:00Z",
            "stats": {
                "clicked": 0,
                "email_reported": 0,
                "error": 0,
                "opened": 0,
                "sent": 0,
                "submitted_data": 0,
                "total": 2
            },
            "status": "Queued"
        }
    }
}
```

#### Human Readable Output

>### Results
>|completed_date|created_date|id|launch_date|name|send_by_date|stats|status|
>|---|---|---|---|---|---|---|---|
>| 0001-01-01T00:00:00Z | 2020-09-03T08:09:42.08969595Z | 1 | 2020-10-14T08:09:00Z | NewCampaign | 0001-01-01T00:00:00Z | total: 2<br/>sent: 0<br/>opened: 0<br/>clicked: 0<br/>submitted_data: 0<br/>email_reported: 0<br/>error: 0 | Queued |


### gophish-delete-campaign
***
Deletes a campaign by ID


#### Base Command

`gophish-delete-campaign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The campaign ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.DeletedCampaign | String | The delelted campaign | 


#### Command Example
```!gophish-delete-campaign id=3```

#### Context Example
```
{
    "Gophish": {
        "DeletedCampaign": {
            "data": null,
            "message": "Campaign deleted successfully!",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|data|message|success|
>|---|---|---|
>|  | Campaign deleted successfully! | true |


### gophish-complete-campaign
***
Marks a campaign as complete.


#### Base Command

`gophish-complete-campaign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The campaign ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.CompletedCampaign | String | Details about the completed campaign | 


#### Command Example
```!gophish-complete-campaign id=3```

#### Context Example
```
{
    "Gophish": {
        "CompletedCampaign": {
            "data": null,
            "message": "Campaign completed successfully!",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|data|message|success|
>|---|---|---|
>|  | Campaign completed successfully! | true |


### gophish-create-campaign
***
Creates and launches a new campaign.


#### Base Command

`gophish-create-campaign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the Campaign | Required | 
| template | Template to use | Required | 
| url | URL to use | Required | 
| page | Landing Page to use | Required | 
| smtp | Sending profile to use | Required | 
| launch_date | When to launch the campaign  for example (2018-10-08T16:20:00+00:00) | Required | 
| send_by_date | Send all emails by for example (2018-10-10T16:20:00+00:00) | Optional | 
| groups | Group names to send to as a list (Group1,group2 etc) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.CreatedCampaign | String | info about the created campaign | 


#### Command Example
```!gophish-create-campaign name=TestingCommands template=Credentials url=https://192.168.1.1:80 page=Outlook smtp=Google launch_date=Tomorrow groups=Users```

#### Context Example
```
{
    "Gophish": {
        "CreatedCampaign": {
            "completed_date": "0001-01-01T00:00:00Z",
            "created_date": "2020-09-04T05:20:59.3716417Z",
            "groups": [
                {
                    "id": 1,
                    "modified_date": "2020-09-03T08:09:17.940720135Z",
                    "name": "Users",
                    "targets": [
                        {
                            "email": "emailaddress",
                            "first_name": "Esko",
                            "last_name": "Eskola",
                            "position": "CEO"
                        },
                        {
                            "email": "emailaddress",
                            "first_name": "Jorma",
                            "last_name": "Jormala",
                            "position": "CFO"
                        }
                    ]
                }
            ],
            "id": 5,
            "launch_date": "2020-09-05T05:20:59Z",
            "name": "TestingCommands",
            "page": {
                "capture_credentials": true,
                "capture_passwords": false,
                "html": "HTML GOES HERE",
                "id": 1,
                "modified_date": "2020-09-03T08:08:18.028831434Z",
                "name": "Outlook",
                "redirect_url": "https://urlhere"
            },
            "results": [
                {
                    "email": "emailaddress",
                    "first_name": "Esko",
                    "id": "UrR1was",
                    "ip": "",
                    "last_name": "Eskola",
                    "latitude": 0,
                    "longitude": 0,
                    "modified_date": "2020-09-04T05:20:59.3716417Z",
                    "position": "CEO",
                    "reported": false,
                    "send_date": "2020-09-05T05:20:59Z",
                    "status": "Scheduled"
                },
                {
                    "email": "emailaddress",
                    "first_name": "Jorma",
                    "id": "fuM9Io2",
                    "ip": "",
                    "last_name": "Jormala",
                    "latitude": 0,
                    "longitude": 0,
                    "modified_date": "2020-09-04T05:20:59.3716417Z",
                    "position": "CFO",
                    "reported": false,
                    "send_date": "2020-09-05T05:20:59Z",
                    "status": "Scheduled"
                }
            ],
            "send_by_date": "0001-01-01T00:00:00Z",
            "smtp": {
                "from_address": "Phil emailaddress",
                "headers": [],
                "host": "smtp.gmail.com:465",
                "id": 1,
                "ignore_cert_errors": true,
                "interface_type": "SMTP",
                "modified_date": "2020-09-03T08:07:35.811631358Z",
                "name": "Google",
                "password": "password",
                "username": "emailaddress"
            },
            "status": "Queued",
            "template": {
                "attachments": [],
                "html": "",
                "id": 1,
                "modified_date": "2020-09-03T08:08:43.392043833Z",
                "name": "Credentials",
                "subject": "Input your credentials here",
                "text": "Here {.URL}"
            },
            "url": "https://192.168.1.1:80"
        }
    }
}
```

#### Human Readable Output

>### Results
>|completed_date|created_date|groups|id|launch_date|name|page|results|send_by_date|smtp|status|template|url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0001-01-01T00:00:00Z | 2020-09-04T05:20:59.3716417Z | {'id': 1, 'name': 'Users', 'modified_date': '2020-09-03T08:09:17.940720135Z', 'targets': [{'email': 'emailaddress', 'first_name': 'Esko', 'last_name': 'Eskola', 'position': 'CEO'}, {'email': 'emailaddress', 'first_name': 'Jorma', 'last_name': 'Jormala', 'position': 'CFO'}]} | 5 | 2020-09-05T05:20:59Z | TestingCommands | id: 1<br/>name: Outlook<br/>html: HTML GOES HERE<br/>capture_credentials: true<br/>capture_passwords: false<br/>redirect_url: https://urlhere<br/>modified_date: 2020-09-03T08:08:18.028831434Z | {'id': 'UrR1was', 'status': 'Scheduled', 'ip': '', 'latitude': 0, 'longitude': 0, 'send_date': '2020-09-05T05:20:59Z', 'reported': False, 'modified_date': '2020-09-04T05:20:59.3716417Z', 'email': 'emailaddress', 'first_name': 'Esko', 'last_name': 'Eskola', 'position': 'CEO'},<br/>{'id': 'fuM9Io2', 'status': 'Scheduled', 'ip': '', 'latitude': 0, 'longitude': 0, 'send_date': '2020-09-05T05:20:59Z', 'reported': False, 'modified_date': '2020-09-04T05:20:59.3716417Z', 'email': 'emailaddress', 'first_name': 'Jorma', 'last_name': 'Jormala', 'position': 'CFO'} | 0001-01-01T00:00:00Z | id: 1<br/>interface_type: SMTP<br/>name: Google<br/>host: smtp.gmail.com:465<br/>username: emailaddress<br/>password: password<br/>from_address: Phil emailaddress<br/>ignore_cert_errors: true<br/>headers: <br/>modified_date: 2020-09-03T08:07:35.811631358Z | Queued | id: 1<br/>name: Credentials<br/>subject: Input your credentials here<br/>text: Here {.URL}<br/>html: <br/>modified_date: 2020-09-03T08:08:43.392043833Z<br/>attachments:  | https://192.168.1.1:80 |


### gophish-get-all-groups
***
Returns a list of groups.


#### Base Command

`gophish-get-all-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.AllGroups | String | List of all groups | 


#### Command Example
```!gophish-get-all-groups```

#### Context Example
```
{
    "Gophish": {
        "AllGroups": [
            {
                "id": 1,
                "modified_date": "2020-09-03T08:09:17.940720135Z",
                "name": "Users",
                "targets": [
                    {
                        "email": "emailaddress",
                        "first_name": "Esko",
                        "last_name": "Eskola",
                        "position": "CEO"
                    },
                    {
                        "email": "emailaddress",
                        "first_name": "Jorma",
                        "last_name": "Jormala",
                        "position": "CFO"
                    }
                ]
            },
            {
                "id": 4,
                "modified_date": "2020-09-04T05:15:06.201901744Z",
                "name": "Testingcommands2",
                "targets": [
                    {
                        "email": "emailaddress",
                        "first_name": "john",
                        "last_name": "johnson",
                        "position": "CEO"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|id|modified_date|name|targets|
>|---|---|---|---|
>| 1 | 2020-09-03T08:09:17.940720135Z | Users | {'email': 'emailaddress', 'first_name': 'Esko', 'last_name': 'Eskola', 'position': 'CEO'},<br/>{'email': 'emailaddress', 'first_name': 'Jorma', 'last_name': 'Jormala', 'position': 'CFO'} |
>| 4 | 2020-09-04T05:15:06.201901744Z | Testingcommands2 | {'email': 'emailaddress', 'first_name': 'john', 'last_name': 'johnson', 'position': 'CEO'} |


### gophish-get-group
***
Returns a group with the given ID.


#### Base Command

`gophish-get-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The group ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.Group | String | Info about the group | 


#### Command Example
```!gophish-get-group id=1```

#### Context Example
```
{
    "Gophish": {
        "Group": {
            "id": 1,
            "modified_date": "2020-09-03T08:09:17.940720135Z",
            "name": "Users",
            "targets": [
                {
                    "email": "emailaddress",
                    "first_name": "Esko",
                    "last_name": "Eskola",
                    "position": "CEO"
                },
                {
                    "email": "emailaddress",
                    "first_name": "Jorma",
                    "last_name": "Jormala",
                    "position": "CFO"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|modified_date|name|targets|
>|---|---|---|---|
>| 1 | 2020-09-03T08:09:17.940720135Z | Users | {'email': 'emailaddress', 'first_name': 'Esko', 'last_name': 'Eskola', 'position': 'CEO'},<br/>{'email': 'emailaddress', 'first_name': 'Jorma', 'last_name': 'Jormala', 'position': 'CFO'} |


### gophish-get-all-groups-summary
***
Returns a summary of each group.


#### Base Command

`gophish-get-all-groups-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.AllGroupsSummary | String | Summary data of all groups | 


#### Command Example
```!gophish-get-all-groups-summary```

#### Context Example
```
{
    "Gophish": {
        "AllGroupsSummary": {
            "groups": [
                {
                    "id": 1,
                    "modified_date": "2020-09-03T08:09:17.940720135Z",
                    "name": "Users",
                    "num_targets": 2
                },
                {
                    "id": 4,
                    "modified_date": "2020-09-04T05:15:06.201901744Z",
                    "name": "Testingcommands2",
                    "num_targets": 1
                }
            ],
            "total": 2
        }
    }
}
```

#### Human Readable Output

>### Results
>|groups|total|
>|---|---|
>| {'id': 1, 'name': 'Users', 'modified_date': '2020-09-03T08:09:17.940720135Z', 'num_targets': 2},<br/>{'id': 4, 'name': 'Testingcommands2', 'modified_date': '2020-09-04T05:15:06.201901744Z', 'num_targets': 1} | 2 |


### gophish-get-group-summary
***
It may be the case that you just want the number of members in a group, not necessarily the full member details. This API endpoint returns a summary for a group.


#### Base Command

`gophish-get-group-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The group ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.GroupSummary | String | Summary data for the group | 


#### Command Example
```!gophish-get-group-summary id=1```

#### Context Example
```
{
    "Gophish": {
        "GroupSummary": {
            "id": 1,
            "modified_date": "2020-09-03T08:09:17.940720135Z",
            "name": "Users",
            "num_targets": 2
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|modified_date|name|num_targets|
>|---|---|---|---|
>| 1 | 2020-09-03T08:09:17.940720135Z | Users | 2 |


### gophish-create-group
***
Creates a new group.


#### Base Command

`gophish-create-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | name of the group | Required | 
| targets | List of targets format: email,firstname,lastname,position:email,firstname,lastname,position etc | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.CreatedGroup | String | details about the created group | 


#### Command Example
```!gophish-create-group name=Testingcommands targets="emailaddress,john,johnson,CEO"```

#### Context Example
```
{
    "Gophish": {
        "CreatedGroup": {
            "id": 5,
            "modified_date": "2020-09-04T05:17:31.959112924Z",
            "name": "Testingcommands",
            "targets": [
                {
                    "email": "emailaddress",
                    "first_name": "john",
                    "last_name": "johnson",
                    "position": "CEO"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|modified_date|name|targets|
>|---|---|---|---|
>| 5 | 2020-09-04T05:17:31.959112924Z | Testingcommands | {'email': 'emailaddress', 'first_name': 'john', 'last_name': 'johnson', 'position': 'CEO'} |


### gophish-delete-group
***
Deletes a group


#### Base Command

`gophish-delete-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The group ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.DeletedGroup | String | info about the group that was deleted | 


#### Command Example
```!gophish-delete-group id=4```

#### Context Example
```
{
    "Gophish": {
        "DeletedGroup": {
            "data": null,
            "message": "Group deleted successfully!",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|data|message|success|
>|---|---|---|
>|  | Group deleted successfully! | true |


### gophish-get-landing-page
***
Gets a landing page info


#### Base Command

`gophish-get-landing-page`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | id of the page to get | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gophish.LandingPage | string | info about the landing page | 


#### Command Example
```!gophish-get-landing-page id=1```

#### Context Example
```
{
    "Gophish": {
        "LandingPage": {
            "capture_credentials": true,
            "capture_passwords": false,
            "html": "HTML GOES HERE",
            "id": 1,
            "modified_date": "2020-09-03T08:08:18.028831434Z",
            "name": "Outlook",
            "redirect_url": "https://urlhere"
        }
    }
}
```

#### Human Readable Output

>### Results
>|capture_credentials|capture_passwords|html|id|modified_date|name|redirect_url|
>|---|---|---|---|---|---|---|
>| true | false | HTML GOES HERE | 1 | 2020-09-03T08:08:18.028831434Z | Outlook | https://urlhere |