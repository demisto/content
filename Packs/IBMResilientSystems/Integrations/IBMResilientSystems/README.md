Overview
--------

Use this integration to manage and orchestrate your IBM Resilient Systems incident response from Cortex XSOAR.

* * *

Configure the IBM Resilient Systems Integration on Cortex XSOAR
---------------------------------------------------------------

1.  Navigate to **Settings** \> **Integrations** \> **Servers & Services**.
2.  Search for IBM Resilient Systems.
3.  Click **Add instance** to create and configure a new integration instance.
    * **Name**: a textual name for the integration instance
    * **Server URL**
    * **Credentials (either username and password or API key ID and API key secret, see [here](https://www.ibm.com/support/knowledgecenter/SSBRUQ_35.0.0/com.ibm.resilient.doc/admin/API_accounts.htm) for more details about API key ID and secret)**
    * **Organization name**
    * **Do not validate server certificate (not secure)**
    * **Use system proxy settings**
    * **Fetch incidents**
    * **Incident type**
4.  Click **Test** to validate the URLs and token.

* * *

Commands
--------

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1.  [Search for incidents: rs-search-incidents](#search-for-incidents-rs-search-incidents)
2.  [Update an incident: rs-update-incident](#update-an-incident-rs-update-incident)
3.  [Get a list of incident members: rs-incident-get-members](#get-a-list-of-incident-members-rs-incident-get-members)
4.  [Get incident information: rs-get-incident](#get-incident-information-rs-get-incident)
5.  [Update information for an incident member: rs-incidents-update-member](#update-information-for-an-incident-member-rs-incidents-update-member)
6.  [Get a list of users: rs-get-users](#get-a-list-of-users-rs-get-users)
7.  [Close an incident: rs-close-incident](#close-an-incident-rs-close-incident)
8.  [Create an incident: rs-create-incident](#create-an-incident-rs-create-incident)
9.  [Get artifacts for an incident: rs-incident-artifacts](#get-artifacts-for-an-incident-rs-incident-artifacts)
10. [Get attachments of an incident: rs-incident-attachments](#get-attachments-of-an-incident-rs-incident-attachments)
11. [Get related incidents: rs-related-incidents](#get-related-incidents-rs-related-incidents)
12. [Get tasks for an incident: rs-incidents-get-tasks](#get-tasks-for-an-incident-rs-incidents-get-tasks)
13. [Add a note to an incident: rs-add-note](#add-a-note-to-an-incident-rs-add-note)
14. [Add an artifact to an incident: rs-add-artifact](#add-an-artifact-to-an-incident-rs-add-artifact)

### search for incidents: rs-search-incidents

Search for incidents in your IBM Resilient system.

##### Command Example

`!rs-search-incidents severity=Low,Medium incident-type=CommunicationError`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| severity | Incident severity (comma separated)<br><br>* Low<br>* Medium<br>* High |
| date-created-before | Created date of the incident before a specified date (YYYY-MM-DDTHH:MM:SSZ, for example, 2018-05-07T10:59:07Z) |
| date-created-after | Created date of the incident after a specified (format YYYY-MM-DDTHH:MM:SSZ, for example, 2018-05-07T10:59:07Z) |
| date-created-within-the-last | Created date of the incident within the last time frame (days/hours/minutes). Should be entered as a number, and used with the timeframe argument. |
| timeframe | Time frame to search within for incident. Should be used with within-the-last/due-in argument. |
| date-occurred-within-the-last | Occurred date of the incident within the last time frame (days/hours/minutes). Should be entered as a number, and used with with the timeframe argument. |
| date-occurred-before | Occurred date of the incident before given date (YYYY-MM-DDTHH:MM:SSZ, for example, 2018-05-07T10:59:07Z) |
| date-occurred-after | Occurred date of the incident after a specified date (YYYY-MM-DDTHH:MM:SSZ, for example, 2018-05-07T10:59:07Z) |
| incident-type | Incident type |
| nist | NIST Attack Vectors |
| status | Incident status |
| due-in | Due date of the incident in a specific timeframe (days/hours/minutes). Should be entered as a number, along with with the timeframe argument. |

##### Context Output

| **Path** | **Description** |
| --- | --- |
| Resilient.Incidents.CreateDate | Created date of the incident |
| Resilient.Incidents.Name | Incident name |
| Resilient.Incidents.DiscoveredDate | Discovered date of the incident |
| Resilient.Incidents.Id | Incident ID |
| Resilient.Incidents.Phase | Incident phase |
| Resilient.Incidents.Severity | Incident severity |
| Resilient.Incidents.Description | Incident description |

##### Raw Output

    DiscoveredDate:2018-05-18T08:49:38Z
    Id:2112
    Name:Incident Name
    Owner:Owner Name
    Phase:Respond
    Severity:Low

* * *

### Update an incident: rs-update-incident

Updater an incident in your IBM Resilient system.

##### Command Example

`!rs-update-incident incident-id=2222 severity=High incident-type=Malware`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| incident-id | Incident ID to update |
| severity | Severity to update |
| owner | User's full name set as the incident owner |
| incident-type | Incident type (added to the current incident types list) |
| resolution | Incident resolution |
| resolution-summary | Incident resolution summary |
| description | Incident description |
| name | Incident name |
| nist | NIST Attack Vectors (added to the current list of NIST attack vendors) |
| other-fields | A json object of the form: {field\_name: new\_field_value}. For example: {"description": {"textarea": {"format": "html", "content": "The new description"}}, "name": {"text": "The new name"}}. Because of API limitations we currently support only fields of the following types: ID, list of IDS, Number, Boolean, Text, Data, Textarea. In case of conflicts between the other-fields argument and the regular fields arguments, the other-fields will be taken.  <br>![](https://github.com/demisto/content/raw/3322c5933388f2ea9c52dc9fe31a5feb52bc1050/Packs/IBMResilientSystems/doc_files/support_field_types.png) |

##### Context Output

There is no context output for this command.

##### Raw Output

    Incident was updated successfully.

* * *

### Get a list of incident members: rs-incident-get-members

Get a list of members associated with the incident.

##### Command Example

`!rs-incidents-get-members incident-id=2111`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| incident-id | Incident ID to get members of |

##### Context Output

| **Path** | **Description** |
| --- | --- |
| Resilient.Incidents.Id | Incident ID |
| Resilient.Incidents.Members.FirstName | Member's first name |
| Resilient.Incidents.Members.LastName | Member's last name |
| Resilient.Incidents.Members.ID | Member's ID |
| Resilient.Incidents.Members.Email | Member's email address |

##### Raw Output

    [  
       {  
         Email:user1@mail.com 
         FirstName:User1First 
         ID:4      
         LastName:User1Last
       },
       {  
          Email:demisto@demisto.com 
          FirstName:Demisto 
          ID:1
          LastName:Demisto
       }
    ]

* * *

### Get incident information: rs-get-incident

Get information for an incident.

##### Command Example

`!rs-get-incident incident-id=2111`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| incident-id | Incident ID to get information for |

##### Context Output

| **Path** | **Description** |
| --- | --- |
| Resilient.Incidents.CreateDate | Created date of the incident |
| Resilient.Incidents.Name | Incident name |
| Resilient.Incidents.Resolution | Incident resolution |
| Resilient.Incidents.DiscoveredDate | Discovered date of the incident |
| Resilient.Incidents.ResolutionSummary | Incident resolution summary |
| Resilient.Incidents.Id | Incident ID |
| Resilient.Incidents.Phase | Incident phase |
| Resilient.Incidents.Severity | Incident severity |
| Resilient.Incidents.Description | Incident description |
| Resilient.Incidents.Confirmed | Incident confirmation |
| Resilient.Incidents.NegativePr | Negative PR likellihood |
| Resilient.Incidents.DateOccurred | Date occurred of incident |
| Resilient.Incidents.Reporter | Name of reporting individual |
| Resilient.Incidents.NistAttackVectors | Incident NIST attack vectors |

##### Raw Output

    {
        Confirmed:false
        CreatedDate:2018-05-22T23:47:25Z
        DateOccurred:2018-03-30T04:00:00Z
        Description:Desciprion
        DiscoveredDate:2018-05-01T04:00:00Z
        DueDate:2018-05-31T04:00:00Z
        ExposureType:Individual
        Id:2111
        Name:Incident name
        NegativePr:true
        NistAttackVectors:External/RemovableMedia
        Owner:Owner name
        Phase:Initial
        Reporter:Reporter name
        Resolution:Unresolved
        ResolutionSummary:summary
        Severity:Low
    }

* * *

### Update information for an incident member: rs-incidents-update-member

Update information for a member associated with an incident.

##### Command Example

`!rs-incidents-update-member incident-id=2111 members=1`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| incident-id | Incident ID to get information for |
| members | Members' IDs to set (comma separated) |

##### Context Output

There is no context output for this command.

##### Raw Output

    Email:demisto@demisto.com
    FirstName:Demisto
    ID:1
    LastName:Demisto

* * *

### Get a list of users: rs-get-users

Returns a list of users in the IBM Resilient system.

##### Command Example

`!rs-get-users`

##### Input

There is no input for this command.

##### Context Output

There is no context output for this command.

##### Raw Output

    [
      {
        Email:demistodev@demisto.com
        FirstName:Demisto
        ID:3
        LastName:Developer
      },
      {
        Email:demisto@demisto.com
        FirstName:Demisto
        ID:1
        LastName:Demisto
      }
    ]

* * *

### Close an incident: rs-close-incident

Close an incident in the IBM Resilient system.

##### Command Example

`!rs-close-incident incident-id=2111`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| incident-id | ID of the incident to close |

##### Context Output

There is no context output for this command.

##### Raw Output

    Incident 2111 was closed.

* * *

### Create an incident: rs-create-incident

Create an incident in the IBM Resilient system.

##### Command Example

`!rs-create-incident name=IncidentName`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| name | Incident name |

##### Context Output

There is no context output for this command.

##### Raw Output

    Incident  was created.

* * *

### Get artifacts for an incident: rs-incident-artifacts

Return artifacts for an incident in the IBM Resilient system.

##### Command Example

`!rs-incident-artifacts incident-id=2111`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| incident-id | Incident ID to get artifacts for |

##### Context Output

| **Path** | **Description** |
| --- | --- |
| Resilient.Incidents.Id | Incident ID |
| Resilient.Incidents.Name | Incident name |
| Resilient.Incidents.Artifacts.CreatedDate | Artifact created date |
| Resilient.Incidents.Artifacts.Creator | Artifact creator |
| Resilient.Incidents.Artifacts.Description | Artifact description |
| Resilient.Incidents.Artifacts.ID | Artifact ID |
| Resilient.Incidents.Artifacts.Type | Artifact type |
| Resilient.Incidents.Artifacts.Value | Artifact value |
| Resilient.Incidents.Artifacts.Attachments.ContentType | Attachment content type |
| Resilient.Incidents.Artifacts.Attachments.CreatedDate | Attachment created date |
| Resilient.Incidents.Artifacts.Attachments.Creator | Attachment creator |
| Resilient.Incidents.Artifacts.Attachments.ID | Attachment ID |
| Resilient.Incidents.Artifacts.Attachments.Name | Attachment name |
| Resilient.Incidents.Artifacts.Attachments.Size | Attachment size |

##### Raw Output

    {
      "Attachments":
        {
           "ContentType":"application/json",
           "CreatedDate":"2018-05-27T06:54:53Z",
           "Creator":"CreatorName",
           "ID":"4",
           "Name":"artifact.json",
           "Size":"3627"
        },
        {
           "CreatedDate":"2018-05-27T06:54:53Z",
           "Creator":"CreatorName",
           "ID":"5",
           "Type":"Email Attachment",
           "Value":"artifact.json"
        }
    }

* * *

### Get attachments of an incident: rs-incident-attachments

Return attachments for an incident in the IBM Resilient system.

##### Command Example

`!rs-incident-attachments incident-id=2111`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| incident-id | Incident ID to get attachments for |

##### Context Output

| **Path** | **Description** |
| --- | --- |
| Resilient.Incidents.Id | Incident ID |
| Resilient.Incidents.Name | Incident name |
| Resilient.Incidents.Owner | Incident owner |
| Resilient.Incidents.Attachments.ContentType | Attachment content type |
| Resilient.Incidents.Attachments.CreatedDate | Attachment created date |
| Resilient.Incidents.Attachments.Creator | Attachment creator |
| Resilient.Incidents.Attachments.ID | Attachment ID |
| Resilient.Incidents.Attachments.Name | Attachment name |
| Resilient.Incidents.Attachments.Size | Attachment size |

##### Raw Output

    {
      "ContentType":"image/png",
      "CreatedDate":"2018-05-28T06:40:28Z",
      "Creator":"CreatorName",
      "ID":"7",
      "Name":"image.png",
      "Size":"4491"
    }

* * *

### Get related incidents: rs-related-incidents

Get incidents related to a specified incident in the IBM Resilient system.

##### Command Example

`!rs-related-incidents incident-id=2111`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| incident-id | Incident ID to get related incidents for |

##### Context Output

| **Path** | **Description** |
| --- | --- |
| Resilient.Incidents.Id | Incident ID |
| Resilient.Incidents.Related.CreatedDate | Created date of related incident |
| Resilient.Incidents.Related.Name | Name of related incident |
| Resilient.Incidents.Related.ID | ID of related incident |
| Resilient.Incidents.Related.Status | Status (Active/Closed) of related incident |
| Resilient.Incidents.Related.Artifacts.CreatedDate | Created date of artifact |
| Resilient.Incidents.Related.Artifacts.ID | ID of artifact |
| Resilient.Incidents.Related.Artifacts.Creator | Creator of artifact |

##### Raw Output

    [
        {
            "artifacts": [
                {
                    "CreatedDate":"2018-05-27T06:26:37Z",
                    "Creator":"v",
                    "ID":3
                },
                {
                    "CreatedDate":"2018-05-27T06:29:49Z",
                    "Creator":"CreatorName",
                    "Description":"atta",
                    "ID":"4"
                },
                {
                    "CreatedDate":"2018-04-27T23:01:10Z",
                    "ID":2095,
                    "Name":"test Incident 1 - Email",
                    "Status":"Active"
                }
            ],
        }
    ]


* * *

### Get tasks for an incident: rs-incidents-get-tasks

Get tasks for an incident in the IBM Resilient system.

##### Command Example

`!rs-related-incidents incident-id=2111`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| incident-id | Incident ID to get tasks for |

##### Context Output

| **Path** | **Description** |
| --- | --- |
| Resilient.Incidents.Id | Incident ID |
| Resilient.Incidents.Name | Incident name |
| Resilient.Incidents.Tasks.Category | Task category |
| Resilient.Incidents.Tasks.Creator | Task creator |
| Resilient.Incidents.Tasks.DueDate | Task due date |
| Resilient.Incidents.Tasks.Form | Task form |
| Resilient.Incidents.Tasks.ID | Task ID |
| Resilient.Incidents.Tasks.Name | Task name |
| Resilient.Incidents.Tasks.Required | Task required |
| Resilient.Incidents.Tasks.Status | Task status (Open/Closed) |

##### Raw Output

    [
        {
            "Category":"Initial"
            "Creator":"CreatorName"
            DueDate:2018-05-31T04:00:00Z
            ID:2251303
            Name:task
            Required:true
            Status:Open
        },
        {
            Category:Respond
            Creator:CreatorName
            DueDate:2018-05-15T04:00:00Z
            Form:data_compromised
            ID:2251302
            Instructions:It is critical to determine whether personal information was foreseeably compromised or exposed. If so, this will drive a series of activities based on a myriad of breach notification regulations. Perform the necessary research to determine whether any personal information was possibly exposed to unauthorized individuals and update the value of the Data Compromised field and the information on the Incident Breach Information tab above or on the Details tab on the incident.
            Name:Investigate exposure of PI
            Required:true
            Status:Closed
        }
    ]

* * *

### Add a note to an incident: rs-add-note

Add a note to an incident.

##### Command Example

`!rs-add-note incident-id=2111 note="This is a note"`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| incident-id | Incident ID to add the note there |
| note | The text of the note |

##### Context Output

| **Path** | **Description** |
| --- | --- |
| Resilient.IncidentNote.type | The type of the note (incident or task) |
| Resilient.IncidentNote.id | The note's ID |
| Resilient.IncidentNote.parent_id | The ID of the parent note (null for top-level note) |
| Resilient.IncidentNote.user_id | The ID of the user who created the note |
| Resilient.IncidentNote.user_fname | The user's first name |
| Resilient.IncidentNote.user_lname | The user's last name |
| Resilient.IncidentNote.text | The note text |
| Resilient.IncidentNote.create_date | The date the note was created |
| Resilient.IncidentNote.modify_date | The date the note was modified |
| Resilient.IncidentNote.is_deleted | The flag indicating if the note is deleted |
| Resilient.IncidentNote.modify_user.id | The user that last modified the note |
| Resilient.IncidentNote.modify\_user.first\_name | The user's last name that last modified the note |
| Resilient.IncidentNote.modify\_user.last\_name | The user's first name that last modified the note |
| Resilient.IncidentNote.inc_id | The ID of the incident to which this note belongs |
| Resilient.IncidentNote.inc_name | The name of the incident to which this note belongs |
| Resilient.IncidentNote.task_id | The ID of the task to which this note belongs. Will be null on incident notes |
| Resilient.IncidentNote.task_name | The name of the task to which this note belongs. Will be null on incident notes |
| Resilient.IncidentNote.task_custom | For task note, whether or not that task is custom. Null for incident notes |
| Resilient.IncidentNote.task_members | For task notes, the list of that task's members, if any. Null for incident notes |
| Resilient.IncidentNote.task\_at\_id | For task notes, whether or not that task is an automatic task |
| Resilient.IncidentNote.inc_owner | The owner of the incident to which this note belongs |
| Resilient.IncidentNote.user_name | The owner of the incident to which this note belongs |
| Resilient.IncidentNote.modify_principal.id | The ID of the principal |
| Resilient.IncidentNote.modify_principal.type | The type of the principal Currently only user or group |
| Resilient.IncidentNote.modify_principal.name | The name of the principal |
| Resilient.IncidentNote.modify\_principal.display\_name | The display name of the principal |
| Resilient.IncidentNote.comment_perms.update | The permission of the current user to update this note |
| Resilient.IncidentNote.comment_perms.delete | The permission of the current user to delete this note |

##### Raw Output

    The note was added successfully to incident 2111.

* * *

### Add an artifact to an incident: rs-add-artifact

Add an artifact to an incident.

##### Command Example

`!rs-add-artifact incident-id=2111 artifact-type="IP Address" artifact-value="1.1.1.1" artifact-description"Description of the artifact"`

##### Input

| **Parameter** | **Description** |
| --- | --- |
| incident-id | Incident ID to add the artifact there |
| artifact-type | The type of the artifact |
| artifact-value | The value of the artifact |
| artifact-description | The description of the artifact |

##### Context Output

| **Path** | **Description** |
| --- | --- |
| Resilient.IncidentArtifact.id | The id of the artifact |
| Resilient.IncidentArtifact.type | The type of the artifact |
| Resilient.IncidentArtifact.value | The value of the artifact, this would be for example the IP address for an IP address artifact |
| Resilient.IncidentArtifact.description | The description of the artifact |
| Resilient.IncidentArtifact.attachment | The files are attached to the artifact |
| Resilient.IncidentArtifact.parent_id | The parent artifact ID |
| Resilient.IncidentArtifact.creator.id | The ID of the artifact creator |
| Resilient.IncidentArtifact.creator.fname | The first name of the artifact creator |
| Resilient.IncidentArtifact.creator.lname | The last name of the artifact creator |
| Resilient.IncidentArtifact.creator.display_name | The display name of the artifact creator |
| Resilient.IncidentArtifact.creator.status | The status of the artifact creator |
| Resilient.IncidentArtifact.creator.email | The email of the artifact creator |
| Resilient.IncidentArtifact.creator.phone | The phone number of the artifact creator |
| Resilient.IncidentArtifact.creator.cell | The cellphone number of the artifact creator |
| Resilient.IncidentArtifact.creator.title | The user's job title (e.g. Incident Response Manager) |
| Resilient.IncidentArtifact.creator.locked | The status of the creator's acount (true if locked false otherwise) |
| Resilient.IncidentArtifact.creator.password_changed | The user's password has changed (true if changed false otherwise) |
| Resilient.IncidentArtifact.creator.is_external | The user's account is authenticated externally |
| Resilient.IncidentArtifact.creator.ui_theme | The UI theme the user has selected. The Resilient UI recognizes the following values (darkmode lightmode verydarkmode) |
| Resilient.IncidentArtifact.inc_id | The incident ID |
| Resilient.IncidentArtifact.inc_name | The incident name |
| Resilient.IncidentArtifact.inc_owner | The incident owner |
| Resilient.IncidentArtifact.created | The date when the artifact is created |
| Resilient.IncidentArtifact.last\_modified\_time | The last date on which the artifact changed |
| Resilient.IncidentArtifact.last\_modified\_by.id | The ID of the last who changed the artifact |
| Resilient.IncidentArtifact.last\_modified\_by.type | The type of the last who changed the artifact |
| Resilient.IncidentArtifact.last\_modified\_by.name | The name of the last who changed the artifact |
| Resilient.IncidentArtifact.last\_modified\_by.display_name | The display name of the last who changed the artifact |
| Resilient.IncidentArtifact.perms.read | The permission of the current user to read this artifact |
| Resilient.IncidentArtifact.perms.write | The permission of the current user to write this artifact |
| Resilient.IncidentArtifact.perms.delete | The permission of the current user to delete this artifact |
| Resilient.IncidentArtifact.properties | The additional artifact properties |
| Resilient.IncidentArtifact.hash | The hash of the incident |
| Resilient.IncidentArtifact.relating | Whether or not this artifact should be used for relating to other incidents |
| Resilient.IncidentArtifact.creator_principal.id | The ID of the principal |
| Resilient.IncidentArtifact.creator_principal.type | The type of the principal. Currently only user or group |
| Resilient.IncidentArtifact.creator_principal.name | The API name of the principal |
| Resilient.IncidentArtifact.creator\_principal.display\_name | The display name of the principal |
| Resilient.IncidentArtifact.ip.source | The IP address is a source |
| Resilient.IncidentArtifact.ip.destination | The IP address is a destination |

##### Raw Output

    The artifact was added successfully to incident 2111.