# Integration Design
## Intro
In this tutorial we'll talk about how to get from an initial need or idea for an integration you want to implement in Demisto, to a design document that'll help you get organized and understand exactly what you need to implement.

## Why do I need a design document in the first place?
You might be thinking "Why do I need to write this document? Why not just start writing?" 
Well, we believe that writing such a document before starting any code writing will help you better understand your use of this integration, understand what exactly you want to do and what you want to get out of each command or fetch.
(We also require this documentation for our review and final inclusion in Demisto, but the former reason is the more important one).



## Identify What Type of Integration I'm Building
You can divide most integrations in Demisto into one of the following categories. We advise you to try to understand in which your integration fits in. Each link is to a short list of use-cases for such integration and examples of existing integrations and commands so that you can have some idea as to how or what to implement:
## Usecases
1. [Analytics and SIEM](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/Analytics_SIEM_usecase)
2. [Authentication](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/Authentication_usecase)
3. [Case Management](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/Case_Management_usecase)
4. [Data Enrichment and Threat Intelligence](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/Data_Enrichment_Threat_Intelligence_usecase)
5. [Email Gateway](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/Email_Gateway_usecase)
6. [Endpoint](https://github.com/demisto/internal-content/blob/master/documentation/design/usecases/Endpoint_usecase/README.MD)
7. [Forensics and Malware](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/forensics_malware_usecase)
8. [Network Security (Firewall)](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/network_security_IDS_IPS_usecase)
9. [Network Security (IDS/IPS)](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/network_security_firewall_usecase)
10. [Vulnerability Management](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/vulnerability_management_usecase)


## Understanding and Documenting the Use Cases
If your'e on your way to writing an integration for Demisto you probably are already familiar with the product you want to integrate, but it might help to go into the product again to see what actions you want to implemnt, how you think they'll work once in Demisto.
Write down the use cases for your integration, how you would use it and how you think outher people will use it.
```Markdown
# Use Cases:
- Create, get, edit, close a ticket/issue, add + view comments.
- Assign a ticket/issue to a specified user.
- List all tickets, filter by name, date, assignee
```

## Parameters
In this section write what are the parameters you need in order to create an instance of the product and connect to it. These parameters will be accessible and used in all the integration. 
We require 2 fields as part of the parameters:
1. proxy - You probably recoginze this field as "Use system proxy settings". This is a boolean field that handles proxy if True
2. insecure - (a.k.a. Trust any certificate (not secure)) This field is also boolean and indicates if to use only certified certificates.

When implementing the integration have a look at existing integrations to see how we implement this.
If your integration implements `Fetches incidents` also add a boolean field called `isFetch`

Some other comonly used paramteres:
1. url
2. apikey
3. token
4. crecentials (username + password)
5. query - Sometimes we want the user to specify the search query for fetch incidents (i.e. Splunkpy)
## Commands, Arguments & Outputs
Now let's write down exactly what commands you want to implement. Each command has 3 parts:
1. Command name
2. Command arguments
3. Command outputs
#### Command Name
We have a standard for a command's name: `brand-action`
For example `intsights-get-alert-activities`
If your commands checks the maliciousness of an IP/Domain/URL/File name your command simply `ip`\ `domain`\ `url`\ `file`. If this is the case make sure your outputs (which we'll get to in a second) match the [context standards](https://github.com/demisto/content/tree/master/docs/context_standards).

#### Command argument
These are the arguments for the command for example `!intsights-get-alert-activities alert-id=`, `!ip ip="8.8.8.8"`
Argument names must be snake case.
* Good: `alert-id`.
* Bad: `alertId`.

#### Command Outputs
There are 3 type of outputs from the command:
1. Human Readable output - This is what will be printed to the war room. It should be in Markdown form.
2. Raw Json - A JSON of the raw response that was returned from the API. 
3. Context Output - The outputs that will be in the context. 

The Context Outupt will be a JSON in the following format `{Product.TypeofOuput.Info}`. For more info about this have a look [here](https://github.com/demisto/content/tree/master/docs/context_and_ouputs)

### Command Design
The final result for each command should look something like this:

**Command Name**: cisco-asa-list-rules
###### Arguments
argument | type | description|mandatory
---|---|---|---
interface-name|String|the name of the interface|no
interface-type|choose|In/Out/Global|no

###### Context Outputs
* CiscoASA.Rule.Interface
* CiscoASA.Rule.SourceIP
* CiscoASA.Rule.DestIP
* CiscoASA.Rule.Permit
* CiscoASA.Rule.Active
* CiscoASA.Rule.Remarks
* CiscoASA.Rule.Position
* CiscoASA.Rule.ID
###### Human Readable Output
**All Rules for interface {} of type{}**:

RuleID|InterfaceName|SourceIP|DestIP|Position|
---|---|---|---|---|
124|Some Interface|1.1.1.1|2.2.2.2|6|


## Additinal Comments
1. Please  add a link to the REST API documentation to this document both so you could have it handy when needed and so we can have it ready when we review the integration.
2. Find a logo for this integration to be displayed in Demisto that is under 10 kb.
3. If caclulating DBot Score stay as close as possible to the vendor’s scoring thresholds and categorization (these are usually documented/can be understood from the UI). Dbot score reputation includes the following scores: 0 – unknown, 1 – good, 2 – suspicious, 3 – bad. Give users a threshold argument in order to let customers override and set another scoring logic.
4. The data we return should make sense to an analyst so please convert EPOCH, decrypt data if needed, If you return IDs, make sure to return the original asset name, category type, group name etc.
5. Stay as true to the product as possible- keep the same names as used by the vendor, the UI is a good baseline for what the human readable should look like.
6. If you think a command or fetch may return a lot of data - limit it. We allow 200 results max in Demisto. Make sure to include this in the design for each command that you limit.
7. If some commands may take a long time make sure you add a polling command. For example if you initiate a Compliance Search in EWS, an action that may take several minutes make sure you have a check-status command as well. ts accordingly, if a command needs major changes- deprecate it and add a new one
