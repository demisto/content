An Integration with McAfee ePO to fetch incidents, enrich investigations contexxt and automate remediation actions.
This integration was integrated and tested with version 5.10.0 of McAfee EPO
## Configure McAfeeEPOv2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for McAfeeEPOv2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | ePO Server URL | True |
    | ePO Username | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | First fetch time in miliseconds | False |
    | ePO Event Type | False |
    | Incident type | False |
    | Fetch incidents | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### epo-help
***
Print help information of ePO commands


#### Base Command

`epo-help`
#### Input

There are no input arguments for this command.

#### Command Example
```!epo-help```

#### Context Example
```json
{
    "McAfeeEPO": {
        "Help": [
            {
                "Command": "ComputerMgmt.AddVirtualMacVendorCommand",
                "CommandArguments": [
                    "vendorId",
                    "vendorNote"
                ],
                "Description": "Add Virtual MAC\r\nVendor with given ID and note."
            },
            {
                "Command": "ComputerMgmt.GetVirtualMacVendorCommand",
                "CommandArguments": [
                    "vendorId"
                ],
                "Description": "Get Virtual MAC Vendor detail\r\nfor the given ID."
            },
            {
                "Command": "ComputerMgmt.ListAllVirtualMacVendorsCommand",
                "CommandArguments": [],
                "Description": "Lists all Virtual MAC Vendors\r\nconfigured."
            },
            {
                "Command": "ComputerMgmt.createAgentDeploymentUrlCmd",
                "CommandArguments": [
                    "deployPath",
                    "groupId",
                    "urlName\r\nagentVersionNumber",
                    "agentHotFix",
                    "[edit]",
                    "[ahId]",
                    "[fallBackAhId]"
                ],
                "Description": "Create Agent\r\nDeployment URL Command"
            },
            {
                "Command": "ComputerMgmt.createCustomInstallPackageCmd",
                "CommandArguments": [
                    "deployPath",
                    "[ahId]",
                    "[fallBackAhId]",
                    "-\r\nCreate",
                    "Custom",
                    "Install",
                    "Package",
                    "Command"
                ],
                "Description": "No Description"
            },
            {
                "Command": "ComputerMgmt.createDefaultAgentDeploymentUrlCmd",
                "CommandArguments": [
                    "tenantId"
                ],
                "Description": "Create Default\r\nNon-Editable Agent Deployment URL Command"
            },
            {
                "Command": "ComputerMgmt.createTagGroup",
                "CommandArguments": [
                    "parentTagGroupId",
                    "newTagGroupName"
                ],
                "Description": "Create a new\r\nsubgroup under an existing tag group."
            },
            {
                "Command": "ComputerMgmt.deleteMacVendor",
                "CommandArguments": [
                    "vendorId"
                ],
                "Description": "Deletes a Virtual Mac Vendor."
            },
            {
                "Command": "ComputerMgmt.deleteTag",
                "CommandArguments": [
                    "tagIds",
                    "[forceDelete]"
                ],
                "Description": "Delete one or more tags."
            },
            {
                "Command": "ComputerMgmt.deleteTagGroup",
                "CommandArguments": [
                    "tagGroupIds",
                    "[deleteTags]"
                ],
                "Description": "Delete one or more Tag\r\nGroups."
            },
            {
                "Command": "ComputerMgmt.editMacVendor",
                "CommandArguments": [
                    "vendorId",
                    "newVendorId",
                    "newVendorNote"
                ],
                "Description": "Edits Virtual\r\nMac Vendor"
            },
            {
                "Command": "ComputerMgmt.listAllTagGroups",
                "CommandArguments": [],
                "Description": "List All Tag Groups in Tag Group Tree"
            },
            {
                "Command": "ComputerMgmt.moveTagsToTagGroup",
                "CommandArguments": [
                    "tagIds",
                    "tagGroupId"
                ],
                "Description": "Move tags to an existing tag\r\ngroup."
            },
            {
                "Command": "ComputerMgmt.renameTagGroup",
                "CommandArguments": [
                    "tagGroupId",
                    "renameTagGroupName"
                ],
                "Description": "Rename a tag group."
            },
            {
                "Command": "ENDP_FW_META.propertyTranslator",
                "CommandArguments": [
                    ""
                ],
                "Description": "Translates client rule properties and\r\npopulates appropriate database tables with this data."
            },
            {
                "Command": "ProductDeployment.createProductDeploymentTask",
                "CommandArguments": [
                    "[autoUpdate]",
                    "systemIds=<>\r\ndeploymentName=<>",
                    "productCodes=<>",
                    "packageBranches=<>",
                    "[actionsChosen=<>]\r\n[deploymentDescription=<>]",
                    "[commandLineParams=<>]",
                    "[everyPolicyEnforcement=<>]\r\n[canPostpone=<>]",
                    "[numPostpones=<>]",
                    "[postponeExpiresAfter=<>]",
                    "[displayText=<>]\r\n[startType=<>]",
                    "[startDate=<>]",
                    "[startTime=<>]",
                    "[timeZone=<>]\r\n[enableRandomization=<>]",
                    "[randomizationMinutes=<>]"
                ],
                "Description": "Create a new product\r\ndeployment task"
            },
            {
                "Command": "RepositoryMgmt.createHttpRepository",
                "CommandArguments": [
                    "name",
                    "url",
                    "uncPath",
                    "downloadUser\r\ndownloadPassword",
                    "uploadUser",
                    "uploadPassword",
                    "[softwareInclusionList]\r\n[softwareExclusionList]"
                ],
                "Description": "Remote command to create HTTP distributed repository."
            },
            {
                "Command": "RepositoryMgmt.createUncRepository",
                "CommandArguments": [
                    "name",
                    "uncPath",
                    "downloadUser",
                    "downloadPassword\r\nuploadUser",
                    "uploadPassword",
                    "[softwareInclusionList]",
                    "[softwareExclusionList]",
                    "-\r\nRemote",
                    "command",
                    "to",
                    "create",
                    "UNC",
                    "distributed",
                    "repository."
                ],
                "Description": "No Description"
            },
            {
                "Command": "agentmgmt.listAgentHandlers",
                "CommandArguments": [],
                "Description": "List all Agent Handlers"
            },
            {
                "Command": "clienttask.export",
                "CommandArguments": [
                    "[productId]",
                    "[fileName]"
                ],
                "Description": "Exports client tasks"
            },
            {
                "Command": "clienttask.find",
                "CommandArguments": [
                    "[searchText]"
                ],
                "Description": "Finds client tasks"
            },
            {
                "Command": "clienttask.importClientTask",
                "CommandArguments": [
                    "importFileName"
                ],
                "Description": "Imports client tasks from an XML\r\nfile."
            },
            {
                "Command": "clienttask.run",
                "CommandArguments": [
                    "names",
                    "productId",
                    "taskId",
                    "[retryAttempts]",
                    "[retryIntervalInSeconds]\r\n[abortAfterMinutes]",
                    "[useAllAgentHandlers]",
                    "[stopAfterMinutes]",
                    "[randomMinutes]\r\n[timeoutInHours]"
                ],
                "Description": "Runs the client task on a supplied list of systems"
            },
            {
                "Command": "clienttask.syncShared",
                "CommandArguments": [],
                "Description": "Shares client tasks with participating registered\r\nservers"
            },
            {
                "Command": "commonevent.purgeEvents",
                "CommandArguments": [
                    "queryId",
                    "[unit]",
                    "[purgeType]"
                ],
                "Description": "Deletes threat events based\r\non age or a queryId. The query must be table-based."
            },
            {
                "Command": "commonevent.purgeProductEvents",
                "CommandArguments": [
                    "queryId",
                    "[unit]",
                    "[purgeType]"
                ],
                "Description": "Purge Client Events\r\nby Query ID or age."
            },
            {
                "Command": "console.cert.updatecrl",
                "CommandArguments": [
                    "console.updateCRL",
                    "crlFile"
                ],
                "Description": "cert.update.crl.help.oneline"
            },
            {
                "Command": "core.addPermSetsForUser",
                "CommandArguments": [
                    "userName",
                    "permSetName"
                ],
                "Description": "Adds permission set(s) to\r\nspecified user"
            },
            {
                "Command": "core.addUser",
                "CommandArguments": [
                    "userName",
                    "password",
                    "[fullName=<>]",
                    "[email=<>]",
                    "[phoneNumber=<>]\r\n[notes=<>]",
                    "[allowedIPs=<>]",
                    "[disabled=<>]",
                    "[admin=<>]",
                    "[retryTolerant=<>]"
                ],
                "Description": "Adds a\r\nuser to the system"
            },
            {
                "Command": "core.executeQuery",
                "CommandArguments": [
                    "queryId",
                    "[database=<>]"
                ],
                "Description": "Executes a SQUID query and returns the\r\nresults"
            },
            {
                "Command": "core.exportPermissionSets",
                "CommandArguments": [],
                "Description": "Exports all permission sets."
            },
            {
                "Command": "core.help",
                "CommandArguments": [
                    "[command]",
                    "[prefix=<>]"
                ],
                "Description": "Displays a list of all commands and help\r\nstrings."
            },
            {
                "Command": "core.importPermissionSets",
                "CommandArguments": [
                    "file",
                    "[overwrite]"
                ],
                "Description": "Imports permission sets."
            },
            {
                "Command": "core.listDatabases",
                "CommandArguments": [],
                "Description": "Displays all registered databases that the user is\r\npermitted to see."
            },
            {
                "Command": "core.listDatatypes",
                "CommandArguments": [
                    "[type]"
                ],
                "Description": "Displays all registered datatypes and operations for\r\nthose types that the user is permitted to see."
            },
            {
                "Command": "core.listPermSets",
                "CommandArguments": [
                    "[userName]"
                ],
                "Description": "List permission sets in the system"
            },
            {
                "Command": "core.listQueries",
                "CommandArguments": [],
                "Description": "Displays all queries that the user is permitted to see."
            },
            {
                "Command": "core.listTables",
                "CommandArguments": [
                    "[table]"
                ],
                "Description": "Displays all SQUID tables that the user is permitted\r\nto see."
            },
            {
                "Command": "core.listUsers",
                "CommandArguments": [
                    "[permSetName]"
                ],
                "Description": "List users in the system"
            },
            {
                "Command": "core.purgeAuditLog",
                "CommandArguments": [
                    "[age]",
                    "[unit]"
                ],
                "Description": "Purge the Audit Log by age"
            },
            {
                "Command": "core.removePermSetsForUser",
                "CommandArguments": [
                    "userName",
                    "permSetName"
                ],
                "Description": "Removes permission set(s) from\r\na specified user"
            },
            {
                "Command": "core.removeUser",
                "CommandArguments": [
                    "userName"
                ],
                "Description": "Removes a user from the system"
            },
            {
                "Command": "core.updateUser",
                "CommandArguments": [
                    "userName",
                    "[password=<>]",
                    "[windowsUserName=<>]",
                    "[windowsDomain=<>]\r\n[subjectDN=<>]",
                    "[newUserName=<>]",
                    "[fullName=<>]",
                    "[email=<>]",
                    "[phoneNumber=<>]\r\n[allowedIPs=<>]",
                    "[notes=<>]",
                    "[disabled=<>]",
                    "[admin=<>]"
                ],
                "Description": "Updates an existing user"
            },
            {
                "Command": "epo.getVersion",
                "CommandArguments": [],
                "Description": "Gets the McAfee ePO version"
            },
            {
                "Command": "epo.purgeComplianceHistory",
                "CommandArguments": [
                    "queryId",
                    "[unit]"
                ],
                "Description": "Purges compliance events by query or\r\nage"
            },
            {
                "Command": "epo.syncDirectory",
                "CommandArguments": [
                    "[syncPointList]"
                ],
                "Description": "Synchronizes Domains/AD"
            },
            {
                "Command": "epogroup.findSystems",
                "CommandArguments": [
                    "groupId",
                    "[searchSubgroups]"
                ],
                "Description": "Find computers within a given\r\ngroup in the McAfee ePO tree"
            },
            {
                "Command": "issue.createIssue",
                "CommandArguments": [
                    "name=<>",
                    "desc=<>",
                    "[type=<>]",
                    "[state=<>]",
                    "[priority=<>]\r\n[severity=<>]",
                    "[resolution=<>]",
                    "[due=<>]",
                    "[assigneeName=<>]",
                    "[ticketServerName=<>]\r\n[ticketId=<>]",
                    "[properties=<>]"
                ],
                "Description": "Creates an issue"
            },
            {
                "Command": "issue.deleteIssue",
                "CommandArguments": [
                    "id=<>"
                ],
                "Description": "Deletes issues"
            },
            {
                "Command": "issue.listIssues",
                "CommandArguments": [
                    "[id=<>]"
                ],
                "Description": "Lists issues"
            },
            {
                "Command": "issue.updateIssue",
                "CommandArguments": [
                    "id=<>",
                    "[name=<>]",
                    "[desc=<>]",
                    "[state=<>]",
                    "[priority=<>]\r\n[severity=<>]",
                    "[resolution=<>]",
                    "[due=<>]",
                    "[assigneeName=<>]",
                    "[ticketServerName=<>]\r\n[ticketId=<>]",
                    "[properties=<>]"
                ],
                "Description": "Updates an issue"
            },
            {
                "Command": "ldap.populateCache",
                "CommandArguments": [
                    "[rsName]"
                ],
                "Description": "Rediscovers and populates Registered Servers\r\nmappings with domains"
            },
            {
                "Command": "policy.assignToGroup",
                "CommandArguments": [
                    "groupId",
                    "productId",
                    "objectId",
                    "[resetInheritance]"
                ],
                "Description": "Assigns\r\npolicy to the specified group"
            },
            {
                "Command": "policy.assignToSystem",
                "CommandArguments": [
                    "names",
                    "productId",
                    "typeId",
                    "objectId",
                    "[resetInheritance]",
                    "-\r\nAssigns",
                    "the",
                    "policy",
                    "to",
                    "a",
                    "supplied",
                    "list",
                    "of",
                    "systems"
                ],
                "Description": "No Description"
            },
            {
                "Command": "policy.export",
                "CommandArguments": [
                    "productId",
                    "[fileName]"
                ],
                "Description": "Exports policies"
            },
            {
                "Command": "policy.find",
                "CommandArguments": [
                    "[searchText]"
                ],
                "Description": "Finds all policies that the user is permitted to see\r\nthat match the given search text."
            },
            {
                "Command": "policy.importPolicy",
                "CommandArguments": [
                    "file",
                    "[force]"
                ],
                "Description": "Imports policies"
            },
            {
                "Command": "policy.syncShared",
                "CommandArguments": [],
                "Description": "Shares policies with participating registered servers"
            },
            {
                "Command": "repository.changeBranch",
                "CommandArguments": [
                    "productId",
                    "packageType",
                    "sourceBranch",
                    "targetBranch",
                    "[move]",
                    "-\r\nChange",
                    "the",
                    "Branch",
                    "for",
                    "a",
                    "Package"
                ],
                "Description": "No Description"
            },
            {
                "Command": "repository.checkInPackage",
                "CommandArguments": [
                    "packageLocation",
                    "branch",
                    "[option]",
                    "[force]"
                ],
                "Description": "Checks\r\npackage into the Master Repository"
            },
            {
                "Command": "repository.deletePackage",
                "CommandArguments": [
                    "productId",
                    "packageType",
                    "branch"
                ],
                "Description": "Deletes Package from the\r\nMaster Repository"
            },
            {
                "Command": "repository.export",
                "CommandArguments": [
                    "[fileName]"
                ],
                "Description": "Exports repositories"
            },
            {
                "Command": "repository.find",
                "CommandArguments": [
                    "[searchText]"
                ],
                "Description": "Finds all repositories that the user is permitted\r\nto see that match the given search text."
            },
            {
                "Command": "repository.findPackages",
                "CommandArguments": [
                    "[searchText]"
                ],
                "Description": "Finds Packages"
            },
            {
                "Command": "repository.importRepositories",
                "CommandArguments": [
                    "file",
                    "repositoryType",
                    "[overwrite]"
                ],
                "Description": "Imports\r\nrepositories"
            },
            {
                "Command": "repository.pull",
                "CommandArguments": [
                    "sourceRepository",
                    "targetBranch",
                    "moveToPrevious",
                    "productList"
                ],
                "Description": "Pulls\r\npackages from the source repository and puts them into the Master Repository"
            },
            {
                "Command": "repository.replicate",
                "CommandArguments": [
                    "[repositoryList]",
                    "[incremental]"
                ],
                "Description": "Replicate"
            },
            {
                "Command": "scheduler.cancelServerTask",
                "CommandArguments": [
                    "taskLogId"
                ],
                "Description": "Ends a currently running task"
            },
            {
                "Command": "scheduler.getServerTask",
                "CommandArguments": [
                    "taskName"
                ],
                "Description": "Gets details about a specific server task"
            },
            {
                "Command": "scheduler.listAllServerTasks",
                "CommandArguments": [],
                "Description": "Displays all server tasks"
            },
            {
                "Command": "scheduler.listRunningServerTasks",
                "CommandArguments": [],
                "Description": "Get the list of all running server tasks."
            },
            {
                "Command": "scheduler.runServerTask",
                "CommandArguments": [
                    "taskName"
                ],
                "Description": "Runs a server task and returns the task log\r\nID."
            },
            {
                "Command": "scheduler.updateServerTask",
                "CommandArguments": [
                    "taskName",
                    "[status]"
                ],
                "Description": "Enables or disables a server task\r\n(by default status='enabled')"
            },
            {
                "Command": "system.applyTag",
                "CommandArguments": [
                    "names",
                    "tagName"
                ],
                "Description": "Assigns the given tag to a supplied list of\r\nsystems"
            },
            {
                "Command": "system.clearTag",
                "CommandArguments": [
                    "names",
                    "tagName",
                    "[all]"
                ],
                "Description": "Clears the tag from supplied systems"
            },
            {
                "Command": "system.delete",
                "CommandArguments": [
                    "names",
                    "[uninstall]",
                    "[uninstallSoftware]"
                ],
                "Description": "Deletes systems from the\r\nSystem Tree by name or ID."
            },
            {
                "Command": "system.deployAgent",
                "CommandArguments": [
                    "names",
                    "username",
                    "[password]",
                    "[agentPackage]",
                    "[skipIfInstalled]\r\n[suppressUI]",
                    "[forceInstall]",
                    "[installPath]",
                    "[domain]",
                    "[useAllHandlers]\r\n[primaryAgentHandler]",
                    "[retryIntervalSeconds]",
                    "[attempts]",
                    "[abortAfterMinutes]\r\n[includeSubgroups]",
                    "[useSsh]",
                    "[inputSource]"
                ],
                "Description": "Deploys an agent to the given list\r\nof systems"
            },
            {
                "Command": "system.excludeTag",
                "CommandArguments": [
                    "names",
                    "tagName"
                ],
                "Description": "Excludes the tag from supplied systems"
            },
            {
                "Command": "system.exportTag",
                "CommandArguments": [
                    "[fileName]"
                ],
                "Description": "Export Tags"
            },
            {
                "Command": "system.find",
                "CommandArguments": [
                    "searchText",
                    "[searchNameOnly]"
                ],
                "Description": "Finds systems in the System Tree"
            },
            {
                "Command": "system.findGroups",
                "CommandArguments": [
                    "[searchText]"
                ],
                "Description": "Finds groups in the System Tree"
            },
            {
                "Command": "system.findTag",
                "CommandArguments": [
                    "[searchText]"
                ],
                "Description": "Find Tags"
            },
            {
                "Command": "system.importSystem",
                "CommandArguments": [
                    "names",
                    "branchNodeID",
                    "[allowDuplicates]",
                    "[uninstallRemoved]\r\n[pushAgent]",
                    "[pushAgentForceInstall]",
                    "[pushAgentSkipIfInstalled]\r\n[pushAgentSuppressUI]",
                    "[pushAgentInstallPath]",
                    "[pushAgentPackagePath]\r\n[pushAgentDomainName]",
                    "[pushAgentUserName]",
                    "[pushAgentPassword]",
                    "[deleteIfRemoved]\r\n[flattenTreeStructure]"
                ],
                "Description": "Imports systems"
            },
            {
                "Command": "system.importTag",
                "CommandArguments": [
                    "uploadFile",
                    "[force]"
                ],
                "Description": "Imports Tags"
            },
            {
                "Command": "system.move",
                "CommandArguments": [
                    "names",
                    "parentGroupId",
                    "[autoSort]"
                ],
                "Description": "Moves systems to the specified\r\ndestination group."
            },
            {
                "Command": "system.resort",
                "CommandArguments": [
                    "names"
                ],
                "Description": "Resorts the systems in the System Tree"
            },
            {
                "Command": "system.runTagCriteria",
                "CommandArguments": [
                    "tagID",
                    "[resetTaggedSystems]"
                ],
                "Description": "The Run Tag Criteria action\r\nevaluates every managed system against the tag's criteria."
            },
            {
                "Command": "system.setUserProperties",
                "CommandArguments": [
                    "names",
                    "[description]",
                    "[customField1]",
                    "[customField2]\r\n[customField3]",
                    "[customField4]"
                ],
                "Description": "Sets user properties on the given system"
            },
            {
                "Command": "system.transfer",
                "CommandArguments": [
                    "names",
                    "epoServer"
                ],
                "Description": "Transfers systems to a different McAfee ePO\r\nserver"
            },
            {
                "Command": "system.wakeupAgent",
                "CommandArguments": [
                    "names",
                    "[fullProps]",
                    "[superAgent]",
                    "[randomMinutes]\r\n[forceFullPolicyUpdate]",
                    "[useAllHandlers]",
                    "[retryIntervalSeconds]",
                    "[attempts]\r\n[abortAfterMinutes]",
                    "[includeSubgroups]"
                ],
                "Description": "Wakes up the agent on a supplied list\r\nof systems"
            },
            {
                "Command": "tasklog.listMessages",
                "CommandArguments": [
                    "taskLogId"
                ],
                "Description": "Lists the messages for the specified task log\r\nentry"
            },
            {
                "Command": "tasklog.listSubtasks",
                "CommandArguments": [
                    "taskLogId"
                ],
                "Description": "Lists subtasks of a specified task log entry"
            },
            {
                "Command": "tasklog.listTaskHistory",
                "CommandArguments": [
                    "[taskName]",
                    "[taskSource]",
                    "[maxRows]",
                    "[age]",
                    "[unit]"
                ],
                "Description": "Lists\r\ntask log entries, optionally filtered by task name, task ID, or task source"
            },
            {
                "Command": "tasklog.listTaskSources",
                "CommandArguments": [],
                "Description": "Lists the task sources"
            },
            {
                "Command": "tasklog.purge",
                "CommandArguments": [
                    "[age]",
                    "[unit]"
                ],
                "Description": "Purges the Server Task Log beyond a given age and\r\ntime unit"
            },
            {
                "Command": "telemetry.contentRuleEngine.collect",
                "CommandArguments": [
                    "[filePath-at-ePO]"
                ],
                "Description": "No Description"
            },
            {
                "Command": "telemetry.uploadTask.runNow",
                "CommandArguments": [
                    "No",
                    "Arguments"
                ],
                "Description": "No Description"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Command|CommandArguments|Description|
>|---|---|---|
>| ComputerMgmt.AddVirtualMacVendorCommand | vendorId,<br/>vendorNote | Add Virtual MAC<br/>Vendor with given ID and note. |
>| ComputerMgmt.GetVirtualMacVendorCommand | vendorId | Get Virtual MAC Vendor detail<br/>for the given ID. |
>| ComputerMgmt.ListAllVirtualMacVendorsCommand |  | Lists all Virtual MAC Vendors<br/>configured. |
>| ComputerMgmt.createAgentDeploymentUrlCmd | deployPath,<br/>groupId,<br/>urlName<br/>agentVersionNumber,<br/>agentHotFix,<br/>[edit],<br/>[ahId],<br/>[fallBackAhId] | Create Agent<br/>Deployment URL Command |
>| ComputerMgmt.createCustomInstallPackageCmd | deployPath,<br/>[ahId],<br/>[fallBackAhId],<br/>-<br/>Create,<br/>Custom,<br/>Install,<br/>Package,<br/>Command | No Description |
>| ComputerMgmt.createDefaultAgentDeploymentUrlCmd | tenantId | Create Default<br/>Non-Editable Agent Deployment URL Command |
>| ComputerMgmt.createTagGroup | parentTagGroupId,<br/>newTagGroupName | Create a new<br/>subgroup under an existing tag group. |
>| ComputerMgmt.deleteMacVendor | vendorId | Deletes a Virtual Mac Vendor. |
>| ComputerMgmt.deleteTag | tagIds,<br/>[forceDelete] | Delete one or more tags. |
>| ComputerMgmt.deleteTagGroup | tagGroupIds,<br/>[deleteTags] | Delete one or more Tag<br/>Groups. |
>| ComputerMgmt.editMacVendor | vendorId,<br/>newVendorId,<br/>newVendorNote | Edits Virtual<br/>Mac Vendor |
>| ComputerMgmt.listAllTagGroups |  | List All Tag Groups in Tag Group Tree |
>| ComputerMgmt.moveTagsToTagGroup | tagIds,<br/>tagGroupId | Move tags to an existing tag<br/>group. |
>| ComputerMgmt.renameTagGroup | tagGroupId,<br/>renameTagGroupName | Rename a tag group. |
>| ENDP_FW_META.propertyTranslator |  | Translates client rule properties and<br/>populates appropriate database tables with this data. |
>| ProductDeployment.createProductDeploymentTask | [autoUpdate],<br/>systemIds=<><br/>deploymentName=<>,<br/>productCodes=<>,<br/>packageBranches=<>,<br/>[actionsChosen=<>]<br/>[deploymentDescription=<>],<br/>[commandLineParams=<>],<br/>[everyPolicyEnforcement=<>]<br/>[canPostpone=<>],<br/>[numPostpones=<>],<br/>[postponeExpiresAfter=<>],<br/>[displayText=<>]<br/>[startType=<>],<br/>[startDate=<>],<br/>[startTime=<>],<br/>[timeZone=<>]<br/>[enableRandomization=<>],<br/>[randomizationMinutes=<>] | Create a new product<br/>deployment task |
>| RepositoryMgmt.createHttpRepository | name,<br/>url,<br/>uncPath,<br/>downloadUser<br/>downloadPassword,<br/>uploadUser,<br/>uploadPassword,<br/>[softwareInclusionList]<br/>[softwareExclusionList] | Remote command to create HTTP distributed repository. |
>| RepositoryMgmt.createUncRepository | name,<br/>uncPath,<br/>downloadUser,<br/>downloadPassword<br/>uploadUser,<br/>uploadPassword,<br/>[softwareInclusionList],<br/>[softwareExclusionList],<br/>-<br/>Remote,<br/>command,<br/>to,<br/>create,<br/>UNC,<br/>distributed,<br/>repository. | No Description |
>| agentmgmt.listAgentHandlers |  | List all Agent Handlers |
>| clienttask.export | [productId],<br/>[fileName] | Exports client tasks |
>| clienttask.find | [searchText] | Finds client tasks |
>| clienttask.importClientTask | importFileName | Imports client tasks from an XML<br/>file. |
>| clienttask.run | names,<br/>productId,<br/>taskId,<br/>[retryAttempts],<br/>[retryIntervalInSeconds]<br/>[abortAfterMinutes],<br/>[useAllAgentHandlers],<br/>[stopAfterMinutes],<br/>[randomMinutes]<br/>[timeoutInHours] | Runs the client task on a supplied list of systems |
>| clienttask.syncShared |  | Shares client tasks with participating registered<br/>servers |
>| commonevent.purgeEvents | queryId,<br/>[unit],<br/>[purgeType] | Deletes threat events based<br/>on age or a queryId. The query must be table-based. |
>| commonevent.purgeProductEvents | queryId,<br/>[unit],<br/>[purgeType] | Purge Client Events<br/>by Query ID or age. |
>| console.cert.updatecrl | console.updateCRL,<br/>crlFile | cert.update.crl.help.oneline |
>| core.addPermSetsForUser | userName,<br/>permSetName | Adds permission set(s) to<br/>specified user |
>| core.addUser | userName,<br/>password,<br/>[fullName=<>],<br/>[email=<>],<br/>[phoneNumber=<>]<br/>[notes=<>],<br/>[allowedIPs=<>],<br/>[disabled=<>],<br/>[admin=<>],<br/>[retryTolerant=<>] | Adds a<br/>user to the system |
>| core.executeQuery | queryId,<br/>[database=<>] | Executes a SQUID query and returns the<br/>results |
>| core.exportPermissionSets |  | Exports all permission sets. |
>| core.help | [command],<br/>[prefix=<>] | Displays a list of all commands and help<br/>strings. |
>| core.importPermissionSets | file,<br/>[overwrite] | Imports permission sets. |
>| core.listDatabases |  | Displays all registered databases that the user is<br/>permitted to see. |
>| core.listDatatypes | [type] | Displays all registered datatypes and operations for<br/>those types that the user is permitted to see. |
>| core.listPermSets | [userName] | List permission sets in the system |
>| core.listQueries |  | Displays all queries that the user is permitted to see. |
>| core.listTables | [table] | Displays all SQUID tables that the user is permitted<br/>to see. |
>| core.listUsers | [permSetName] | List users in the system |
>| core.purgeAuditLog | [age],<br/>[unit] | Purge the Audit Log by age |
>| core.removePermSetsForUser | userName,<br/>permSetName | Removes permission set(s) from<br/>a specified user |
>| core.removeUser | userName | Removes a user from the system |
>| core.updateUser | userName,<br/>[password=<>],<br/>[windowsUserName=<>],<br/>[windowsDomain=<>]<br/>[subjectDN=<>],<br/>[newUserName=<>],<br/>[fullName=<>],<br/>[email=<>],<br/>[phoneNumber=<>]<br/>[allowedIPs=<>],<br/>[notes=<>],<br/>[disabled=<>],<br/>[admin=<>] | Updates an existing user |
>| epo.getVersion |  | Gets the McAfee ePO version |
>| epo.purgeComplianceHistory | queryId,<br/>[unit] | Purges compliance events by query or<br/>age |
>| epo.syncDirectory | [syncPointList] | Synchronizes Domains/AD |
>| epogroup.findSystems | groupId,<br/>[searchSubgroups] | Find computers within a given<br/>group in the McAfee ePO tree |
>| issue.createIssue | name=<>,<br/>desc=<>,<br/>[type=<>],<br/>[state=<>],<br/>[priority=<>]<br/>[severity=<>],<br/>[resolution=<>],<br/>[due=<>],<br/>[assigneeName=<>],<br/>[ticketServerName=<>]<br/>[ticketId=<>],<br/>[properties=<>] | Creates an issue |
>| issue.deleteIssue | id=<> | Deletes issues |
>| issue.listIssues | [id=<>] | Lists issues |
>| issue.updateIssue | id=<>,<br/>[name=<>],<br/>[desc=<>],<br/>[state=<>],<br/>[priority=<>]<br/>[severity=<>],<br/>[resolution=<>],<br/>[due=<>],<br/>[assigneeName=<>],<br/>[ticketServerName=<>]<br/>[ticketId=<>],<br/>[properties=<>] | Updates an issue |
>| ldap.populateCache | [rsName] | Rediscovers and populates Registered Servers<br/>mappings with domains |
>| policy.assignToGroup | groupId,<br/>productId,<br/>objectId,<br/>[resetInheritance] | Assigns<br/>policy to the specified group |
>| policy.assignToSystem | names,<br/>productId,<br/>typeId,<br/>objectId,<br/>[resetInheritance],<br/>-<br/>Assigns,<br/>the,<br/>policy,<br/>to,<br/>a,<br/>supplied,<br/>list,<br/>of,<br/>systems | No Description |
>| policy.export | productId,<br/>[fileName] | Exports policies |
>| policy.find | [searchText] | Finds all policies that the user is permitted to see<br/>that match the given search text. |
>| policy.importPolicy | file,<br/>[force] | Imports policies |
>| policy.syncShared |  | Shares policies with participating registered servers |
>| repository.changeBranch | productId,<br/>packageType,<br/>sourceBranch,<br/>targetBranch,<br/>[move],<br/>-<br/>Change,<br/>the,<br/>Branch,<br/>for,<br/>a,<br/>Package | No Description |
>| repository.checkInPackage | packageLocation,<br/>branch,<br/>[option],<br/>[force] | Checks<br/>package into the Master Repository |
>| repository.deletePackage | productId,<br/>packageType,<br/>branch | Deletes Package from the<br/>Master Repository |
>| repository.export | [fileName] | Exports repositories |
>| repository.find | [searchText] | Finds all repositories that the user is permitted<br/>to see that match the given search text. |
>| repository.findPackages | [searchText] | Finds Packages |
>| repository.importRepositories | file,<br/>repositoryType,<br/>[overwrite] | Imports<br/>repositories |
>| repository.pull | sourceRepository,<br/>targetBranch,<br/>moveToPrevious,<br/>productList | Pulls<br/>packages from the source repository and puts them into the Master Repository |
>| repository.replicate | [repositoryList],<br/>[incremental] | Replicate |
>| scheduler.cancelServerTask | taskLogId | Ends a currently running task |
>| scheduler.getServerTask | taskName | Gets details about a specific server task |
>| scheduler.listAllServerTasks |  | Displays all server tasks |
>| scheduler.listRunningServerTasks |  | Get the list of all running server tasks. |
>| scheduler.runServerTask | taskName | Runs a server task and returns the task log<br/>ID. |
>| scheduler.updateServerTask | taskName,<br/>[status] | Enables or disables a server task<br/>(by default status='enabled') |
>| system.applyTag | names,<br/>tagName | Assigns the given tag to a supplied list of<br/>systems |
>| system.clearTag | names,<br/>tagName,<br/>[all] | Clears the tag from supplied systems |
>| system.delete | names,<br/>[uninstall],<br/>[uninstallSoftware] | Deletes systems from the<br/>System Tree by name or ID. |
>| system.deployAgent | names,<br/>username,<br/>[password],<br/>[agentPackage],<br/>[skipIfInstalled]<br/>[suppressUI],<br/>[forceInstall],<br/>[installPath],<br/>[domain],<br/>[useAllHandlers]<br/>[primaryAgentHandler],<br/>[retryIntervalSeconds],<br/>[attempts],<br/>[abortAfterMinutes]<br/>[includeSubgroups],<br/>[useSsh],<br/>[inputSource] | Deploys an agent to the given list<br/>of systems |
>| system.excludeTag | names,<br/>tagName | Excludes the tag from supplied systems |
>| system.exportTag | [fileName] | Export Tags |
>| system.find | searchText,<br/>[searchNameOnly] | Finds systems in the System Tree |
>| system.findGroups | [searchText] | Finds groups in the System Tree |
>| system.findTag | [searchText] | Find Tags |
>| system.importSystem | names,<br/>branchNodeID,<br/>[allowDuplicates],<br/>[uninstallRemoved]<br/>[pushAgent],<br/>[pushAgentForceInstall],<br/>[pushAgentSkipIfInstalled]<br/>[pushAgentSuppressUI],<br/>[pushAgentInstallPath],<br/>[pushAgentPackagePath]<br/>[pushAgentDomainName],<br/>[pushAgentUserName],<br/>[pushAgentPassword],<br/>[deleteIfRemoved]<br/>[flattenTreeStructure] | Imports systems |
>| system.importTag | uploadFile,<br/>[force] | Imports Tags |
>| system.move | names,<br/>parentGroupId,<br/>[autoSort] | Moves systems to the specified<br/>destination group. |
>| system.resort | names | Resorts the systems in the System Tree |
>| system.runTagCriteria | tagID,<br/>[resetTaggedSystems] | The Run Tag Criteria action<br/>evaluates every managed system against the tag's criteria. |
>| system.setUserProperties | names,<br/>[description],<br/>[customField1],<br/>[customField2]<br/>[customField3],<br/>[customField4] | Sets user properties on the given system |
>| system.transfer | names,<br/>epoServer | Transfers systems to a different McAfee ePO<br/>server |
>| system.wakeupAgent | names,<br/>[fullProps],<br/>[superAgent],<br/>[randomMinutes]<br/>[forceFullPolicyUpdate],<br/>[useAllHandlers],<br/>[retryIntervalSeconds],<br/>[attempts]<br/>[abortAfterMinutes],<br/>[includeSubgroups] | Wakes up the agent on a supplied list<br/>of systems |
>| tasklog.listMessages | taskLogId | Lists the messages for the specified task log<br/>entry |
>| tasklog.listSubtasks | taskLogId | Lists subtasks of a specified task log entry |
>| tasklog.listTaskHistory | [taskName],<br/>[taskSource],<br/>[maxRows],<br/>[age],<br/>[unit] | Lists<br/>task log entries, optionally filtered by task name, task ID, or task source |
>| tasklog.listTaskSources |  | Lists the task sources |
>| tasklog.purge | [age],<br/>[unit] | Purges the Server Task Log beyond a given age and<br/>time unit |
>| telemetry.contentRuleEngine.collect | [filePath-at-ePO] | No Description |
>| telemetry.uploadTask.runNow | No,<br/>Arguments | No Description |


### epo-get-latest-dat
***
Checks the latest DAT file in the McAfee repository.


#### Base Command

`epo-get-latest-dat`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeEPO.LatestDat.CurrentVersion | Unknown | Update DAT Version | 


#### Command Example
```!epo-get-latest-dat```

#### Context Example
```json
{
    "McAfeeEPO": {
        "LatestDat": {
            "CurrentVersion": "9947"
        }
    }
}
```

#### Human Readable Output

>### Results
>|CurrentVersion|
>|---|
>| 9947 |


### epo-get-system-tree-group
***
Return System Tree Groups


#### Base Command

`epo-get-system-tree-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | String to search by. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeEPO.SystemGroups.groupId | Unknown | Group ID | 
| McAfeeEPO.SystemGroups.groupPath | Unknown | Group Path | 


#### Command Example
```!epo-get-system-tree-group query="Lab"```

#### Context Example
```json
{
    "McAfeeEPO": {
        "SystemGroups": {
            "groupId": 4,
            "groupPath": "My Organization\\Lab"
        }
    }
}
```

#### Human Readable Output

>### Results
>|groupId|groupPath|
>|---|---|
>| 4 | My Organization\Lab |


### epo-get-systems
***
Finds computers within a specified group in the ePO tree


#### Base Command

`epo-get-systems`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | System tree group ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeEPO.Systems.ComputerName | Unknown | System HostName | 
| McAfeeEPO.Systems.IPAddress | Unknown | System IP Address | 
| McAfeeEPO.Systems.AgentGUID | Unknown | Agent GUID | 
| McAfeeEPO.Systems.DomainName | Unknown | Domain Name | 


#### Command Example
```!epo-get-systems groupId="4"```

#### Context Example
```json
{
    "McAfeeEPO": {
        "Systems": [
            {
                "AgentGUID": "514AC637-50E5-48D1-8908-6AC54BF90E3A",
                "AgentVersion": "5.5.1.342",
                "AutoID": 4,
                "CPUSerialNumber": "N/A",
                "CPUSpeed": 2000,
                "CPUType": "Intel(R) Xeon(R) CPU E5-2640 v2 @ 2.00GHz",
                "ComputerDescription": "N/A",
                "ComputerName": "WIN-KGR51CJ40N0",
                "DefaultLangID": "0409",
                "Description": null,
                "DomainName": "WORKGROUP",
                "ExcludedTags": "",
                "FreeDiskSpace": 18968,
                "FreeMemory": 2898857984,
                "Free_Space_of_Drive_C": 18968,
                "IPAddress": "192.168.20.105",
                "IPHostName": "WIN-KGR51CJ40N0",
                "IPSubnet": "0:0:0:0:0:FFFF:C0A8:1400",
                "IPSubnetMask": "0:0:0:0:0:FFFF:FFFF:FF00",
                "IPV4x": null,
                "IPV6": "0:0:0:0:0:FFFF:C0A8:1469",
                "IPXAddress": "N/A",
                "IsPortable": 0,
                "LastAgentHandler": 1,
                "LastUpdate": "2021-04-07T07:48:04-07:00",
                "ManagedState": 1,
                "NetAddress": "000C29559F37",
                "NumOfCPU": 8,
                "OSBitMode": 1,
                "OSBuildNum": 14393,
                "OSCsdVersion": "",
                "OSOEMID": "00376-40000-00000-AA947",
                "OSPlatform": "Server",
                "OSType": "Windows Server 2016",
                "OSVersion": "10.0",
                "ParentID": 1,
                "SubnetAddress": "192.168.20.0",
                "SubnetMask": "255.255.255.0",
                "Tags": "Endpoint ATP, Endpoint Security Platfrom, Install Firewall, Server, Threat Prevention",
                "TimeZone": "Pacific Standard Time",
                "TotalDiskSpace": 40392,
                "TotalPhysicalMemory": 8588857344,
                "Total_Space_of_Drive_C": 40392,
                "UserName": "Administrator",
                "UserProperty1": "",
                "UserProperty2": "",
                "UserProperty3": "",
                "UserProperty4": "",
                "UserProperty5": "",
                "UserProperty6": "",
                "UserProperty7": "",
                "UserProperty8": "",
                "Vdi": 0
            },
            {
                "AgentGUID": "8EB28509-9372-409F-BCAC-DAB4F2ED7EF1",
                "AgentVersion": "5.5.1.342",
                "AutoID": 4,
                "CPUSerialNumber": "N/A",
                "CPUSpeed": 2000,
                "CPUType": "Intel(R) Xeon(R) CPU E5-2640 v2 @ 2.00GHz",
                "ComputerDescription": "N/A",
                "ComputerName": "W7CLIENT",
                "DefaultLangID": "0409",
                "Description": null,
                "DomainName": "AYMAN",
                "ExcludedTags": "",
                "FreeDiskSpace": 3028,
                "FreeMemory": 3183710208,
                "Free_Space_of_Drive_C": 3028,
                "IPAddress": "192.168.20.102",
                "IPHostName": "w7client.ayman.local",
                "IPSubnet": "0:0:0:0:0:FFFF:C0A8:1400",
                "IPSubnetMask": "0:0:0:0:0:FFFF:FFFF:FF00",
                "IPV4x": null,
                "IPV6": "0:0:0:0:0:FFFF:C0A8:1466",
                "IPXAddress": "N/A",
                "IsPortable": 0,
                "LastAgentHandler": 1,
                "LastUpdate": "2021-04-07T07:21:55-07:00",
                "ManagedState": 1,
                "NetAddress": "000C295809F9",
                "NumOfCPU": 1,
                "OSBitMode": 1,
                "OSBuildNum": 7601,
                "OSCsdVersion": "Service Pack 1",
                "OSOEMID": "00371-868-0000007-85607",
                "OSPlatform": "Workstation",
                "OSType": "Windows 7",
                "OSVersion": "6.1",
                "ParentID": 2,
                "SubnetAddress": "192.168.20.0",
                "SubnetMask": "255.255.255.0",
                "Tags": "Endpoint ATP, Endpoint Security Platfrom, Install Firewall, Threat Prevention, Workstation",
                "TimeZone": "Arabian Standard Time",
                "TotalDiskSpace": 32665,
                "TotalPhysicalMemory": 4294434816,
                "Total_Space_of_Drive_C": 32665,
                "UserName": "N/A",
                "UserProperty1": "",
                "UserProperty2": "",
                "UserProperty3": "",
                "UserProperty4": "",
                "UserProperty5": "",
                "UserProperty6": "",
                "UserProperty7": "",
                "UserProperty8": "",
                "Vdi": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|AgentGUID|AgentVersion|AutoID|CPUSerialNumber|CPUSpeed|CPUType|ComputerDescription|ComputerName|DefaultLangID|Description|DomainName|ExcludedTags|FreeDiskSpace|FreeMemory|Free_Space_of_Drive_C|IPAddress|IPHostName|IPSubnet|IPSubnetMask|IPV4x|IPV6|IPXAddress|IsPortable|LastAgentHandler|LastUpdate|ManagedState|NetAddress|NumOfCPU|OSBitMode|OSBuildNum|OSCsdVersion|OSOEMID|OSPlatform|OSType|OSVersion|ParentID|SubnetAddress|SubnetMask|Tags|TimeZone|TotalDiskSpace|TotalPhysicalMemory|Total_Space_of_Drive_C|UserName|UserProperty1|UserProperty2|UserProperty3|UserProperty4|UserProperty5|UserProperty6|UserProperty7|UserProperty8|Vdi|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 514AC637-50E5-48D1-8908-6AC54BF90E3A | 5.5.1.342 | 4 | N/A | 2000 | Intel(R) Xeon(R) CPU E5-2640 v2 @ 2.00GHz | N/A | WIN-KGR51CJ40N0 | 0409 |  | WORKGROUP |  | 18968 | 2898857984 | 18968 | 192.168.20.105 | WIN-KGR51CJ40N0 | 0:0:0:0:0:FFFF:C0A8:1400 | 0:0:0:0:0:FFFF:FFFF:FF00 |  | 0:0:0:0:0:FFFF:C0A8:1469 | N/A | 0 | 1 | 2021-04-07T07:48:04-07:00 | 1 | 000C29559F37 | 8 | 1 | 14393 |  | 00376-40000-00000-AA947 | Server | Windows Server 2016 | 10.0 | 1 | 192.168.20.0 | 255.255.255.0 | Endpoint ATP, Endpoint Security Platfrom, Install Firewall, Server, Threat Prevention | Pacific Standard Time | 40392 | 8588857344 | 40392 | Administrator |  |  |  |  |  |  |  |  | 0 |
>| 8EB28509-9372-409F-BCAC-DAB4F2ED7EF1 | 5.5.1.342 | 4 | N/A | 2000 | Intel(R) Xeon(R) CPU E5-2640 v2 @ 2.00GHz | N/A | W7CLIENT | 0409 |  | AYMAN |  | 3028 | 3183710208 | 3028 | 192.168.20.102 | w7client.ayman.local | 0:0:0:0:0:FFFF:C0A8:1400 | 0:0:0:0:0:FFFF:FFFF:FF00 |  | 0:0:0:0:0:FFFF:C0A8:1466 | N/A | 0 | 1 | 2021-04-07T07:21:55-07:00 | 1 | 000C295809F9 | 1 | 1 | 7601 | Service Pack 1 | 00371-868-0000007-85607 | Workstation | Windows 7 | 6.1 | 2 | 192.168.20.0 | 255.255.255.0 | Endpoint ATP, Endpoint Security Platfrom, Install Firewall, Threat Prevention, Workstation | Arabian Standard Time | 32665 | 4294434816 | 32665 | N/A |  |  |  |  |  |  |  |  | 0 |


### epo-get-tables
***
Get ePO Tables


#### Base Command

`epo-get-tables`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table | Table Name. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-get-tables table="EPOEvents"```

#### Context Example
```json
{
    "McAfeeEPO": {
        "Tables": {
            "columns": "\r\n    Name                    Type           Select? Condition? GroupBy? Order? Number? \r\n    ----------------------- -------------- ------- ---------- -------- ------ -------\r\n    AutoID                  long           False   False      False    True   True   \r\n    AutoGUID                string         False   False      False    True   False  \r\n    ServerID                string         True    False      False    True   False  \r\n    ReceivedUTC             timestamp      True    True       True     True   False  \r\n    DetectedUTC             timestamp      True    True       True     True   False  \r\n    EventTimeLocal          timestamp      True    True       True     True   False  \r\n    AgentGUID               string         True    False      False    True   False  \r\n    Analyzer                string_lookup  True    True       True     True   False  \r\n    AnalyzerName            string_lookup  True    True       True     True   False  \r\n    AnalyzerVersion         string_lookup  True    True       True     True   False  \r\n    AnalyzerHostName        string         True    True       True     True   False  \r\n    AnalyzerIPV4            ipv4           True    True       True     True   False  \r\n    AnalyzerIPV6            ipv6           True    True       True     True   False  \r\n    AnalyzerMAC             string         True    True       True     True   False  \r\n    AnalyzerDATVersion      string         True    True       True     True   False  \r\n    AnalyzerEngineVersion   string_lookup  True    True       True     True   False  \r\n    SourceHostName          string         True    True       True     True   False  \r\n    SourceIPV4              ipv4           True    True       True     True   False  \r\n    SourceIPV6              ipv6           True    True       True     True   False  \r\n    SourceMAC               string         True    True       True     True   False  \r\n    SourceUserName          string         True    True       True     True   False  \r\n    SourceProcessName       string         True    True       True     True   False  \r\n    SourceURL               string         True    True       True     True   False  \r\n    TargetHostName          string         True    True       True     True   False  \r\n    TargetIPV4              ipv4           True    True       True     True   False  \r\n    TargetIPV6              ipv6           True    True       True     True   False  \r\n    TargetMAC               string         True    True       True     True   False  \r\n    TargetUserName          string         True    True       True     True   False  \r\n    TargetPort              int            True    True       True     True   True   \r\n    TargetProtocol          string_lookup  True    True       True     True   False  \r\n    TargetProcessName       string         True    True       True     True   False  \r\n    TargetFileName          string         True    True       True     True   False  \r\n    ThreatCategory          threatcategory True    True       True     True   False  \r\n    ThreatEventID           eventIdInt     True    True       True     True   True   \r\n    TenantId                int            False   False      False    True   True   \r\n    ThreatSeverity          enum           True    True       True     True   False  \r\n    ThreatName              string_lookup  True    True       True     True   False  \r\n    ThreatType              string_enum    True    True       True     True   False  \r\n    ThreatActionTaken       string_enum    True    True       True     True   False  \r\n    ThreatHandled           boolean        True    True       True     True   False  \r\n    AnalyzerDetectionMethod string_lookup  True    True       True     True   False  \r\n",
            "databaseType": "",
            "description": "Retrieves information about Threat Events sent from managed systems.",
            "foreignKeys": "\r\n    Source table Source Columns Destination table            Destination columns Allows inverse? One-to-one? Many-to-one? \r\n    ------------ -------------- ---------------------------- ------------------- --------------- ----------- ------------\r\n    EPOEvents    AgentGUID      EPOLeafNode                  AgentGUID           False           False       True        \r\n    EPOEvents    ThreatEventID  EPOEventFilterDesc           EventId             False           False       True        \r\n    EPOEvents    AutoID         EPOEvents_RelatedTargetsView EventID             False           False       True        \r\n    EPOEvents    AutoID         EPOEvents_RelatedSourcesView EventID             False           False       True        \r\n",
            "name": "Threat Events",
            "relatedTables": "\r\n    Name\r\n    ----------------------------\r\n    EPStoryGraphInfo\r\n    JTIClientEventInfoView\r\n    EPOEventFilterDesc\r\n    WP_EventInfo\r\n    EPExtendedEvent\r\n    EPOLeafNode\r\n    EPOEvents_RelatedTargetsView\r\n    EPOEvents_RelatedSourcesView\r\n",
            "target": "EPOEvents",
            "type": "target"
        }
    }
}
```

#### Human Readable Output

>### Results
>|columns|databaseType|description|foreignKeys|name|relatedTables|target|type|
>|---|---|---|---|---|---|---|---|
>| <br/>    Name                    Type           Select? Condition? GroupBy? Order? Number? <br/>    ----------------------- -------------- ------- ---------- -------- ------ -------<br/>    AutoID                  long           False   False      False    True   True   <br/>    AutoGUID                string         False   False      False    True   False  <br/>    ServerID                string         True    False      False    True   False  <br/>    ReceivedUTC             timestamp      True    True       True     True   False  <br/>    DetectedUTC             timestamp      True    True       True     True   False  <br/>    EventTimeLocal          timestamp      True    True       True     True   False  <br/>    AgentGUID               string         True    False      False    True   False  <br/>    Analyzer                string_lookup  True    True       True     True   False  <br/>    AnalyzerName            string_lookup  True    True       True     True   False  <br/>    AnalyzerVersion         string_lookup  True    True       True     True   False  <br/>    AnalyzerHostName        string         True    True       True     True   False  <br/>    AnalyzerIPV4            ipv4           True    True       True     True   False  <br/>    AnalyzerIPV6            ipv6           True    True       True     True   False  <br/>    AnalyzerMAC             string         True    True       True     True   False  <br/>    AnalyzerDATVersion      string         True    True       True     True   False  <br/>    AnalyzerEngineVersion   string_lookup  True    True       True     True   False  <br/>    SourceHostName          string         True    True       True     True   False  <br/>    SourceIPV4              ipv4           True    True       True     True   False  <br/>    SourceIPV6              ipv6           True    True       True     True   False  <br/>    SourceMAC               string         True    True       True     True   False  <br/>    SourceUserName          string         True    True       True     True   False  <br/>    SourceProcessName       string         True    True       True     True   False  <br/>    SourceURL               string         True    True       True     True   False  <br/>    TargetHostName          string         True    True       True     True   False  <br/>    TargetIPV4              ipv4           True    True       True     True   False  <br/>    TargetIPV6              ipv6           True    True       True     True   False  <br/>    TargetMAC               string         True    True       True     True   False  <br/>    TargetUserName          string         True    True       True     True   False  <br/>    TargetPort              int            True    True       True     True   True   <br/>    TargetProtocol          string_lookup  True    True       True     True   False  <br/>    TargetProcessName       string         True    True       True     True   False  <br/>    TargetFileName          string         True    True       True     True   False  <br/>    ThreatCategory          threatcategory True    True       True     True   False  <br/>    ThreatEventID           eventIdInt     True    True       True     True   True   <br/>    TenantId                int            False   False      False    True   True   <br/>    ThreatSeverity          enum           True    True       True     True   False  <br/>    ThreatName              string_lookup  True    True       True     True   False  <br/>    ThreatType              string_enum    True    True       True     True   False  <br/>    ThreatActionTaken       string_enum    True    True       True     True   False  <br/>    ThreatHandled           boolean        True    True       True     True   False  <br/>    AnalyzerDetectionMethod string_lookup  True    True       True     True   False  <br/> |  | Retrieves information about Threat Events sent from managed systems. | <br/>    Source table Source Columns Destination table            Destination columns Allows inverse? One-to-one? Many-to-one? <br/>    ------------ -------------- ---------------------------- ------------------- --------------- ----------- ------------<br/>    EPOEvents    AgentGUID      EPOLeafNode                  AgentGUID           False           False       True        <br/>    EPOEvents    ThreatEventID  EPOEventFilterDesc           EventId             False           False       True        <br/>    EPOEvents    AutoID         EPOEvents_RelatedTargetsView EventID             False           False       True        <br/>    EPOEvents    AutoID         EPOEvents_RelatedSourcesView EventID             False           False       True        <br/> | Threat Events | <br/>    Name<br/>    ----------------------------<br/>    EPStoryGraphInfo<br/>    JTIClientEventInfoView<br/>    EPOEventFilterDesc<br/>    WP_EventInfo<br/>    EPExtendedEvent<br/>    EPOLeafNode<br/>    EPOEvents_RelatedTargetsView<br/>    EPOEvents_RelatedSourcesView<br/> | EPOEvents | target |


### epo-query
***
Execute an Ad-Hoc Query


#### Base Command

`epo-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table | ePO Table to Query. | Required | 
| columns | Select the columns to return , space seperated , example "column1 column2". | Optional | 
| query_filter | Query Filter, example "eq EPOEvents.ThreatType 'virus'". | Optional | 
| order_by | asc EPOEvents.ReceivedUTC. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-query table="EPOEvents" query_filter="eq EPOEvents.ThreatCategory \"av.detect\""```

#### Context Example
```json
{
    "McAfeeEPO": {
        "QueryResults": {
            "AgentGUID": "8EB28509-9372-409F-BCAC-DAB4F2ED7EF1",
            "Analyzer": "ENDP_AM_1070",
            "AnalyzerDATVersion": "4386.0",
            "AnalyzerDetectionMethod": "On-Access Scan",
            "AnalyzerEngineVersion": "6200.9189",
            "AnalyzerHostName": "w7client",
            "AnalyzerIPV4": 1084757094,
            "AnalyzerIPV6": "0:0:0:0:0:FFFF:C0A8:1466",
            "AnalyzerMAC": "000c295809f9",
            "AnalyzerName": "McAfee Endpoint Security",
            "AnalyzerVersion": "10.7.0",
            "DetectedUTC": "2021-03-26T14:17:20-07:00",
            "EventTimeLocal": "2021-03-26T14:17:20-07:00",
            "ReceivedUTC": "2021-03-26T06:16:56-07:00",
            "ServerID": "WIN-KGR51CJ40N0",
            "SourceHostName": "w7client",
            "SourceIPV4": 1084757094,
            "SourceIPV6": "0:0:0:0:0:FFFF:C0A8:1466",
            "SourceMAC": null,
            "SourceProcessName": "C:\\Windows\\explorer.exe",
            "SourceURL": null,
            "SourceUserName": null,
            "TargetFileName": "C:\\Users\\hussain\\Downloads\\eicar_com\\eicar.com",
            "TargetHostName": "w7client",
            "TargetIPV4": 1084757094,
            "TargetIPV6": "0:0:0:0:0:FFFF:C0A8:1466",
            "TargetMAC": null,
            "TargetPort": null,
            "TargetProcessName": null,
            "TargetProtocol": null,
            "TargetUserName": "AYMAN\\hussain",
            "ThreatActionTaken": "IDS_ALERT_ACT_TAK_DEL",
            "ThreatCategory": "av.detect",
            "ThreatEventID": 1278,
            "ThreatHandled": true,
            "ThreatName": "EICAR test file",
            "ThreatSeverity": 2,
            "ThreatType": "test"
        }
    }
}
```

#### Human Readable Output

>### Results
>|AgentGUID|Analyzer|AnalyzerDATVersion|AnalyzerDetectionMethod|AnalyzerEngineVersion|AnalyzerHostName|AnalyzerIPV4|AnalyzerIPV6|AnalyzerMAC|AnalyzerName|AnalyzerVersion|DetectedUTC|EventTimeLocal|ReceivedUTC|ServerID|SourceHostName|SourceIPV4|SourceIPV6|SourceMAC|SourceProcessName|SourceURL|SourceUserName|TargetFileName|TargetHostName|TargetIPV4|TargetIPV6|TargetMAC|TargetPort|TargetProcessName|TargetProtocol|TargetUserName|ThreatActionTaken|ThreatCategory|ThreatEventID|ThreatHandled|ThreatName|ThreatSeverity|ThreatType|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 8EB28509-9372-409F-BCAC-DAB4F2ED7EF1 | ENDP_AM_1070 | 4384.0 | On-Access Scan | 6200.9189 | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 | 000c295809f9 | McAfee Endpoint Security | 10.7.0 | 2021-03-24T08:53:41-07:00 | 2021-03-24T08:53:41-07:00 | 2021-03-24T00:55:50-07:00 | WIN-KGR51CJ40N0 | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 |  | C:\Windows\explorer.exe |  |  | C:\Users\hussain\Desktop\eicar_com\eicar.com | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 |  |  |  |  | AYMAN\hussain | IDS_ALERT_ACT_TAK_DEL | av.detect | 1278 | true | EICAR test file | 2 | test |
>| 8EB28509-9372-409F-BCAC-DAB4F2ED7EF1 | ENDP_AM_1070 | 4384.0 | On-Access Scan | 6200.9189 | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 | 000c295809f9 | McAfee Endpoint Security | 10.7.0 | 2021-03-24T08:54:35-07:00 | 2021-03-24T08:54:35-07:00 | 2021-03-24T00:55:51-07:00 | WIN-KGR51CJ40N0 | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 |  | C:\Windows\explorer.exe |  |  | C:\Users\hussain\Downloads\ArtemisTest\ArtemisTest.exe | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 |  |  |  |  | AYMAN\hussain | IDS_ALERT_ACT_TAK_DEL | av.detect | 1027 | true | Artemis!5DB32A316F07 | 2 | virus |
>| 8EB28509-9372-409F-BCAC-DAB4F2ED7EF1 | ENDP_AM_1070 | 4385.0 | On-Access Scan | 6200.9189 | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 | 000c295809f9 | McAfee Endpoint Security | 10.7.0 | 2021-03-25T13:31:13-07:00 | 2021-03-25T13:31:13-07:00 | 2021-03-25T05:31:20-07:00 | WIN-KGR51CJ40N0 | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 |  | C:\Windows\explorer.exe |  |  | C:\Users\hussain\Downloads\eicar_com\eicar.com | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 |  |  |  |  | AYMAN\hussain | IDS_ALERT_ACT_TAK_DEL | av.detect | 1278 | true | EICAR test file | 2 | test |
>| 8EB28509-9372-409F-BCAC-DAB4F2ED7EF1 | ENDP_AM_1070 | 4385.0 | On-Access Scan | 6200.9189 | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 | 000c295809f9 | McAfee Endpoint Security | 10.7.0 | 2021-03-25T13:32:39-07:00 | 2021-03-25T13:32:39-07:00 | 2021-03-25T05:33:09-07:00 | WIN-KGR51CJ40N0 | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 |  | C:\Windows\System32\certutil.exe |  |  | C:\Users\hussain\Downloads\EDR-Testing-Script-master\EDR-Testing-Script-master\AllTheThings.dll | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 |  |  |  |  | AYMAN\hussain | IDS_ALERT_ACT_TAK_DEL | av.detect | 1027 | true | Artemis!00BFB3A8E171 | 2 | trojan |
>| 8EB28509-9372-409F-BCAC-DAB4F2ED7EF1 | ENDP_AM_1070 | 4386.0 | On-Access Scan | 6200.9189 | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 | 000c295809f9 | McAfee Endpoint Security | 10.7.0 | 2021-03-26T14:17:20-07:00 | 2021-03-26T14:17:20-07:00 | 2021-03-26T06:16:56-07:00 | WIN-KGR51CJ40N0 | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 |  | C:\Windows\explorer.exe |  |  | C:\Users\hussain\Downloads\eicar_com\eicar.com | w7client | 1084757094 | 0:0:0:0:0:FFFF:C0A8:1466 |  |  |  |  | AYMAN\hussain | IDS_ALERT_ACT_TAK_DEL | av.detect | 1278 | true | EICAR test file | 2 | test |


### epo-fetch-sample-alerts
***
Fetch Sample Alerts using the configuration parameters


#### Base Command

`epo-fetch-sample-alerts`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!epo-fetch-sample-alerts```

#### Human Readable Output

>null

### epo-find-policies
***
Finds policies matching a specified keyword


#### Base Command

`epo-find-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keyword | Policy match keyword. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeEPO.Policies.typeName | Unknown | Policy Type | 
| McAfeeEPO.Policies.productId | Unknown | Product ID | 
| McAfeeEPO.Policies.objectName | Unknown | Policy Name | 
| McAfeeEPO.Policies.typeId | Unknown | Policy Type ID | 
| McAfeeEPO.Policies.productName | Unknown | Policy Product Name | 
| McAfeeEPO.Policies.objectId | Unknown | Policy ID | 


#### Command Example
```!epo-find-policies```

#### Context Example
```json
{
    "McAfeeEPO": {
        "Policies": [
            {
                "featureId": "TIEClientMETA",
                "featureName": " Policy Category",
                "objectId": 51,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "TIEClientMETA",
                "productName": "Endpoint Security Adaptive Threat Protection ",
                "typeId": 24,
                "typeName": "Options"
            },
            {
                "featureId": "TIEClientMETA",
                "featureName": " Policy Category",
                "objectId": 57,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "TIEClientMETA",
                "productName": "Endpoint Security Adaptive Threat Protection ",
                "typeId": 24,
                "typeName": "Options"
            },
            {
                "featureId": "TIEClientMETA",
                "featureName": " Policy Category",
                "objectId": 54,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "TIEClientMETA",
                "productName": "Endpoint Security Adaptive Threat Protection ",
                "typeId": 27,
                "typeName": "Dynamic Application Containment"
            },
            {
                "featureId": "TIEClientMETA",
                "featureName": " Policy Category",
                "objectId": 55,
                "objectName": "McAfee Default Security",
                "objectNotes": "",
                "productId": "TIEClientMETA",
                "productName": "Endpoint Security Adaptive Threat Protection ",
                "typeId": 27,
                "typeName": "Dynamic Application Containment"
            },
            {
                "featureId": "TIEClientMETA",
                "featureName": " Policy Category",
                "objectId": 56,
                "objectName": "McAfee Default Balanced",
                "objectNotes": "",
                "productId": "TIEClientMETA",
                "productName": "Endpoint Security Adaptive Threat Protection ",
                "typeId": 27,
                "typeName": "Dynamic Application Containment"
            },
            {
                "featureId": "TIEClientMETA",
                "featureName": " Policy Category",
                "objectId": 60,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "TIEClientMETA",
                "productName": "Endpoint Security Adaptive Threat Protection ",
                "typeId": 27,
                "typeName": "Dynamic Application Containment"
            },
            {
                "featureId": "ENDP_GS_1000",
                "featureName": " Policy Category",
                "objectId": 23,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_GS_1000",
                "productName": "Endpoint Security Common ",
                "typeId": 11,
                "typeName": "Options"
            },
            {
                "featureId": "ENDP_GS_1000",
                "featureName": " Policy Category",
                "objectId": 24,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_GS_1000",
                "productName": "Endpoint Security Common ",
                "typeId": 11,
                "typeName": "Options"
            },
            {
                "featureId": "ENDP_FW_META_FW",
                "featureName": "Firewall",
                "objectId": 27,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_FW_META",
                "productName": "Endpoint Security Firewall ",
                "typeId": 13,
                "typeName": "Options"
            },
            {
                "featureId": "ENDP_FW_META_FW",
                "featureName": "Firewall",
                "objectId": 30,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_FW_META",
                "productName": "Endpoint Security Firewall ",
                "typeId": 13,
                "typeName": "Options"
            },
            {
                "featureId": "ENDP_FW_META_FW",
                "featureName": "Firewall",
                "objectId": 76,
                "objectName": "Quarantine Policy",
                "objectNotes": "",
                "productId": "ENDP_FW_META",
                "productName": "Endpoint Security Firewall ",
                "typeId": 13,
                "typeName": "Options"
            },
            {
                "featureId": "ENDP_FW_META_FW",
                "featureName": "Firewall",
                "objectId": 28,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_FW_META",
                "productName": "Endpoint Security Firewall ",
                "typeId": 14,
                "typeName": "Rules"
            },
            {
                "featureId": "ENDP_FW_META_FW",
                "featureName": "Firewall",
                "objectId": 29,
                "objectName": "McAfee Default Server",
                "objectNotes": "",
                "productId": "ENDP_FW_META",
                "productName": "Endpoint Security Firewall ",
                "typeId": 14,
                "typeName": "Rules"
            },
            {
                "featureId": "ENDP_FW_META_FW",
                "featureName": "Firewall",
                "objectId": 31,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_FW_META",
                "productName": "Endpoint Security Firewall ",
                "typeId": 14,
                "typeName": "Rules"
            },
            {
                "featureId": "ENDP_FW_META_FW",
                "featureName": "Firewall",
                "objectId": 77,
                "objectName": "Quarantine Policy",
                "objectNotes": "",
                "productId": "ENDP_FW_META",
                "productName": "Endpoint Security Firewall ",
                "typeId": 14,
                "typeName": "Rules"
            },
            {
                "featureId": "ENDP_AM_1000",
                "featureName": " Policy Category",
                "objectId": 38,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_AM_1000",
                "productName": "Endpoint Security Threat Prevention ",
                "typeId": 18,
                "typeName": "On-Access Scan"
            },
            {
                "featureId": "ENDP_AM_1000",
                "featureName": " Policy Category",
                "objectId": 40,
                "objectName": "On-Access Scan for Exchange",
                "objectNotes": "",
                "productId": "ENDP_AM_1000",
                "productName": "Endpoint Security Threat Prevention ",
                "typeId": 18,
                "typeName": "On-Access Scan"
            },
            {
                "featureId": "ENDP_AM_1000",
                "featureName": " Policy Category",
                "objectId": 44,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_AM_1000",
                "productName": "Endpoint Security Threat Prevention ",
                "typeId": 18,
                "typeName": "On-Access Scan"
            },
            {
                "featureId": "ENDP_AM_1000",
                "featureName": " Policy Category",
                "objectId": 39,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_AM_1000",
                "productName": "Endpoint Security Threat Prevention ",
                "typeId": 19,
                "typeName": "On-Demand Scan"
            },
            {
                "featureId": "ENDP_AM_1000",
                "featureName": " Policy Category",
                "objectId": 45,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_AM_1000",
                "productName": "Endpoint Security Threat Prevention ",
                "typeId": 19,
                "typeName": "On-Demand Scan"
            },
            {
                "featureId": "ENDP_AM_1000",
                "featureName": " Policy Category",
                "objectId": 41,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_AM_1000",
                "productName": "Endpoint Security Threat Prevention ",
                "typeId": 20,
                "typeName": "Options"
            },
            {
                "featureId": "ENDP_AM_1000",
                "featureName": " Policy Category",
                "objectId": 46,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_AM_1000",
                "productName": "Endpoint Security Threat Prevention ",
                "typeId": 20,
                "typeName": "Options"
            },
            {
                "featureId": "ENDP_AM_1000",
                "featureName": " Policy Category",
                "objectId": 42,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_AM_1000",
                "productName": "Endpoint Security Threat Prevention ",
                "typeId": 21,
                "typeName": "Access Protection"
            },
            {
                "featureId": "ENDP_AM_1000",
                "featureName": " Policy Category",
                "objectId": 47,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_AM_1000",
                "productName": "Endpoint Security Threat Prevention ",
                "typeId": 21,
                "typeName": "Access Protection"
            },
            {
                "featureId": "ENDP_AM_1000",
                "featureName": " Policy Category",
                "objectId": 43,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_AM_1000",
                "productName": "Endpoint Security Threat Prevention ",
                "typeId": 22,
                "typeName": "Exploit Prevention"
            },
            {
                "featureId": "ENDP_AM_1000",
                "featureName": " Policy Category",
                "objectId": 48,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_AM_1000",
                "productName": "Endpoint Security Threat Prevention ",
                "typeId": 22,
                "typeName": "Exploit Prevention"
            },
            {
                "featureId": "ENDP_WP_1000",
                "featureName": " Policy Category",
                "objectId": 63,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_WP_1000",
                "productName": "Endpoint Security Web Control ",
                "typeId": 29,
                "typeName": "Options"
            },
            {
                "featureId": "ENDP_WP_1000",
                "featureName": " Policy Category",
                "objectId": 69,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_WP_1000",
                "productName": "Endpoint Security Web Control ",
                "typeId": 29,
                "typeName": "Options"
            },
            {
                "featureId": "ENDP_WP_1000",
                "featureName": " Policy Category",
                "objectId": 64,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_WP_1000",
                "productName": "Endpoint Security Web Control ",
                "typeId": 30,
                "typeName": "Enforcement Messaging"
            },
            {
                "featureId": "ENDP_WP_1000",
                "featureName": " Policy Category",
                "objectId": 70,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_WP_1000",
                "productName": "Endpoint Security Web Control ",
                "typeId": 30,
                "typeName": "Enforcement Messaging"
            },
            {
                "featureId": "ENDP_WP_1000",
                "featureName": " Policy Category",
                "objectId": 66,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_WP_1000",
                "productName": "Endpoint Security Web Control ",
                "typeId": 31,
                "typeName": "Block and Allow List"
            },
            {
                "featureId": "ENDP_WP_1000",
                "featureName": " Policy Category",
                "objectId": 72,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_WP_1000",
                "productName": "Endpoint Security Web Control ",
                "typeId": 31,
                "typeName": "Block and Allow List"
            },
            {
                "featureId": "ENDP_WP_1000",
                "featureName": " Policy Category",
                "objectId": 67,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_WP_1000",
                "productName": "Endpoint Security Web Control ",
                "typeId": 32,
                "typeName": "Content Actions"
            },
            {
                "featureId": "ENDP_WP_1000",
                "featureName": " Policy Category",
                "objectId": 73,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_WP_1000",
                "productName": "Endpoint Security Web Control ",
                "typeId": 32,
                "typeName": "Content Actions"
            },
            {
                "featureId": "ENDP_WP_1000",
                "featureName": " Policy Category",
                "objectId": 65,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "ENDP_WP_1000",
                "productName": "Endpoint Security Web Control ",
                "typeId": 34,
                "typeName": "Browser Control"
            },
            {
                "featureId": "ENDP_WP_1000",
                "featureName": " Policy Category",
                "objectId": 71,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "ENDP_WP_1000",
                "productName": "Endpoint Security Web Control ",
                "typeId": 34,
                "typeName": "Browser Control"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 4,
                "objectName": "McAfee Default",
                "objectNotes": "The McAfee Default policy is configured with settings recommended by McAfee to protect many environments",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 3,
                "typeName": "General"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 9,
                "objectName": "Large Organization Default",
                "objectNotes": "The Large Organization Default policy is configured with settings recommended by McAfee to protect large enterprise environments.",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 3,
                "typeName": "General"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 11,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 3,
                "typeName": "General"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 20,
                "objectName": "Lab",
                "objectNotes": "",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 3,
                "typeName": "General"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 5,
                "objectName": "McAfee Default",
                "objectNotes": "The McAfee Default policy is configured with settings recommended by McAfee to protect many environments",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 4,
                "typeName": "Repository"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 12,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 4,
                "typeName": "Repository"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 6,
                "objectName": "McAfee Default",
                "objectNotes": "The McAfee Default policy is configured with settings recommended by McAfee to protect many environments",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 5,
                "typeName": "Troubleshooting"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 13,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 5,
                "typeName": "Troubleshooting"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 7,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 6,
                "typeName": "Custom Properties"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 14,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 6,
                "typeName": "Custom Properties"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 8,
                "objectName": "McAfee Default",
                "objectNotes": "The McAfee Default policy is configured with settings recommended by McAfee to protect many environments",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 7,
                "typeName": "Product Improvement Program"
            },
            {
                "featureId": "EPOAGENTMETA",
                "featureName": "McAfee Agent",
                "objectId": 15,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "EPOAGENTMETA",
                "productName": "McAfee Agent ",
                "typeId": 7,
                "typeName": "Product Improvement Program"
            },
            {
                "featureId": "MCPSRVER1000",
                "featureName": "McAfee Client Proxy",
                "objectId": 34,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "MCPSRVER1000",
                "productName": "McAfee Client Proxy 2.5.0",
                "typeId": 16,
                "typeName": "MCP Policy"
            },
            {
                "featureId": "MCPSRVER1000",
                "featureName": "McAfee Client Proxy",
                "objectId": 35,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "MCPSRVER1000",
                "productName": "McAfee Client Proxy 2.5.0",
                "typeId": 16,
                "typeName": "MCP Policy"
            },
            {
                "featureId": "TELEMTRY1000",
                "featureName": "Product Improvement Program",
                "objectId": 18,
                "objectName": "McAfee Default",
                "objectNotes": "",
                "productId": "TELEMTRY1000",
                "productName": "Product Improvement Program ",
                "typeId": 9,
                "typeName": "General"
            },
            {
                "featureId": "TELEMTRY1000",
                "featureName": "Product Improvement Program",
                "objectId": 19,
                "objectName": "My Default",
                "objectNotes": "",
                "productId": "TELEMTRY1000",
                "productName": "Product Improvement Program ",
                "typeId": 9,
                "typeName": "General"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|featureId|featureName|objectId|objectName|objectNotes|productId|productName|typeId|typeName|
>|---|---|---|---|---|---|---|---|---|
>| TIEClientMETA |  Policy Category | 51 | McAfee Default |  | TIEClientMETA | Endpoint Security Adaptive Threat Protection  | 24 | Options |
>| TIEClientMETA |  Policy Category | 57 | My Default |  | TIEClientMETA | Endpoint Security Adaptive Threat Protection  | 24 | Options |
>| TIEClientMETA |  Policy Category | 54 | McAfee Default |  | TIEClientMETA | Endpoint Security Adaptive Threat Protection  | 27 | Dynamic Application Containment |
>| TIEClientMETA |  Policy Category | 55 | McAfee Default Security |  | TIEClientMETA | Endpoint Security Adaptive Threat Protection  | 27 | Dynamic Application Containment |
>| TIEClientMETA |  Policy Category | 56 | McAfee Default Balanced |  | TIEClientMETA | Endpoint Security Adaptive Threat Protection  | 27 | Dynamic Application Containment |
>| TIEClientMETA |  Policy Category | 60 | My Default |  | TIEClientMETA | Endpoint Security Adaptive Threat Protection  | 27 | Dynamic Application Containment |
>| ENDP_GS_1000 |  Policy Category | 23 | McAfee Default |  | ENDP_GS_1000 | Endpoint Security Common  | 11 | Options |
>| ENDP_GS_1000 |  Policy Category | 24 | My Default |  | ENDP_GS_1000 | Endpoint Security Common  | 11 | Options |
>| ENDP_FW_META_FW | Firewall | 27 | McAfee Default |  | ENDP_FW_META | Endpoint Security Firewall  | 13 | Options |
>| ENDP_FW_META_FW | Firewall | 30 | My Default |  | ENDP_FW_META | Endpoint Security Firewall  | 13 | Options |
>| ENDP_FW_META_FW | Firewall | 76 | Quarantine Policy |  | ENDP_FW_META | Endpoint Security Firewall  | 13 | Options |
>| ENDP_FW_META_FW | Firewall | 28 | McAfee Default |  | ENDP_FW_META | Endpoint Security Firewall  | 14 | Rules |
>| ENDP_FW_META_FW | Firewall | 29 | McAfee Default Server |  | ENDP_FW_META | Endpoint Security Firewall  | 14 | Rules |
>| ENDP_FW_META_FW | Firewall | 31 | My Default |  | ENDP_FW_META | Endpoint Security Firewall  | 14 | Rules |
>| ENDP_FW_META_FW | Firewall | 77 | Quarantine Policy |  | ENDP_FW_META | Endpoint Security Firewall  | 14 | Rules |
>| ENDP_AM_1000 |  Policy Category | 38 | McAfee Default |  | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 18 | On-Access Scan |
>| ENDP_AM_1000 |  Policy Category | 40 | On-Access Scan for Exchange |  | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 18 | On-Access Scan |
>| ENDP_AM_1000 |  Policy Category | 44 | My Default |  | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 18 | On-Access Scan |
>| ENDP_AM_1000 |  Policy Category | 39 | McAfee Default |  | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 19 | On-Demand Scan |
>| ENDP_AM_1000 |  Policy Category | 45 | My Default |  | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 19 | On-Demand Scan |
>| ENDP_AM_1000 |  Policy Category | 41 | McAfee Default |  | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 20 | Options |
>| ENDP_AM_1000 |  Policy Category | 46 | My Default |  | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 20 | Options |
>| ENDP_AM_1000 |  Policy Category | 42 | McAfee Default |  | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 21 | Access Protection |
>| ENDP_AM_1000 |  Policy Category | 47 | My Default |  | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 21 | Access Protection |
>| ENDP_AM_1000 |  Policy Category | 43 | McAfee Default |  | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 22 | Exploit Prevention |
>| ENDP_AM_1000 |  Policy Category | 48 | My Default |  | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 22 | Exploit Prevention |
>| ENDP_WP_1000 |  Policy Category | 63 | McAfee Default |  | ENDP_WP_1000 | Endpoint Security Web Control  | 29 | Options |
>| ENDP_WP_1000 |  Policy Category | 69 | My Default |  | ENDP_WP_1000 | Endpoint Security Web Control  | 29 | Options |
>| ENDP_WP_1000 |  Policy Category | 64 | McAfee Default |  | ENDP_WP_1000 | Endpoint Security Web Control  | 30 | Enforcement Messaging |
>| ENDP_WP_1000 |  Policy Category | 70 | My Default |  | ENDP_WP_1000 | Endpoint Security Web Control  | 30 | Enforcement Messaging |
>| ENDP_WP_1000 |  Policy Category | 66 | McAfee Default |  | ENDP_WP_1000 | Endpoint Security Web Control  | 31 | Block and Allow List |
>| ENDP_WP_1000 |  Policy Category | 72 | My Default |  | ENDP_WP_1000 | Endpoint Security Web Control  | 31 | Block and Allow List |
>| ENDP_WP_1000 |  Policy Category | 67 | McAfee Default |  | ENDP_WP_1000 | Endpoint Security Web Control  | 32 | Content Actions |
>| ENDP_WP_1000 |  Policy Category | 73 | My Default |  | ENDP_WP_1000 | Endpoint Security Web Control  | 32 | Content Actions |
>| ENDP_WP_1000 |  Policy Category | 65 | McAfee Default |  | ENDP_WP_1000 | Endpoint Security Web Control  | 34 | Browser Control |
>| ENDP_WP_1000 |  Policy Category | 71 | My Default |  | ENDP_WP_1000 | Endpoint Security Web Control  | 34 | Browser Control |
>| EPOAGENTMETA | McAfee Agent | 4 | McAfee Default | The McAfee Default policy is configured with settings recommended by McAfee to protect many environments | EPOAGENTMETA | McAfee Agent  | 3 | General |
>| EPOAGENTMETA | McAfee Agent | 9 | Large Organization Default | The Large Organization Default policy is configured with settings recommended by McAfee to protect large enterprise environments. | EPOAGENTMETA | McAfee Agent  | 3 | General |
>| EPOAGENTMETA | McAfee Agent | 11 | My Default |  | EPOAGENTMETA | McAfee Agent  | 3 | General |
>| EPOAGENTMETA | McAfee Agent | 20 | Lab |  | EPOAGENTMETA | McAfee Agent  | 3 | General |
>| EPOAGENTMETA | McAfee Agent | 5 | McAfee Default | The McAfee Default policy is configured with settings recommended by McAfee to protect many environments | EPOAGENTMETA | McAfee Agent  | 4 | Repository |
>| EPOAGENTMETA | McAfee Agent | 12 | My Default |  | EPOAGENTMETA | McAfee Agent  | 4 | Repository |
>| EPOAGENTMETA | McAfee Agent | 6 | McAfee Default | The McAfee Default policy is configured with settings recommended by McAfee to protect many environments | EPOAGENTMETA | McAfee Agent  | 5 | Troubleshooting |
>| EPOAGENTMETA | McAfee Agent | 13 | My Default |  | EPOAGENTMETA | McAfee Agent  | 5 | Troubleshooting |
>| EPOAGENTMETA | McAfee Agent | 7 | McAfee Default |  | EPOAGENTMETA | McAfee Agent  | 6 | Custom Properties |
>| EPOAGENTMETA | McAfee Agent | 14 | My Default |  | EPOAGENTMETA | McAfee Agent  | 6 | Custom Properties |
>| EPOAGENTMETA | McAfee Agent | 8 | McAfee Default | The McAfee Default policy is configured with settings recommended by McAfee to protect many environments | EPOAGENTMETA | McAfee Agent  | 7 | Product Improvement Program |
>| EPOAGENTMETA | McAfee Agent | 15 | My Default |  | EPOAGENTMETA | McAfee Agent  | 7 | Product Improvement Program |
>| MCPSRVER1000 | McAfee Client Proxy | 34 | McAfee Default |  | MCPSRVER1000 | McAfee Client Proxy 2.5.0 | 16 | MCP Policy |
>| MCPSRVER1000 | McAfee Client Proxy | 35 | My Default |  | MCPSRVER1000 | McAfee Client Proxy 2.5.0 | 16 | MCP Policy |
>| TELEMTRY1000 | Product Improvement Program | 18 | McAfee Default |  | TELEMTRY1000 | Product Improvement Program  | 9 | General |
>| TELEMTRY1000 | Product Improvement Program | 19 | My Default |  | TELEMTRY1000 | Product Improvement Program  | 9 | General |


### epo-assign-policy
***
Assign Policy to Endpoints or Endpoint Groups


#### Base Command

`epo-assign-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | ePO Policy ID. | Required | 
| type_id | ePO Policy Type ID. | Required | 
| product_id | ePO Policy Product ID. | Required | 
| endpoints | Comma seperated list of endpoints to assign the policy to. | Optional | 
| groups | Comma seperated list of groups to assign the policy to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeEPO.PolicyAssignTasks.id | Unknown | Task ID | 
| McAfeeEPO.PolicyAssignTasks.message | Unknown | Task Message | 
| McAfeeEPO.PolicyAssignTasks.name | Unknown | Task Computer Name | 
| McAfeeEPO.PolicyAssignTasks.status | Unknown | Task Status | 


#### Command Example
```!epo-assign-policy policy_id="77" type_id="14" product_id="ENDP_FW_META" endpoints="W7CLIENT,WIN-KGR51CJ40N0"```

#### Context Example
```json
{
    "McAfeeEPO": {
        "PolicyAssignTasks": [
            {
                "id": "2",
                "message": "Assign policy succeeded",
                "name": "W7CLIENT",
                "status": 0
            },
            {
                "id": "1",
                "message": "Assign policy succeeded",
                "name": "WIN-KGR51CJ40N0",
                "status": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|id|message|name|status|
>|---|---|---|---|
>| 2 | Assign policy succeeded | W7CLIENT | 0 |
>| 1 | Assign policy succeeded | WIN-KGR51CJ40N0 | 0 |


### epo-find-systems
***
Find systems by search keyword


#### Base Command

`epo-find-systems`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keyword | Search keyword. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeEPO.Systems.ComputerName | Unknown | System HostName | 
| McAfeeEPO.Systems.IPAddress | Unknown | System IP Address | 
| McAfeeEPO.Systems.AgentGUID | Unknown | Agent GUID | 
| McAfeeEPO.Systems.DomainName | Unknown | Domain Name | 


#### Command Example
```!epo-find-systems keyword="W7CLIENT"```

#### Context Example
```json
{
    "McAfeeEPO": {
        "Systems": {
            "AgentGUID": "8EB28509-9372-409F-BCAC-DAB4F2ED7EF1",
            "AgentVersion": "5.5.1.342",
            "AutoID": 4,
            "CPUSerialNumber": "N/A",
            "CPUSpeed": 2000,
            "CPUType": "Intel(R) Xeon(R) CPU E5-2640 v2 @ 2.00GHz",
            "ComputerDescription": "N/A",
            "ComputerName": "W7CLIENT",
            "DefaultLangID": "0409",
            "Description": null,
            "DomainName": "AYMAN",
            "ExcludedTags": "",
            "FreeDiskSpace": 3028,
            "FreeMemory": 3183710208,
            "Free_Space_of_Drive_C": 3028,
            "IPAddress": "192.168.20.102",
            "IPHostName": "w7client.ayman.local",
            "IPSubnet": "0:0:0:0:0:FFFF:C0A8:1400",
            "IPSubnetMask": "0:0:0:0:0:FFFF:FFFF:FF00",
            "IPV4x": null,
            "IPV6": "0:0:0:0:0:FFFF:C0A8:1466",
            "IPXAddress": "N/A",
            "IsPortable": 0,
            "LastAgentHandler": 1,
            "LastUpdate": "2021-04-07T07:21:55-07:00",
            "ManagedState": 1,
            "NetAddress": "000C295809F9",
            "NumOfCPU": 1,
            "OSBitMode": 1,
            "OSBuildNum": 7601,
            "OSCsdVersion": "Service Pack 1",
            "OSOEMID": "00371-868-0000007-85607",
            "OSPlatform": "Workstation",
            "OSType": "Windows 7",
            "OSVersion": "6.1",
            "ParentID": 2,
            "SubnetAddress": "192.168.20.0",
            "SubnetMask": "255.255.255.0",
            "Tags": "Endpoint ATP, Endpoint Security Platfrom, Install Firewall, Threat Prevention, Workstation",
            "TimeZone": "Arabian Standard Time",
            "TotalDiskSpace": 32665,
            "TotalPhysicalMemory": 4294434816,
            "Total_Space_of_Drive_C": 32665,
            "UserName": "N/A",
            "UserProperty1": "",
            "UserProperty2": "",
            "UserProperty3": "",
            "UserProperty4": "",
            "UserProperty5": "",
            "UserProperty6": "",
            "UserProperty7": "",
            "UserProperty8": "",
            "Vdi": 0
        }
    }
}
```

#### Human Readable Output

>### Results
>|AgentGUID|AgentVersion|AutoID|CPUSerialNumber|CPUSpeed|CPUType|ComputerDescription|ComputerName|DefaultLangID|Description|DomainName|ExcludedTags|FreeDiskSpace|FreeMemory|Free_Space_of_Drive_C|IPAddress|IPHostName|IPSubnet|IPSubnetMask|IPV4x|IPV6|IPXAddress|IsPortable|LastAgentHandler|LastUpdate|ManagedState|NetAddress|NumOfCPU|OSBitMode|OSBuildNum|OSCsdVersion|OSOEMID|OSPlatform|OSType|OSVersion|ParentID|SubnetAddress|SubnetMask|Tags|TimeZone|TotalDiskSpace|TotalPhysicalMemory|Total_Space_of_Drive_C|UserName|UserProperty1|UserProperty2|UserProperty3|UserProperty4|UserProperty5|UserProperty6|UserProperty7|UserProperty8|Vdi|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 8EB28509-9372-409F-BCAC-DAB4F2ED7EF1 | 5.5.1.342 | 4 | N/A | 2000 | Intel(R) Xeon(R) CPU E5-2640 v2 @ 2.00GHz | N/A | W7CLIENT | 0409 |  | AYMAN |  | 3028 | 3183710208 | 3028 | 192.168.20.102 | w7client.ayman.local | 0:0:0:0:0:FFFF:C0A8:1400 | 0:0:0:0:0:FFFF:FFFF:FF00 |  | 0:0:0:0:0:FFFF:C0A8:1466 | N/A | 0 | 1 | 2021-04-07T07:21:55-07:00 | 1 | 000C295809F9 | 1 | 1 | 7601 | Service Pack 1 | 00371-868-0000007-85607 | Workstation | Windows 7 | 6.1 | 2 | 192.168.20.0 | 255.255.255.0 | Endpoint ATP, Endpoint Security Platfrom, Install Firewall, Threat Prevention, Workstation | Arabian Standard Time | 32665 | 4294434816 | 32665 | N/A |  |  |  |  |  |  |  |  | 0 |

