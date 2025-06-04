# CloudShare

This integration is a BETA that covers the API commands from CloudShare.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cloudshare-get-envs

***
Retrieves environments

#### Base Command

`cloudshare-get-envs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owned | Returns only environments owned by the user. Possible values are: true, false. Default is false. | Optional |
| visible | Returns all environments visible to the user. Possible values are: true, false. Default is false. | Optional |
| ownerEmail | Optional. Filters results by the environment owner's email address, where {ownerEmail} is the environment owner's email address. | Optional |
| classId | Optional. Filters results to include only environments created for a specified class, including instructor and student environments, where {classId} is the ID of the class. | Optional |
| brief | Optional. Whether to return a less detailed or more detailed response. {brief_value} can be: true (default) - Returns less detail. false - Returns more detail. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Environments.projectId | string | Project ID |
| CloudShare.Environments.policyId | string | Policy ID |
| CloudShare.Environments.blueprintId | string | Blueprint ID |
| CloudShare.Environments.description | string | Description |
| CloudShare.Environments.ownerEmail | string | Owner email |
| CloudShare.Environments.regionId | string | Region ID |
| CloudShare.Environments.name | string | Name |
| CloudShare.Environments.id | string | ID |
| CloudShare.Environments.status | string | Status |
| CloudShare.Environments.teamId | string | Team ID |

### cloudshare-get-projects

***
Retrieves all available projects

#### Base Command

`cloudshare-get-projects`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| WhereUserIsProjectManager | Returns only projects in which the user is a project manager. Possible values are: tru, false. Default is false. | Optional |
| WhereUserIsProjectMember | Returns only projects in which the user is a project member. Possible values are: true, false. Default is false. | Optional |
| WhereUserCanCreateClass | Returns only projects in which the user is allowed to create a class. The minimum user level allowed to create classes is set per project and can be changed by project manager users. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Projects.name | string | Name |
| CloudShare.Projects.isActive | boolean | Is Active |
| CloudShare.Projects.id | string | ID |

### cloudshare-get-project

***
Retrieves a specified project's details

#### Base Command

`cloudshare-get-project`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| projectId | The ID of a specific project. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Projects.id | string | ID |
| CloudShare.Projects.name | string | Name |
| CloudShare.Projects.hasNonGenericPolicy | boolean | Has non-generic policy |
| CloudShare.Projects.canAddPolicy | boolean | Can add policy |
| CloudShare.Projects.awsEnabled | boolean | AWS enabled |
| CloudShare.Projects.environmentResourceQuota.cpuCount | number | CPU count |
| CloudShare.Projects.environmentResourceQuota.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Projects.environmentResourceQuota.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Projects.projectResourceQuota.cpuCount | number | CPU count |
| CloudShare.Projects.projectResourceQuota.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Projects.projectResourceQuota.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Projects.subscriptionResourceQuota.cpuCount | number | CPU count |
| CloudShare.Projects.subscriptionResourceQuota.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Projects.subscriptionResourceQuota.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Projects.canCreateFromScratch | boolean | Can create from scratch |
| CloudShare.Projects.defaultPolicyForEnvCreation | string | Default policy for env creation |
| CloudShare.Projects.isActive | boolean | Is active |

### cloudshare-get-project-policies

***
Retrieves all environment policies available in a specified project. Environment policies define how long an environment will run, when it will be deleted, and what happens to it when it has been idle for a certain length of time.

#### Base Command

`cloudshare-get-project-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| projectId | The ID of the project. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Project.Policies.allowEnvironmentCreation | boolean | Allow environment creation |
| CloudShare.Project.Policies.id | string | ID |
| CloudShare.Project.Policies.name | string | Name |
| CloudShare.Project.Policies.projectId | string | Project ID |

### cloudshare-get-project-blueprints

***
Retrieves all blueprints available in a specified project

#### Base Command

`cloudshare-get-project-blueprints`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| projectId | The Id of the project. | Required |
| regionId | The ID of a region. Returns all blueprints that have default snapshots on the specified region.  If unspecified, returns all blueprints in the project on all regions. | Optional |
| defaultSnapshot |  If set to true - get the default snapshot for every blueprint. The returned JSON will contain a property 'CreateFromVersions', which is an array of one element - the default snapshot. If unspecified, default is false (don't return the default snapshot). Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Projects.Blueprints.id | string | ID |
| CloudShare.Projects.Blueprints.name | string | Name |
| CloudShare.Projects.Blueprints.description | string | Description |
| CloudShare.Projects.Blueprints.isEnvironmentTemplate | boolean | Is template |
| CloudShare.Projects.Blueprints.type | number | Type |
| CloudShare.Projects.Blueprints.imageUrl | string | Image URL |
| CloudShare.Projects.Blueprints.tags | unknown | Tags |
| CloudShare.Projects.Blueprints.categories | unknown | Categories |
| CloudShare.Projects.Blueprints.resources.cpuCount | number | CPU count |
| CloudShare.Projects.Blueprints.resources.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Projects.Blueprints.resources.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Projects.Blueprints.numberOfMachines | number | Number of machines |
| CloudShare.Projects.Blueprints.hasMultipleVersions | boolean | Has multiple versions |
| CloudShare.Projects.Blueprints.hasDefaultVersion | boolean | Has default version |
| CloudShare.Projects.Blueprints.disabledForRegularEnvironmentCreation | boolean | Disabled for regular environment creation |
| CloudShare.Projects.Blueprints.disabledForTrainingEnvironmentCreation | boolean | Disabled for training environment creation |
| CloudShare.Projects.Blueprints.canAddMultipleInstances | boolean | Can add multiple instances |
| CloudShare.Projects.Blueprints.envTemplateScope | unknown | Environment template scope |
| CloudShare.Projects.Blueprints.creationDate | string | Creation date |
| CloudShare.Projects.Blueprints.CreateFromVersions.Machines | unknown | Machines |
| CloudShare.Projects.Blueprints.CreateFromVersions.AuthorName | string | Author name |
| CloudShare.Projects.Blueprints.CreateFromVersions.Comment | string | Comment |
| CloudShare.Projects.Blueprints.CreateFromVersions.Type | number | Type |
| CloudShare.Projects.Blueprints.CreateFromVersions.Name | string | Name |
| CloudShare.Projects.Blueprints.CreateFromVersions.IsDefault | boolean | Is default |
| CloudShare.Projects.Blueprints.CreateFromVersions.IsLatest | boolean | Is latest |
| CloudShare.Projects.Blueprints.CreateFromVersions.Number | number | Number |
| CloudShare.Projects.Blueprints.CreateFromVersions.Resources.CpuCount | number | CPU count |
| CloudShare.Projects.Blueprints.CreateFromVersions.Resources.DiskSizeMB | number | Disk size\(MB\) |
| CloudShare.Projects.Blueprints.CreateFromVersions.Resources.MemorySizeMB | number | Memory size\(MB\) |
| CloudShare.Projects.Blueprints.CreateFromVersions.CreateTime | string | Create time |
| CloudShare.Projects.Blueprints.CreateFromVersions.Description | string | Description |
| CloudShare.Projects.Blueprints.CreateFromVersions.ImageUrl | string | Image URL |
| CloudShare.Projects.Blueprints.CreateFromVersions.Regions | unknown | Regions |
| CloudShare.Projects.Blueprints.CreateFromVersions.Id | string | ID |

### cloudshare-get-project-blueprint

***
Retrieves details of a specified blueprint, including snapshots.

#### Base Command

`cloudshare-get-project-blueprint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| projectId | The ID of the project in which the blueprint resides. | Required |
| blueprintId | The ID of the blueprint. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Projects.Blueprints.id | string | ID |
| CloudShare.Projects.Blueprints.name | string | Name |
| CloudShare.Projects.Blueprints.description | string | Description |
| CloudShare.Projects.Blueprints.isEnvironmentTemplate | boolean | Is template |
| CloudShare.Projects.Blueprints.type | number | Type |
| CloudShare.Projects.Blueprints.imageUrl | string | Image URL |
| CloudShare.Projects.Blueprints.tags | unknown | Tags |
| CloudShare.Projects.Blueprints.categories | unknown | Categories |
| CloudShare.Projects.Blueprints.resources.cpuCount | number | CPU count |
| CloudShare.Projects.Blueprints.resources.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Projects.Blueprints.resources.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Projects.Blueprints.numberOfMachines | number | Number of machines |
| CloudShare.Projects.Blueprints.hasMultipleVersions | boolean | Has multiple versions |
| CloudShare.Projects.Blueprints.hasDefaultVersion | boolean | Has default version |
| CloudShare.Projects.Blueprints.disabledForRegularEnvironmentCreation | boolean | Disabled for regular environment creation |
| CloudShare.Projects.Blueprints.disabledForTrainingEnvironmentCreation | boolean | Disabled for training environment creation |
| CloudShare.Projects.Blueprints.canAddMultipleInstances | boolean | Can add multiple instances |
| CloudShare.Projects.Blueprints.envTemplateScope | unknown | Environment template scope |
| CloudShare.Projects.Blueprints.creationDate | string | Creation date |
| CloudShare.Projects.Blueprints.CreateFromVersions.Machines | unknown | Machines |
| CloudShare.Projects.Blueprints.CreateFromVersions.AuthorName | string | Author name |
| CloudShare.Projects.Blueprints.CreateFromVersions.Comment | string | Comment |
| CloudShare.Projects.Blueprints.CreateFromVersions.Type | number | Type |
| CloudShare.Projects.Blueprints.CreateFromVersions.Name | string | Name |
| CloudShare.Projects.Blueprints.CreateFromVersions.IsDefault | boolean | Is default |
| CloudShare.Projects.Blueprints.CreateFromVersions.IsLatest | boolean | Is latest |
| CloudShare.Projects.Blueprints.CreateFromVersions.Number | number | Number |
| CloudShare.Projects.Blueprints.CreateFromVersions.Resources.CpuCount | number | CPU count |
| CloudShare.Projects.Blueprints.CreateFromVersions.Resources.DiskSizeMB | number | Disk size\(MB\) |
| CloudShare.Projects.Blueprints.CreateFromVersions.Resources.MemorySizeMB | number | Memory size\(MB\) |
| CloudShare.Projects.Blueprints.CreateFromVersions.CreateTime | string | Create time |
| CloudShare.Projects.Blueprints.CreateFromVersions.Description | string | Description |
| CloudShare.Projects.Blueprints.CreateFromVersions.ImageUrl | string | Image URL |
| CloudShare.Projects.Blueprints.CreateFromVersions.Regions | unknown | Regions |
| CloudShare.Projects.Blueprints.CreateFromVersions.Id | string | ID |

### cloudshare-get-classes

***
Retrieves all classes visible to the user

#### Base Command

`cloudshare-get-classes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Classes.instructorEmail | string | Instructor email |
| CloudShare.Classes.timeZoneName | string | Timezone name |
| CloudShare.Classes.startDate | string | Start date |
| CloudShare.Classes.endDate | string | End date |
| CloudShare.Classes.status | string | Status |
| CloudShare.Classes.name | unknown | Name |
| CloudShare.Classes.shortId | string | Short ID |
| CloudShare.Classes.id | string | ID |
| CloudShare.Classes.regionId | string | Region ID |

### cloudshare-get-class

***
Retrieves details of a specified class

#### Base Command

`cloudshare-get-class`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classId | The id of the class. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Classes.id | string | ID |
| CloudShare.Classes.name | string | Name |
| CloudShare.Classes.shortId | string | Short ID |
| CloudShare.Classes.policyId | string | Policy ID |
| CloudShare.Classes.policyName | string | Policy name |
| CloudShare.Classes.isUsingClassTypes | boolean | Is issuing class types |
| CloudShare.Classes.blueprintId | string | Blueprint ID |
| CloudShare.Classes.blueprintName | string | Blueprint name |
| CloudShare.Classes.blueprintToken | string | Blueprint token |
| CloudShare.Classes.cloudName | string | Cloud name |
| CloudShare.Classes.timeZoneId | string | Timezone ID |
| CloudShare.Classes.projectId | string | Project ID |
| CloudShare.Classes.projectName | string | Project name |
| CloudShare.Classes.creatorName | string | Creator name |
| CloudShare.Classes.creatorEmail | string | Creator email |
| CloudShare.Classes.instructorVupId | string | Instructor VUP ID |
| CloudShare.Classes.instructorName | string | Instructor name |
| CloudShare.Classes.defaultDurationInMinutes | number | Default duration \(mins\) |
| CloudShare.Classes.allowStartDateEditing | boolean | Allow start date editing |
| CloudShare.Classes.limitEarlyAccess | number | Limit early access |
| CloudShare.Classes.studentPassphrase | string | Student passphrase |
| CloudShare.Classes.useCustomInvitationEmail | boolean | Use custom invitation email |
| CloudShare.Classes.showCourseAddressField | boolean | Show course address field |
| CloudShare.Classes.address | string | Address |
| CloudShare.Classes.customInvitationEmailSubject | string | Custom invitation email subject |
| CloudShare.Classes.customInvitationEmailBody | string | Custom invitation email body |
| CloudShare.Classes.defaultInvitationEmailSubject | string | Default invitation email subject |
| CloudShare.Classes.defaultInvitationEmailBody | string | Default invitation email subject |
| CloudShare.Classes.showPermitAccessToNonRegisteredStudent | boolean | Show permit access to non-registered student |
| CloudShare.Classes.allowEditDefaultsWhenPermitAccessToNonRegistered | boolean | Allow edit defaults when permit access to non registered |
| CloudShare.Classes.permitAccessToNonRegisteredStudent | boolean | Permit access to non registered student |
| CloudShare.Classes.showMaxStudentsField | boolean | Show max students field |
| CloudShare.Classes.maxStudents | number | Max students |
| CloudShare.Classes.maxLimitOnMaxStudentField | number | Max kimit on max student field |
| CloudShare.Classes.customFieldsValues.id | string | ID |
| CloudShare.Classes.customFieldsValues.order | number | Order |
| CloudShare.Classes.customFieldsValues.name | string | Name |
| CloudShare.Classes.customFieldsValues.type | number | Type |
| CloudShare.Classes.customFieldsValues.isRequired | boolean | Is required |
| CloudShare.Classes.customFieldsValues.regex | string | Regex |
| CloudShare.Classes.customFieldsValues.defaultValue | unknown | Default value |
| CloudShare.Classes.customFieldsValues.value | unknown | Value |
| CloudShare.Classes.instructorEmail | string | Instructor email |
| CloudShare.Classes.timeZoneName | string | Timezone name |
| CloudShare.Classes.startDate | string | Start date |
| CloudShare.Classes.endDate | string | End date |
| CloudShare.Classes.status | string | Status |

### cloudshare-delete-class

***
Deletes a class

#### Base Command

`cloudshare-delete-class`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classId | The id of the class. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-delete-class-environments

***
Deletes all active student environments in a class

#### Base Command

`cloudshare-delete-class-environments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classId | The ID of the class. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| cloudshare.Classes.Actions.Delete.failed | unknown | Failed deletions |
| cloudshare.Classes.Actions.Delete.succeed | unknown | Succeeded deletions |
| cloudshare.Classes.Actions.Delete.succeed.id | string | ID |
| cloudshare.Classes.Actions.Delete.succeed.email | string | Email |
| cloudshare.Classes.Actions.Delete.succeed.fullName | string | Full name |
| cloudshare.Classes.Actions.Delete.succeed.envId | string | Environment ID |

### cloudshare-get-classes-countries

***
Retrieves all countries that can be set as class locations

#### Base Command

`cloudshare-get-classes-countries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Classes.Countries.code | string | Code |
| CloudShare.Classes.Countries.englishName | string | English name |
| CloudShare.Classes.Countries.states | unknown | States |

### cloudshare-get-classes-customfields

***
Retrieves any custom class creation fields defined in a specified project.

#### Base Command

`cloudshare-get-classes-customfields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| projectId | The id of the project. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Classes.CustomFields.id | string | ID |
| CloudShare.Classes.CustomFields.order | number | Order |
| CloudShare.Classes.CustomFields.name | string | Name |
| CloudShare.Classes.CustomFields.type | number | Type |
| CloudShare.Classes.CustomFields.isRequired | boolean | Is required |
| CloudShare.Classes.CustomFields.regex | string | Regex |
| CloudShare.Classes.CustomFields.defaultValue | unknown | Default value |
| CloudShare.Classes.CustomFields.value | unknown | Value |

### cloudshare-get-classes-detailed

***
Retrieves all the details of a specified class, including full student data.

#### Base Command

`cloudshare-get-classes-detailed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classId | The id of the class. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Classes.Class.id | string | ID |
| CloudShare.Classes.Class.name | string | Name |
| CloudShare.Classes.Class.shortId | string | Short ID |
| CloudShare.Classes.Class.policyId | string | Policy ID |
| CloudShare.Classes.Class.policyName | string | Policy name |
| CloudShare.Classes.Class.isUsingClassTypes | boolean | Is issuing class types |
| CloudShare.Classes.Class.blueprintId | string | Blueprint ID |
| CloudShare.Classes.Class.blueprintName | string | Blueprint name |
| CloudShare.Classes.Class.blueprintToken | string | Blueprint token |
| CloudShare.Classes.Class.cloudName | string | Cloud name |
| CloudShare.Classes.Class.timeZoneId | string | Timezone ID |
| CloudShare.Classes.Class.projectId | string | Project ID |
| CloudShare.Classes.Class.projectName | string | Project name |
| CloudShare.Classes.Class.creatorName | string | Creator name |
| CloudShare.Classes.Class.creatorEmail | string | Creator email |
| CloudShare.Classes.Class.instructorVupId | string | Instructor VUP ID |
| CloudShare.Classes.Class.instructorName | string | Instructor name |
| CloudShare.Classes.Class.defaultDurationInMinutes | number | Default duration \(mins\) |
| CloudShare.Classes.Class.allowStartDateEditing | boolean | Allow start date editing |
| CloudShare.Classes.Class.limitEarlyAccess | number | Limit early access |
| CloudShare.Classes.Class.studentPassphrase | string | Student passphrase |
| CloudShare.Classes.Class.useCustomInvitationEmail | boolean | Use custom invitation email |
| CloudShare.Classes.Class.showCourseAddressField | boolean | Show course address field |
| CloudShare.Classes.Class.address | string | Address |
| CloudShare.Classes.Class.customInvitationEmailSubject | string | Custom invitation email subject |
| CloudShare.Classes.Class.customInvitationEmailBody | string | Custom invitation email body |
| CloudShare.Classes.Class.defaultInvitationEmailSubject | string | Default invitation email subject |
| CloudShare.Classes.Class.defaultInvitationEmailBody | string | Default invitation email subject |
| CloudShare.Classes.Class.showPermitAccessToNonRegisteredStudent | boolean | Show permit access to non-registered student |
| CloudShare.Classes.Class.allowEditDefaultsWhenPermitAccessToNonRegistered | boolean | Allow edit defaults when permit access to non registered |
| CloudShare.Classes.Class.permitAccessToNonRegisteredStudent | boolean | Permit access to non registered student |
| CloudShare.Classes.Class.showMaxStudentsField | boolean | Show max students field |
| CloudShare.Classes.Class.maxStudents | number | Max students |
| CloudShare.Classes.Class.maxLimitOnMaxStudentField | number | Max kimit on max student field |
| CloudShare.Classes.Class.customFieldsValues.id | string | ID |
| CloudShare.Classes.Class.customFieldsValues.order | number | Order |
| CloudShare.Classes.Class.customFieldsValues.name | string | Name |
| CloudShare.Classes.Class.customFieldsValues.type | number | Type |
| CloudShare.Classes.Class.customFieldsValues.isRequired | boolean | Is required |
| CloudShare.Classes.Class.customFieldsValues.regex | string | Regex |
| CloudShare.Classes.Class.customFieldsValues.defaultValue | unknown | Default value |
| CloudShare.Classes.Class.customFieldsValues.value | unknown | Value |
| CloudShare.Classes.Class.instructorEmail | string | Instructor email |
| CloudShare.Classes.Class.timeZoneName | string | Timezone name |
| CloudShare.Classes.Class.startDate | string | Start date |
| CloudShare.Classes.Class.endDate | string | End date |
| CloudShare.Classes.Class.status | string | Status |
| CloudShare.Classes.Students.firstName | string | First name |
| CloudShare.Classes.Students.lastName | string | Last name |
| CloudShare.Classes.Students.email | string | Email |
| CloudShare.Classes.Students.company | string | Company |
| CloudShare.Classes.Students.jobLevel | string | Job level |
| CloudShare.Classes.Students.address1 | string | Address 1 |
| CloudShare.Classes.Students.address2 | string | Address 2 |
| CloudShare.Classes.Students.city | string | City |
| CloudShare.Classes.Students.state | string | State |
| CloudShare.Classes.Students.zipCode | string | Zip code |
| CloudShare.Classes.Students.country | string | Country |
| CloudShare.Classes.Students.phone | string | Phone |
| CloudShare.Classes.Students.regCode | string | Reg code |
| CloudShare.Classes.Students.id | string | ID |

### cloudshare-get-classes-instructors

***
Retrieves project member users who can be assigned to classes as instructors

#### Base Command

`cloudshare-get-classes-instructors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyId | The ID of a policy. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Classes.Instructors.id | string | ID |
| CloudShare.Classes.Instructors.name | string | Name |
| CloudShare.Classes.Instructors.email | string | Email |

### cloudshare-create-class

***
Creates a class

#### Base Command

`cloudshare-create-class`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| PolicyId | The ID of the policy to apply to the class. The policy will control the runtime and storage time of each student's environment and what will happen to the environment when it is inactive. | Required |
| BlueprintId | The ID of the blueprint to base the class on. Students who attend the class will be served environments based on this blueprint. | Required |
| ProjectId | The ID of the project in which the class will be created. The specified blueprint and instructor must be from the same project. | Required |
| InstructorVupId | The ID of the project member user to assign to the class as the instructor. | Required |
| RegionId | The ID of the region the class should be created in. | Optional |
| StartDate | The date and time at which to start the class, in MM/DD/YYYY HH:MM AM/PM format. | Required |
| TimeZoneId | The ID of the timezone for the startDate. | Required |
| StudentPassphrase | The passphrase that students will need to enter in order to attend the class. | Required |
| UseCustomInvitationEmail | Whether or not the student invitation email is customized. Possible values are: false, true. Default is false. | Optional |
| LimitEarlyAccess | This option controls access by students and instructor to a lab before scheduled class time. Possible values: 0 - Allow lab access before class (default). 1 - Allow lab access before class for instructor only. 2 - No early access allowed. Possible values are: 0, 1, 2. Default is 0. | Required |
| CustomInvitationEmailSubject | The subject line of the custom student invitation email. Used if UseCustomInvitationEmail is set to true. | Optional |
| CustomInvitationEmailBody | The body of the custom student invitation email. Used if UseCustomInvitationEmail is set to true. | Optional |
| PermitAccessToNonRegisteredStudent | Whether to permit users to self register as students for the class. Possible values are: false, true. Default is false. | Optional |
| MaxStudents | Numeric. The maximum number of students allowed in the class (can be null). Maximum value: 60. | Optional |
| address | The location of the class (JSON dictionary) including keys: state, address1, address2, zipCode, city,  country (To retrieve valid values for country, use cloudshare-get-classes-countries). | Optional |
| CustomFieldsValues | Specifies input values for custom fields defined for class creation in the project. Mandatory if project forces validation of custom fields. Fields and valid values depend on custom fields structure for the project. To retrieve custom fields structure for the project, use cloudshare-get-classes-customfields. | Optional |
| enableSteps | Enables the class to have multiple steps. Possible values are: false, true. Default is false. | Optional |
| StudentsCanSwitchStep | Whether students can change steps independently. Applies when enableSteps is set to true. Possible values are: false, true. Default is false. | Optional |
| steps | A list of class steps (JSON dictionaries) for a multi-step class. Must be provided if enableSteps is set to true. | Optional |
| selfPaced | Creates a Self-Paced Class that allows a student to enter class at a time convenient to them. Possible values are: false, true. Default is false. | Optional |
| allowMultipleStudentLogin | When set to true, allows for more than one environment activation per student. Possible values are: false, true. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Classes.id | string | ID |

### cloudshare-send-class-invitations

***
Sends invitations to students to attend a class

#### Base Command

`cloudshare-send-class-invitations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classId | The ID of the class. | Required |
| studentIds | A list (CSV) of IDs of students to send invite invitations to. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-suspend-class-environments

***
Suspends all running student environments in a specified class

#### Base Command

`cloudshare-suspend-class-environments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classId | The ID of the class. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Classes.Suspended.failed.id | string | ID |
| CloudShare.Classes.Suspended.succeed.id | string | ID |
| CloudShare.Classes.Suspended.succeed.email | string | Email |
| CloudShare.Classes.Suspended.succeed.fullName | string | Full name |
| CloudShare.Classes.Suspended.succeed.envId | string | Environment ID |

### cloudshare-modify-class

***
Modifies a class

#### Base Command

`cloudshare-modify-class`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instructorVupId | The ID of the project member user to assign to the class as the instructor. | Optional |
| startDate | The date and time at which to start the class, in MM/DD/YYYY HH:MM AM/PM format. | Optional |
| timeZoneId | The ID of the timezone for the startDate. | Optional |
| studentPassphrase | The passphrase that students will need to enter in order to attend the class. | Optional |
| useCustomInvitationEmail | Whether or not the student invitation email is customized. Possible values are: false, true. Default is false. | Optional |
| limitEarlyAccess | This option controls access by students and instructor to a lab before scheduled class time. Possible values: 0 - Allow lab access before class (default). 1 - Allow lab access before class for instructor only. 2 - No early access allowed. Possible values are: 0, 1, 2. Default is 0. | Optional |
| customInvitationEmailSubject | The subject line of the custom student invitation email. Used if UseCustomInvitationEmail is set to true. | Optional |
| customInvitationEmailBody | The body of the custom student invitation email. Used if UseCustomInvitationEmail is set to true. | Optional |
| permitAccessToNonRegisteredStudent | Whether to permit users to self register as students for the class. Possible values are: false, true. Default is false. | Optional |
| maxStudents | Numeric. The maximum number of students allowed in the class (can be null). Maximum value: 60. | Optional |
| address | The location of the class (JSON dictionary) including keys: state, address1, address2, zipCode, city,  country (To retrieve valid values for country, use cloudshare-get-classes-countries). | Optional |
| customFieldsValues | Specifies input values for custom fields defined for class creation in the project. Mandatory if project forces validation of custom fields. Fields and valid values depend on custom fields structure for the project. To retrieve custom fields structure for the project, use cloudshare-get-classes-customfields. | Optional |
| selfPaced | Creates a Self-Paced Class that allows a student to enter class at a time convenient to them. Possible values are: false, true. Default is false. | Optional |
| allowMultipleStudentLogin | When set to true, allows for more than one environment activation per student. Possible values are: false, true. Default is false. | Optional |
| classId | The ID of the class. | Required |
| name | The name of the class. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Classes.id | string | ID |
| CloudShare.Classes.name | string | Name |
| CloudShare.Classes.shortId | string | Short ID |
| CloudShare.Classes.policyId | string | Policy ID |
| CloudShare.Classes.policyName | string | Policy name |
| CloudShare.Classes.isUsingClassTypes | boolean | Is issuing class types |
| CloudShare.Classes.blueprintId | string | Blueprint ID |
| CloudShare.Classes.blueprintName | string | Blueprint name |
| CloudShare.Classes.blueprintToken | string | Blueprint token |
| CloudShare.Classes.cloudName | string | Cloud name |
| CloudShare.Classes.timeZoneId | string | Timezone ID |
| CloudShare.Classes.projectId | string | Project ID |
| CloudShare.Classes.projectName | string | Project name |
| CloudShare.Classes.creatorName | string | Creator name |
| CloudShare.Classes.creatorEmail | string | Creator email |
| CloudShare.Classes.instructorVupId | string | Instructor VUP ID |
| CloudShare.Classes.instructorName | string | Instructor name |
| CloudShare.Classes.defaultDurationInMinutes | number | Default duration \(mins\) |
| CloudShare.Classes.allowStartDateEditing | boolean | Allow start date editing |
| CloudShare.Classes.limitEarlyAccess | number | Limit early access |
| CloudShare.Classes.studentPassphrase | string | Student passphrase |
| CloudShare.Classes.useCustomInvitationEmail | boolean | Use custom invitation email |
| CloudShare.Classes.showCourseAddressField | boolean | Show course address field |
| CloudShare.Classes.address | string | Address |
| CloudShare.Classes.customInvitationEmailSubject | string | Custom invitation email subject |
| CloudShare.Classes.customInvitationEmailBody | string | Custom invitation email body |
| CloudShare.Classes.defaultInvitationEmailSubject | string | Default invitation email subject |
| CloudShare.Classes.defaultInvitationEmailBody | string | Default invitation email subject |
| CloudShare.Classes.showPermitAccessToNonRegisteredStudent | boolean | Show permit access to non-registered student |
| CloudShare.Classes.allowEditDefaultsWhenPermitAccessToNonRegistered | boolean | Allow edit defaults when permit access to non registered |
| CloudShare.Classes.permitAccessToNonRegisteredStudent | boolean | Permit access to non registered student |
| CloudShare.Classes.showMaxStudentsField | boolean | Show max students field |
| CloudShare.Classes.maxStudents | number | Max students |
| CloudShare.Classes.maxLimitOnMaxStudentField | number | Max kimit on max student field |
| CloudShare.Classes.customFieldsValues.id | string | ID |
| CloudShare.Classes.customFieldsValues.order | number | Order |
| CloudShare.Classes.customFieldsValues.name | string | Name |
| CloudShare.Classes.customFieldsValues.type | number | Type |
| CloudShare.Classes.customFieldsValues.isRequired | boolean | Is required |
| CloudShare.Classes.customFieldsValues.regex | string | Regex |
| CloudShare.Classes.customFieldsValues.defaultValue | unknown | Default value |
| CloudShare.Classes.customFieldsValues.value | unknown | Value |
| CloudShare.Classes.instructorEmail | string | Instructor email |
| CloudShare.Classes.timeZoneName | string | Timezone name |
| CloudShare.Classes.startDate | string | Start date |
| CloudShare.Classes.endDate | string | End date |
| CloudShare.Classes.status | string | Status |

### cloudshare-get-students

***
Retrieves information about the students in a class

#### Base Command

`cloudshare-get-students`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classId | The ID of the class. | Required |
| isFull | Whether to return the details of the VMs in each student's environment as well as other details. Possible values are: false, true. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Students.status | number | Status |
| CloudShare.Students.envStatus | number | Environemtn Status |
| CloudShare.Students.envCommands | unknown | Environment commands |
| CloudShare.Students.envId | string | Environment ID |
| CloudShare.Students.firstName | string | First name |
| CloudShare.Students.lastName | string | Last name |
| CloudShare.Students.email | string | Email |
| CloudShare.Students.id | string | ID |
| CloudShare.Students.VMs.id | string | ID |
| CloudShare.Students.VMs.name | string | Name |

### cloudshare-get-student

***
Retrieves information about a student in a class, including the student's environment and VMs

#### Base Command

`cloudshare-get-student`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classId | The ID of the class. | Required |
| studentId | The ID of the student in the class. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Students.status | number | Status |
| CloudShare.Students.envStatus | number | Environemtn Status |
| CloudShare.Students.envCommands | unknown | Environment commands |
| CloudShare.Students.envId | string | Environment ID |
| CloudShare.Students.firstName | string | First name |
| CloudShare.Students.lastName | string | Last name |
| CloudShare.Students.email | string | Email |
| CloudShare.Students.id | string | ID |
| CloudShare.Students.VMs.id | string | ID |
| CloudShare.Students.VMs.name | string | Name |

### cloudshare-delete-student

***
Removes a student from a class

#### Base Command

`cloudshare-delete-student`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classId | The ID of the class. | Required |
| studentId | The ID of the student. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-register-student

***
Registers a student for a class

#### Base Command

`cloudshare-register-student`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classID | The ID of the class. | Required |
| email | The student's email address. | Required |
| firstName | The student's first name. | Required |
| lastName | The student's last name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Students.id | string | ID |

### cloudshare-modify-student

***
Modifies a student's registration details

#### Base Command

`cloudshare-modify-student`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classId | The ID of the class for which the student is registered. | Required |
| studentId | The ID of the student. | Required |
| email | The student's email address. This can be changed as long as the student did not yet log in. | Optional |
| firstName | The student's first name. | Optional |
| lastName | The student's last name. | Optional |

#### Context Output

There is no context output for this command.

### cloudshare-get-regions

***
Retrieves available regions

#### Base Command

`cloudshare-get-regions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Regions.id | string | ID |
| CloudShare.Regions.name | string | Name |
| CloudShare.Regions.cloudName | string | Cloud name |
| CloudShare.Regions.friendlyName | string | Friendly name |

### cloudshare-get-timezones

***
Retrieves available time zones

#### Base Command

`cloudshare-get-timezones`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Timezones.id | string | ID |
| CloudShare.Timezones.displayName | string | Display name |

### cloudshare-get-env-resource

***
Retrieves the total resources that have been used by an environment

#### Base Command

`cloudshare-get-env-resource`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envId | The environment ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.EnvironmentResources.totalRuntimeHours | number | Total run time |
| CloudShare.EnvironmentResources.totalGbh | number | Total GB / hour |
| CloudShare.EnvironmentResources.maxDiskGb | number | Max disk space\(GB\) |
| CloudShare.EnvironmentResources.lastUpdateTime | string | Last update time |
| CloudShare.EnvironmentResources.name | string | Name |
| CloudShare.EnvironmentResources.id | string | ID |

### cloudshare-get-env-extended

***
Retrieves details of an environment along with VM information

#### Base Command

`cloudshare-get-env-extended`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envId | The ID of the environment. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Environments.projectId | string | Project ID |
| CloudShare.Environments.policyId | string | Policy ID |
| CloudShare.Environments.blueprintId | string | Blueprint ID |
| CloudShare.Environments.description | string | Description |
| CloudShare.Environments.ownerEmail | string | Owner email |
| CloudShare.Environments.regionId | string | Region ID |
| CloudShare.Environments.name | string | Name |
| CloudShare.Environments.id | string | ID |
| CloudShare.Environments.status | string | Status |
| CloudShare.Environments.teamId | string | Team ID |
| CloudShare.Environments.VMs.id | string | ID |
| CloudShare.Environments.VMs.name | string | Name |
| CloudShare.Environments.VMs.description | string | Description |
| CloudShare.Environments.VMs.statusText | string | Status text |
| CloudShare.Environments.VMs.progress | number | Progress |
| CloudShare.Environments.VMs.imageId | string | Image ID |
| CloudShare.Environments.VMs.os | string | OS |
| CloudShare.Environments.VMs.webAccessUrl | string | Web access URL |
| CloudShare.Environments.VMs.fqdn | string | FQDN |
| CloudShare.Environments.VMs.externalAddress | string | External address |
| CloudShare.Environments.VMs.internalAddresses | unknown | Internal addresses |
| CloudShare.Environments.VMs.cpuCount | number | CPU count |
| CloudShare.Environments.VMs.diskSizeGb | number | Disk size\(GB\) |
| CloudShare.Environments.VMs.memorySizeMb | number | Memory size\(MB\) |
| CloudShare.Environments.VMs.username | string | Username |
| CloudShare.Environments.VMs.password | string | Password |
| CloudShare.Environments.VMs.consoleToken | string | Console token |

### cloudshare-get-env-extended-vanity

***
Uses the vanity name or FQDN of a VM to retrieve details of an environment and its VMs

#### Base Command

`cloudshare-get-env-extended-vanity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machineVanity | Specifies the vanity name or FQDN of a machine. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Environments.projectId | string | Project ID |
| CloudShare.Environments.policyId | string | Policy ID |
| CloudShare.Environments.blueprintId | string | Blueprint ID |
| CloudShare.Environments.description | string | Description |
| CloudShare.Environments.ownerEmail | string | Owner email |
| CloudShare.Environments.regionId | string | Region ID |
| CloudShare.Environments.name | string | Name |
| CloudShare.Environments.id | string | ID |
| CloudShare.Environments.status | string | Status |
| CloudShare.Environments.teamId | string | Team ID |
| CloudShare.Environments.VMs.id | string | ID |
| CloudShare.Environments.VMs.name | string | Name |
| CloudShare.Environments.VMs.description | string | Description |
| CloudShare.Environments.VMs.statusText | string | Status text |
| CloudShare.Environments.VMs.progress | number | Progress |
| CloudShare.Environments.VMs.imageId | string | Image ID |
| CloudShare.Environments.VMs.os | string | OS |
| CloudShare.Environments.VMs.webAccessUrl | string | Web access URL |
| CloudShare.Environments.VMs.fqdn | string | FQDN |
| CloudShare.Environments.VMs.externalAddress | string | External address |
| CloudShare.Environments.VMs.internalAddresses | unknown | Internal addresses |
| CloudShare.Environments.VMs.cpuCount | number | CPU count |
| CloudShare.Environments.VMs.diskSizeGb | number | Disk size\(GB\) |
| CloudShare.Environments.VMs.memorySizeMb | number | Memory size\(MB\) |
| CloudShare.Environments.VMs.username | string | Username |
| CloudShare.Environments.VMs.password | string | Password |
| CloudShare.Environments.VMs.consoleToken | string | Console token |

### cloudshare-get-env-extended-token

***
Uses a sponsored login token to retrieve details of an environment along with VM information

#### Base Command

`cloudshare-get-env-extended-token`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sponsoredLoginToken | Specifies the token. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Environments.projectId | string | Project ID |
| CloudShare.Environments.policyId | string | Policy ID |
| CloudShare.Environments.blueprintId | string | Blueprint ID |
| CloudShare.Environments.description | string | Description |
| CloudShare.Environments.ownerEmail | string | Owner email |
| CloudShare.Environments.regionId | string | Region ID |
| CloudShare.Environments.name | string | Name |
| CloudShare.Environments.id | string | ID |
| CloudShare.Environments.status | string | Status |
| CloudShare.Environments.teamId | string | Team ID |
| CloudShare.Environments.VMs.id | string | ID |
| CloudShare.Environments.VMs.name | string | Name |
| CloudShare.Environments.VMs.description | string | Description |
| CloudShare.Environments.VMs.statusText | string | Status text |
| CloudShare.Environments.VMs.progress | number | Progress |
| CloudShare.Environments.VMs.imageId | string | Image ID |
| CloudShare.Environments.VMs.os | string | OS |
| CloudShare.Environments.VMs.webAccessUrl | string | Web access URL |
| CloudShare.Environments.VMs.fqdn | string | FQDN |
| CloudShare.Environments.VMs.externalAddress | string | External address |
| CloudShare.Environments.VMs.internalAddresses | unknown | Internal addresses |
| CloudShare.Environments.VMs.cpuCount | number | CPU count |
| CloudShare.Environments.VMs.diskSizeGb | number | Disk size\(GB\) |
| CloudShare.Environments.VMs.memorySizeMb | number | Memory size\(MB\) |
| CloudShare.Environments.VMs.username | string | Username |
| CloudShare.Environments.VMs.password | string | Password |
| CloudShare.Environments.VMs.consoleToken | string | Console token |

### cloudshare-get-env-multiple-resources

***
Retrieves all environments that were active in a specified time range, and their resource usage. Each environment record includes total run time, total RAM-GB Hours, max disk usage and the sponsored token that was used to create the environment, if applicable.

#### Base Command

`cloudshare-get-env-multiple-resources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscriptionId | Specifies a user subscription, where {subscriptionID} is the ID of the subscription. Provide the subscription if the user is a member of multiple subscriptions. | Optional |
| starttime | Specifies the start of the time range, where {starttime_value} is the start of the time range in the format ISO 8601. For example, "2017-01-01". | Required |
| endtime | Specifies the end of the time range, where {endtime_value} is the end of the time range in the format ISO 8601. For example, '2017-02-01'. | Required |
| skip | Optional. Specifies to skip the first {skip_value} records, where {skip_value} is an integer (default: 0). Can be used iteratively in conjunction with take to view distinct sets of environment records. | Optional |
| take | Optional. Limits the number of records returned, where {take_value} is the maximum number of records to return. Integer (default: 1000, maximum: 1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.EnvironmentResources.sponsoredLoginToken | string | Sponsored login token |
| CloudShare.EnvironmentResources.totalRuntimeHours | number | Total run time \(hours\) |
| CloudShare.EnvironmentResources.totalGbh | number | Total GB / hour |
| CloudShare.EnvironmentResources.maxDiskGb | number | Max disk\(GB\) |
| CloudShare.EnvironmentResources.lastUpdateTime | string | Last update time |
| CloudShare.EnvironmentResources.name | string | Name |
| CloudShare.EnvironmentResources.id | string | ID |

### cloudshare-extend-env

***
Extends the lifetime of an environment

#### Base Command

`cloudshare-extend-env`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envId | Specifies the environment, where {envId} is the environment's ID. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-postpone-env-suspend

***
Postpones an environment's suspended state  Request Path

#### Base Command

`cloudshare-postpone-env-suspend`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envId | Specifies the environment, where {envId} is the environment's ID. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-resume-env

***
Resumes an environment that was previously suspended, returning it to active running state

#### Base Command

`cloudshare-resume-env`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envId | Specifies the environment, where {envId} is the environment's ID. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-revert-env

***
Reverts an environment to a specified snapshot

#### Base Command

`cloudshare-revert-env`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envId | Specifies the environment, where {envId} is the environment's ID. | Required |
| snapshotId | Specifies the snapshot to which to revert the environment, where {snapshotId} is the snapshot's ID. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-suspend-env

***
Suspends an environment

#### Base Command

`cloudshare-suspend-env`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envId | Specifies the environment, where {envId} is the environment's ID. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-get-env

***
Retrieves properties of an environment and enables verification of the requesting user's permissions to the environment

#### Base Command

`cloudshare-get-env`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envID | The environment's ID. | Required |
| permission | Specifies a type of permission to access the environment. Returns an error (status code 500) if the requesting user does not have the specified permission level. Otherwise, returns the environment properties. Possible values are: view, edit, owner. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Environments.projectId | string | Project ID |
| CloudShare.Environments.policyId | string | Policy ID |
| CloudShare.Environments.description | string | Description |
| CloudShare.Environments.ownerEmail | string | Owner email |
| CloudShare.Environments.regionId | string | Region ID |
| CloudShare.Environments.name | string | Name |
| CloudShare.Environments.id | string | ID |
| CloudShare.Environments.status | string | Status |
| CloudShare.Environments.teamId | string | Team ID |

### cloudshare-delete-env

***
Deletes an environment

#### Base Command

`cloudshare-delete-env`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envID | The Id of the environment. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-create-env

***
Creates an environment from a snapshot or from one or more VM templates

#### Base Command

`cloudshare-create-env`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | Specifies details (JSON) of the environment to create. Please refer to https://docs.cloudshare.com/rest-api/v3/environments/envs/post-envs/ for the format. | Required |
| itemsCart | Specifies templates (JSON array) from which to build the environment. Please refer to https://docs.cloudshare.com/rest-api/v3/environments/envs/post-envs/ for the format. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Environments.resources.cpuCount | number | CPU count |
| CloudShare.Environments.resources.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Environments.resources.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Environments.VMs.name | string | Name |
| CloudShare.Environments.VMs.description | string | Description |
| CloudShare.Environments.VMs.osTypeName | string | OS type name |
| CloudShare.Environments.VMs.imageUrl | string | Image URL |
| CloudShare.Environments.VMs.resources.cpuCount | number | CPU count |
| CloudShare.Environments.VMs.resources.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Environments.VMs.resources.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Environments.VMs.domainName | string | Domain name |
| CloudShare.Environments.VMs.internalIPs | unknown | Internal IPs |
| CloudShare.Environments.VMs.macAddresses | unknown | MAC addresses |
| CloudShare.Environments.VMs.canAddMultipleInstances | boolean | Can add multiple instances |
| CloudShare.Environments.VMs.hostName | string | Hostname |
| CloudShare.Environments.VMs.vanityName | string | Vanity name |
| CloudShare.Environments.VMs.httpAccessEnabled | boolean | HTTP access enabled |
| CloudShare.Environments.VMs.startWithHttps | boolean | Start with HTTPS |
| CloudShare.Environments.VMs.user | string | User |
| CloudShare.Environments.VMs.password | string | Password |
| CloudShare.Environments.VMs.id | string | ID |
| CloudShare.Environments.environmentId | string | Environment ID |
| CloudShare.Environments.id | string | ID |

### cloudshare-modify-env

***
Adds one or more VMs to an existing environment

#### Base Command

`cloudshare-modify-env`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envId | The ID of the environment. | Required |
| itemsCart | Specifies templates (JSON array) of VMs to add to the environment. Please refer to https://docs.cloudshare.com/rest-api/v3/environments/envs/post-envs/ for the format. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Environments.resources.cpuCount | number | CPU count |
| CloudShare.Environments.resources.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Environments.resources.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Environments.VMs.name | string | Name |
| CloudShare.Environments.VMs.description | string | Description |
| CloudShare.Environments.VMs.osTypeName | string | OS type name |
| CloudShare.Environments.VMs.imageUrl | string | Image URL |
| CloudShare.Environments.VMs.resources.cpuCount | number | CPU count |
| CloudShare.Environments.VMs.resources.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Environments.VMs.resources.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Environments.VMs.domainName | string | Domain name |
| CloudShare.Environments.VMs.internalIPs | unknown | Internal IPs |
| CloudShare.Environments.VMs.macAddresses | unknown | MAC addresses |
| CloudShare.Environments.VMs.canAddMultipleInstances | boolean | Can add multiple instances |
| CloudShare.Environments.VMs.hostName | string | Hostname |
| CloudShare.Environments.VMs.vanityName | string | Vanity name |
| CloudShare.Environments.VMs.httpAccessEnabled | boolean | HTTP access enabled |
| CloudShare.Environments.VMs.startWithHttps | boolean | Start with HTTPS |
| CloudShare.Environments.VMs.user | string | User |
| CloudShare.Environments.VMs.password | string | Password |
| CloudShare.Environments.VMs.id | string | ID |
| CloudShare.Environments.environmentId | string | Environment ID |
| CloudShare.Environments.id | string | ID |

### cloudshare-delete-vm

***
Deletes a VM

#### Base Command

`cloudshare-delete-vm`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| VmID | The ID of the VM. | Optional |

#### Context Output

There is no context output for this command.

### cloudshare-check-vm-execution-status

***
Checks the status of a previously executed command line script

#### Base Command

`cloudshare-check-vm-execution-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vmID | The ID of the VM on which the script was executed. | Required |
| executionId | The ID returned by the execution request. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.VM.Executions.id | string | ID |
| CloudShare.VM.Executions.exitCode | number | Exit code |
| CloudShare.VM.Executions.success | boolean | Success |
| CloudShare.VM.Executions.standardOutput | string | Standard output |
| CloudShare.VM.Executions.standardError | string | Standard error |
| CloudShare.VM.Executions.executedPath | string | Executed path |

### cloudshare-get-vm-remote-access-file

***
Retrieves the content of a .rdp file that provides remote desktop access to the specified VM. An .rdp file comprising the returned content opens a remote desktop session to the VM from a Windows machine. It can also be used on Linux with FreeRDP or on Mac with Microsoft Remote Access.

#### Base Command

`cloudshare-get-vm-remote-access-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| VmID | The ID of the VM. | Optional |
| desktopHeight | The height resolution of the remote access session, in pixels. | Required |
| desktopWidth | The width resolution of the remote access session, in pixels. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.VM.Remote.VmID | string | VM ID |
| CloudShare.VM.Remote.rdpFileContent | string | RDP file content |
| CloudShare.VM.Remote.clearTextPassword | string | Clear text password |

### cloudshare-execute-vm-command

***
Executes a command line script on a VM

#### Base Command

`cloudshare-execute-vm-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vmId | The ID of the VM. | Required |
| path | Path in VM. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.VM.Execute.executionId | string | Execution ID |

### cloudshare-modify-vm-hardware

***
Adjusts a VM's CPU count, disk size, and RAM

#### Base Command

`cloudshare-modify-vm-hardware`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vmID | The ID of the VM. | Required |
| numCpus | Number of CPUs. | Required |
| memorySizeMBs | RAM size, in megabytes. | Required |
| diskSizeGBs | Disk size, in gigabytes. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.VM.Modify.vmID | string | VM ID |
| CloudShare.VM.Modify.conflictsFound | boolean | Conflicts found |
| CloudShare.VM.Modify.conflicts | string | Conflicts |

### cloudshare-reboot-vm

***
Reboots a VM

#### Base Command

`cloudshare-reboot-vm`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| VmID | The ID of the VM. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-revert-vm

***
Reverts a VM

#### Base Command

`cloudshare-revert-vm`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| VmID | The ID of the VM. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-get-cloud-folders

***
Retrieves the user's cloud folder and the user's projects' project folder(s)

#### Base Command

`cloudshare-get-cloud-folders`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Folders.host | string | Host |
| CloudShare.Folders.path | string | Path |
| CloudShare.Folders.userName | string | Username |
| CloudShare.Folders.password | string | Password |
| CloudShare.Folders.userFolder.name | string | Name |
| CloudShare.Folders.userFolder.quotaSizeGB | string | Quota size\(GB\) |
| CloudShare.Folders.userFolder.quotaSizeInUseGB | string | Quota size in use\(GB\) |
| CloudShare.Folders.userFolder.usagePercentage | string | Usage percentage |
| CloudShare.Folders.projectFolders.name | string | Name |
| CloudShare.Folders.projectFolders.quotaSizeGB | string | Quota size\(GB\) |
| CloudShare.Folders.projectFolders.quotaSizeInUseGB | string | Quota size in use\(GB\) |
| CloudShare.Folders.projectFolders.usagePercentage | string | Usage percentage |

### cloudshare-get-env-cloud-folders

***
Shows the cloud folder on all of the environment's machines

#### Base Command

`cloudshare-get-env-cloud-folders`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EnvId | The ID of the environment. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.EnvFolders.name | string | Name |
| CloudShare.EnvFolders.sanitizedName | string | Santized name |
| CloudShare.EnvFolders.windowsFolder | string | Windows folder |
| CloudShare.EnvFolders.linuxFolder | string | Linux folder |
| CloudShare.EnvFolders.token | string | Token |

### cloudshare-generate-cloud-folder-password

***
Generates a new FTP password for accessing the user's cloud folders.

#### Base Command

`cloudshare-generate-cloud-folder-password`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.FoldersPassword.newPassword | string | New password |
| CloudShare.FoldersPassword.newFtpUri | string | New FTP URI |

### cloudshare-unmount-env-folders

***
Hides the cloud folder on all of the environment's machines

#### Base Command

`cloudshare-unmount-env-folders`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EnvId | The ID of the environment. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-get-templates

***
Retrieves VM templates and blueprints

#### Base Command

`cloudshare-get-templates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| templateType | Filters the results by type of template. Possible values: 0 - Returns blueprints only. 1 - Returns VM templates only. Possible values are: 0, 1. | Optional |
| projectId | Filters the results to include only blueprints that belong to a specific project. | Optional |
| regionId | Filters the results to include only templates that belong to a specific region. | Optional |
| skip | Specifies to skip the first {skip} records, where {skip} is an integer. | Optional |
| take | Limits the number of records returned, where {take_value} is the maximum number of records to return. Integer (default: 1000, maximum: 1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Templates.name | string | Name |
| CloudShare.Templates.description | string | Description |
| CloudShare.Templates.isEnvironmentTemplate | boolean | Is environment template |
| CloudShare.Templates.type | number | Type |
| CloudShare.Templates.imageUrl | string | Image URL |
| CloudShare.Templates.regionId | string | Region ID |
| CloudShare.Templates.tags | unknown | Tags |
| CloudShare.Templates.categories | unknown | Categories |
| CloudShare.Templates.resources.cpuCount | number | CPU count |
| CloudShare.Templates.resources.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Templates.resources.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Templates.numberOfMachines | number | Number of mahcines |
| CloudShare.Templates.hasMultipleVersions | boolean | Has multiple versions |
| CloudShare.Templates.hasDefaultVersion | boolean | Has default version |
| CloudShare.Templates.disabledForRegularEnvironmentCreation | boolean | Disabled for regular environment creation |
| CloudShare.Templates.disabledForTrainingEnvironmentCreation | boolean | Disabled for training environment creation |
| CloudShare.Templates.canAddMultipleInstances | boolean | Can add multiple instances |
| CloudShare.Templates.envTemplateScope | unknown | Env template scopt |
| CloudShare.Templates.creationDate | string | Creation date |
| CloudShare.Templates.id | string | ID |

### cloudshare-get-snapshot

***
Retrieves details of a snapshot

#### Base Command

`cloudshare-get-snapshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| snapshotID | The ID of the snapshot. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Snapshots.authorName | string | Author name |
| CloudShare.Snapshots.comment | string | Comment |
| CloudShare.Snapshots.createTime | string | Create time |
| CloudShare.Snapshots.description | string | Description |
| CloudShare.Snapshots.id | string | ID |
| CloudShare.Snapshots.imageUrl | string | Image URL |
| CloudShare.Snapshots.isDefault | boolean | Is default |
| CloudShare.Snapshots.isLatest | boolean | Is latest |
| CloudShare.Snapshots.machines.canAddMultipleInstances | boolean | Can add multiple instances |
| CloudShare.Snapshots.machines.description | string | Description |
| CloudShare.Snapshots.machines.domainName | string | Domain name |
| CloudShare.Snapshots.machines.hostName | string | Hostname |
| CloudShare.Snapshots.machines.httpAccessEnabled | boolean | HTTP access enabled |
| CloudShare.Snapshots.machines.id | string | ID |
| CloudShare.Snapshots.machines.id | string | Image URL |
| CloudShare.Snapshots.machines.internalIPs | unknown | Internal IPs |
| CloudShare.Snapshots.machines.macAddresses | unknown | MAC addresses |
| CloudShare.Snapshots.machines.name | string | Name |
| CloudShare.Snapshots.machines.osTypeName | string | OS type name |
| CloudShare.Snapshots.machines.password | string | Password |
| CloudShare.Snapshots.machines.resources.cpuCount | number | CPU count |
| CloudShare.Snapshots.machines.resources.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Snapshots.machines.resources.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Snapshots.machines.startWithHttps | boolean | Start with HTTPS |
| CloudShare.Snapshots.machines.user | string | User |
| CloudShare.Snapshots.machines.vanityName | string | Vanity name |
| CloudShare.Snapshots.name | string | Name |
| CloudShare.Snapshots.number | number | Number |
| CloudShare.Snapshots.resources.cpuCount | number | CPU count |
| CloudShare.Snapshots.resources.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Snapshots.resources.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Snapshots.type | number | Type |
| CloudShare.Snapshots.regions | unknown | Regions |

### cloudshare-get-env-snapshots

***
Retrieves all snapshots contained in a specified environment's blueprint. A blueprint can contain up to five snapshots, with newer snapshots displacing the oldest snapshots in the blueprint.

#### Base Command

`cloudshare-get-env-snapshots`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envId | The ID of the environment. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Snapshots.authorName | string | Author name |
| CloudShare.Snapshots.comment | string | Comment |
| CloudShare.Snapshots.createTime | string | Create time |
| CloudShare.Snapshots.description | string | Description |
| CloudShare.Snapshots.id | string | ID |
| CloudShare.Snapshots.imageUrl | string | Image URL |
| CloudShare.Snapshots.isDefault | boolean | Is default |
| CloudShare.Snapshots.isLatest | boolean | Is latest |
| CloudShare.Snapshots.machines.canAddMultipleInstances | boolean | Can add multiple instances |
| CloudShare.Snapshots.machines.description | string | Description |
| CloudShare.Snapshots.machines.domainName | string | Domain name |
| CloudShare.Snapshots.machines.hostName | string | Hostname |
| CloudShare.Snapshots.machines.httpAccessEnabled | boolean | HTTP access enabled |
| CloudShare.Snapshots.machines.id | string | ID |
| CloudShare.Snapshots.machines.id | string | Image URL |
| CloudShare.Snapshots.machines.internalIPs | unknown | Internal IPs |
| CloudShare.Snapshots.machines.macAddresses | unknown | MAC addresses |
| CloudShare.Snapshots.machines.name | string | Name |
| CloudShare.Snapshots.machines.osTypeName | string | OS type name |
| CloudShare.Snapshots.machines.password | string | Password |
| CloudShare.Snapshots.machines.resources.cpuCount | number | CPU count |
| CloudShare.Snapshots.machines.resources.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Snapshots.machines.resources.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Snapshots.machines.startWithHttps | boolean | Start with HTTPS |
| CloudShare.Snapshots.machines.user | string | User |
| CloudShare.Snapshots.machines.vanityName | string | Vanity name |
| CloudShare.Snapshots.name | string | Name |
| CloudShare.Snapshots.number | number | Number |
| CloudShare.Snapshots.resources.cpuCount | number | CPU count |
| CloudShare.Snapshots.resources.diskSizeMB | number | Disk size\(MB\) |
| CloudShare.Snapshots.resources.memorySizeMB | number | Memory size\(MB\) |
| CloudShare.Snapshots.type | number | Type |
| CloudShare.Snapshots.regions | unknown | Regions |

### cloudshare-mark-default-snapshot

***
Marks a specified snapshot as the default snapshot in its containing blueprint.  New environments created from a blueprint are based on the default snapshot in the blueprint. This request enables you to change which snapshot is the default snapshot in a given blueprint so that new environments will be based on the snapshot of your choice.

#### Base Command

`cloudshare-mark-default-snapshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| snapshotID | The ID of the snapshot that you want to mark as default. | Required |

#### Context Output

There is no context output for this command.

### cloudshare-take-snapshot-env

***
Takes a snapshot of an environment

#### Base Command

`cloudshare-take-snapshot-env`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| envId | The ID of the environment of which to take the snapshot. | Required |
| name | A name for the new snapshot. Should not exceed 32 characters. | Required |
| description | A description for the new snapshot. | Optional |
| newBlueprintName | A name to assign to a new blueprint. If specified, the snapshot is created in a new blueprint with the specified name, rather than in the default environment blueprint. Must be null if there is not yet at least one snapshot in the default environment blueprint. If specified, otherBlueprintId must be null. If both newBlueprintName and otherBlueprintId are null, the snapshot is created in the default environment blueprint. | Optional |
| otherBlueprintId | The ID of an existing blueprint. If specified, the snapshot is created in the specified blueprint rather than in the default environment blueprint. Must be null if there is not yet at least one snapshot in the default environment blueprint. If specified, newBlueprintName must be null. If both newBlueprintName and otherBlueprintId are null, the snapshot is created in the default environment blueprint. | Optional |
| setAsDefault | Defaults to true. If true, the new snapshot is marked as the default snapshot in the containing blueprint. Possible values are: true, false. Default is true. | Optional |

#### Context Output

There is no context output for this command.

### cloudshare-get-teams

***
Retrieves all available teams in all available projects

#### Base Command

`cloudshare-get-teams`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Teams.Name | string | Name |
| CloudShare.Teams.Id | string | ID |

### cloudshare-invite-user-poc

***
Invite an end user to a POC, based on a specified blueprint, and assigns a specific project member user to be the owning project member for the end user.  A policy ID, blueprint ID and owning project member ID must be specified.

#### Base Command

`cloudshare-invite-user-poc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyId | The ID of the environment policy to assign to the environment created for the end user as part of the POC. The policy will govern the life cycle of the end user's environment. | Optional |
| blueprintId | The ID of the blueprint based on which the end user's environment will be created (this is the POC's blueprint). | Required |
| OwningProjectMemberId | The ID of the project member user to whom the end user will be assigned. | Required |
| opportunity | The name of the business opportunity to be associated with the end user. | Required |
| validForDays | The number of days to keep the invitation valid for. | Required |
| email | The recipient's email. The invitation will be sent to the specified email. | Required |
| firstName | The recipient's first name. | Required |
| LastName | The recipient's last name. | Required |
| regionId | The region in which to create the POC's environment. | Optional |
| InviteeCanSetEmail | Indicates whether an end user can set email when accepting the invitation. Default is true. Possible values are: true, false. Default is true. | Optional |
| customEmailSubject | The subject of the email. The invitation will be sent with the specified custom email subject. This value will override the custom email subject in the UI. | Optional |
| customEmailBody | The body of the email. The invitation will be sent with the specified custom email body. This value will override the custom email body in the UI. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.Invites.invitationDetailsUrl | string | Invitation details URL |
| CloudShare.Invites.acceptInvitationUrl | string | Accept invitation URL |
| CloudShare.Invites.message | string | Message |

### cloudshare-get-poc-invitations

***
Retrieves POC invitations sent.

#### Base Command

`cloudshare-get-poc-invitations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Retrieve invites from a particular time (Example: "last 7 days"). | Optional |
| sentBy | Filter based on who sent the invite (default is anyone). | Optional |
| skip | Specifies to skip the first {skip} records, where {skip} is an integer (default: 0). Can be used iteratively in conjunction with take to view distinct sets of template records. | Optional |
| sortBy | The filed to sort by. | Optional |
| statusCategory | The status categoey to filter by. | Optional |
| take | Limits the number of records returned, where {take} is the maximum number of records to return. Integer (default: 1000, maximum: 1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudShare.POCInvites.blueprintShortId | string | Blueprint short ID |
| CloudShare.POCInvites.projectName | string | Project name |
| CloudShare.POCInvites.createdOn | string | Created on |
| CloudShare.POCInvites.owningSe | string | Owning SE |
| CloudShare.POCInvites.environmentId | string | Environment ID |
| CloudShare.POCInvites.pocUser | string | POC user |
| CloudShare.POCInvites.startDate | string | Start date |
| CloudShare.POCInvites.status | number | Status |
| CloudShare.POCInvites.opportunity | string | Opportunity |
| CloudShare.POCInvites.owningSeUserId | string | Owning SE user ID |
| CloudShare.POCInvites.projectId | string | Project ID |
| CloudShare.POCInvites.randomToken | string | Random token |
| CloudShare.POCInvites.id | string | ID |
| CloudShare.POCInvites.expirationDate | string | Expiration date |
| CloudShare.POCInvites.blueprintName | string | Blueprint name |
