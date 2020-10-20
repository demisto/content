List all of the events discovered within your enterprise on a particular device within 2 hours earlier than the current time.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | enhancement |
| Demisto Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* gcb-list-events

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| asset_identifier | Host Name, IP Address or MAC Address of the asset. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GoogleChronicleBackstory.Events.eventType | Specifies the type of the event. | String |
| GoogleChronicleBackstory.Events.eventTimestamp | The GMT timestamp when the event was generated. | Date |
| GoogleChronicleBackstory.Events.collectedTimestamp | The GMT timestamp when the event was collected by the vendor's local collection infrastructure. | Date |
| GoogleChronicleBackstory.Events.description | Human\-readable description of the event. | String |
| GoogleChronicleBackstory.Events.productEventType | Short, descriptive, human\-readable, and product\-specific event name or type. | String |
| GoogleChronicleBackstory.Events.productLogId | A vendor\-specific event identifier to uniquely identify the event \(a GUID\). Users might use this identifier to search the vendor's proprietary console for the event in question. | String |
| GoogleChronicleBackstory.Events.productName | Specifies the name of the product. | String |
| GoogleChronicleBackstory.Events.productVersion | Specifies the version of the product. | String |
| GoogleChronicleBackstory.Events.urlBackToProduct | URL linking to a relevant website where you can view more information about this specific event or the general event category. | String |
| GoogleChronicleBackstory.Events.vendorName | Specifies the product vendor's name. | String |
| GoogleChronicleBackstory.Events.principal.assetId | Vendor\-specific unique device identifier. | String |
| GoogleChronicleBackstory.Events.principal.email | Email address. | String |
| GoogleChronicleBackstory.Events.principal.hostname | Client hostname or domain name field. | String |
| GoogleChronicleBackstory.Events.principal.platform | Platform operating system. | String |
| GoogleChronicleBackstory.Events.principal.platformPatchLevel | Platform operating system patch level. | String |
| GoogleChronicleBackstory.Events.principal.platformVersion | Platform operating system version. | String |
| GoogleChronicleBackstory.Events.principal.ip | IP address associated with a network connection. | String |
| GoogleChronicleBackstory.Events.principal.port | Source or destination network port number when a specific network connection is described within an event. | String |
| GoogleChronicleBackstory.Events.principal.mac | MAC addresses associated with a device. | String |
| GoogleChronicleBackstory.Events.principal.administrativeDomain | Domain which the device belongs to \(for example, the Windows domain\). | String |
| GoogleChronicleBackstory.Events.principal.url | Standard URL. | String |
| GoogleChronicleBackstory.Events.principal.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.principal.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.principal.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.principal.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.principal.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.principal.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.principal.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.principal.process.commandLine | Stores the command line string for the process. | String |
| GoogleChronicleBackstory.Events.principal.process.productSpecificProcessId | Stores the product specific process ID. | String |
| GoogleChronicleBackstory.Events.principal.process.productSpecificParentProcessId | Stores the product specific process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.principal.process.file | Stores the file name of the file in use by the process. | String |
| GoogleChronicleBackstory.Events.principal.process.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.principal.process.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.principal.process.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.principal.process.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.principal.process.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.principal.process.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.principal.process.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.principal.process.parentPid | Stores the process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.principal.process.pid | Stores the process ID. | String |
| GoogleChronicleBackstory.Events.principal.registry.registryKey | Stores the registry key associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.principal.registry.registryValueName | Stores the name of the registry value associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.principal.registry.registryValueData | Stores the data associated with a registry value. | String |
| GoogleChronicleBackstory.Events.principal.user.emailAddresses | Stores the email addresses for the user. | String |
| GoogleChronicleBackstory.Events.principal.user.employeeId | Stores the human resources employee ID for the user. | String |
| GoogleChronicleBackstory.Events.principal.user.firstName | Stores the first name for the user. | String |
| GoogleChronicleBackstory.Events.principal.user.middleName | Stores the middle name for the user. | String |
| GoogleChronicleBackstory.Events.principal.user.lastName | Stores the last name for the user. | String |
| GoogleChronicleBackstory.Events.principal.user.groupid | Stores the group ID associated with a user. | String |
| GoogleChronicleBackstory.Events.principal.user.phoneNumbers | Stores the phone numbers for the user. | String |
| GoogleChronicleBackstory.Events.principal.user.title | Stores the job title for the user. | String |
| GoogleChronicleBackstory.Events.principal.user.userDisplayName | Stores the display name for the user. | String |
| GoogleChronicleBackstory.Events.principal.user.userid | Stores the user ID. | String |
| GoogleChronicleBackstory.Events.principal.user.windowsSid | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | String |
| GoogleChronicleBackstory.Events.target.assetId | Vendor\-specific unique device identifier. | String |
| GoogleChronicleBackstory.Events.target.email | Email address. | String |
| GoogleChronicleBackstory.Events.target.hostname | Client hostname or domain name field. | String |
| GoogleChronicleBackstory.Events.target.platform | Platform operating system. | String |
| GoogleChronicleBackstory.Events.target.platformPatchLevel | Platform operating system patch level. | String |
| GoogleChronicleBackstory.Events.target.platformVersion | Platform operating system version. | String |
| GoogleChronicleBackstory.Events.target.ip | IP address associated with a network connection. | String |
| GoogleChronicleBackstory.Events.target.port | Source or destination network port number when a specific network connection is described within an event. | String |
| GoogleChronicleBackstory.Events.target.mac | One or more MAC addresses associated with a device. | String |
| GoogleChronicleBackstory.Events.target.administrativeDomain | Domain which the device belongs to \(for example, the Windows domain\). | String |
| GoogleChronicleBackstory.Events.target.url | Standard URL. | String |
| GoogleChronicleBackstory.Events.target.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.target.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.target.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.target.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.target.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.target.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.target.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.target.process.commandLine | Stores the command line string for the process. | String |
| GoogleChronicleBackstory.Events.target.process.productSpecificProcessId | Stores the product specific process ID. | String |
| GoogleChronicleBackstory.Events.target.process.productSpecificParentProcessId | Stores the product specific process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.target.process.file | Stores the file name of the file in use by the process. | String |
| GoogleChronicleBackstory.Events.target.process.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.target.process.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.target.process.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.target.process.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.target.process.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.target.process.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.target.process.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.target.process.parentPid | Stores the process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.target.process.pid | Stores the process ID. | String |
| GoogleChronicleBackstory.Events.target.registry.registryKey | Stores the registry key associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.target.registry.registryValueName | Stores the name of the registry value associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.target.registry.registryValueData | Stores the data associated with a registry value. | String |
| GoogleChronicleBackstory.Events.target.user.emailAddresses | Stores the email addresses for the user. | String |
| GoogleChronicleBackstory.Events.target.user.employeeId | Stores the human resources employee ID for the user. | String |
| GoogleChronicleBackstory.Events.target.user.firstName | Stores the first name for the user. | String |
| GoogleChronicleBackstory.Events.target.user.middleName | Stores the middle name for the user. | String |
| GoogleChronicleBackstory.Events.target.user.lastName | Stores the last name for the user. | String |
| GoogleChronicleBackstory.Events.target.user.groupid | Stores the group ID associated with a user. | String |
| GoogleChronicleBackstory.Events.target.user.phoneNumbers | Stores the phone numbers for the user. | String |
| GoogleChronicleBackstory.Events.target.user.title | Stores the job title for the user. | String |
| GoogleChronicleBackstory.Events.target.user.userDisplayName | Stores the display name for the user. | String |
| GoogleChronicleBackstory.Events.target.user.userid | Stores the user ID. | String |
| GoogleChronicleBackstory.Events.target.user.windowsSid | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | String |
| GoogleChronicleBackstory.Events.intermediary.assetId | Vendor\-specific unique device identifier. | String |
| GoogleChronicleBackstory.Events.intermediary.email | Email address. | String |
| GoogleChronicleBackstory.Events.intermediary.hostname | Client hostname or domain name field. | String |
| GoogleChronicleBackstory.Events.intermediary.platform | Platform operating system. | String |
| GoogleChronicleBackstory.Events.intermediary.platformPatchLevel | Platform operating system patch level. | String |
| GoogleChronicleBackstory.Events.intermediary.platformVersion | Platform operating system version. | String |
| GoogleChronicleBackstory.Events.intermediary.ip | IP address associated with a network connection. | String |
| GoogleChronicleBackstory.Events.intermediary.port | Source or destination network port number when a specific network connection is described within an event. | String |
| GoogleChronicleBackstory.Events.intermediary.mac | One or more MAC addresses associated with a device. | String |
| GoogleChronicleBackstory.Events.intermediary.administrativeDomain | Domain which the device belongs to \(for example, the Windows domain\). | String |
| GoogleChronicleBackstory.Events.intermediary.url | Standard URL. | String |
| GoogleChronicleBackstory.Events.intermediary.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.intermediary.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.intermediary.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.intermediary.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.intermediary.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.intermediary.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.intermediary.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.intermediary.process.commandLine | Stores the command line string for the process. | String |
| GoogleChronicleBackstory.Events.intermediary.process.productSpecificProcessId | Stores the product specific process ID. | String |
| GoogleChronicleBackstory.Events.intermediary.process.productSpecificParentProcessId | Stores the product specific process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.intermediary.process.file | Stores the file name of the file in use by the process. | String |
| GoogleChronicleBackstory.Events.intermediary.process.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.intermediary.process.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.intermediary.process.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.intermediary.process.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.intermediary.process.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.intermediary.process.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.intermediary.process.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.intermediary.process.parentPid | Stores the process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.intermediary.process.pid | Stores the process ID. | String |
| GoogleChronicleBackstory.Events.intermediary.registry.registryKey | Stores the registry key associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.intermediary.registry.registryValueName | Stores the name of the registry value associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.intermediary.registry.registryValueData | Stores the data associated with a registry value. | String |
| GoogleChronicleBackstory.Events.intermediary.user.emailAddresses | Stores the email addresses for the user. | String |
| GoogleChronicleBackstory.Events.intermediary.user.employeeId | Stores the human resources employee ID for the user. | String |
| GoogleChronicleBackstory.Events.intermediary.user.firstName | Stores the first name for the user. | String |
| GoogleChronicleBackstory.Events.intermediary.user.middleName | Stores the middle name for the user. | String |
| GoogleChronicleBackstory.Events.intermediary.user.lastName | Stores the last name for the user. | String |
| GoogleChronicleBackstory.Events.intermediary.user.groupid | Stores the group ID associated with a user. | String |
| GoogleChronicleBackstory.Events.intermediary.user.phoneNumbers | Stores the phone numbers for the user. | String |
| GoogleChronicleBackstory.Events.intermediary.user.title | Stores the job title for the user. | String |
| GoogleChronicleBackstory.Events.intermediary.user.userDisplayName | Stores the display name for the user. | String |
| GoogleChronicleBackstory.Events.intermediary.user.userid | Stores the user ID. | String |
| GoogleChronicleBackstory.Events.intermediary.user.windowsSid | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | String |
| GoogleChronicleBackstory.Events.src.assetId | Vendor\-specific unique device identifier. | String |
| GoogleChronicleBackstory.Events.src.email | Email address. | String |
| GoogleChronicleBackstory.Events.src.hostname | Client hostname or domain name field. | String |
| GoogleChronicleBackstory.Events.src.platform | Platform operating system. | String |
| GoogleChronicleBackstory.Events.src.platformPatchLevel | Platform operating system patch level. | String |
| GoogleChronicleBackstory.Events.src.platformVersion | Platform operating system version. | String |
| GoogleChronicleBackstory.Events.src.ip | IP address associated with a network connection. | String |
| GoogleChronicleBackstory.Events.src.port | Source or destination network port number when a specific network connection is described within an event. | String |
| GoogleChronicleBackstory.Events.src.mac | One or more MAC addresses associated with a device. | String |
| GoogleChronicleBackstory.Events.src.administrativeDomain | Domain which the device belongs to \(for example, the Windows domain\). | String |
| GoogleChronicleBackstory.Events.src.url | Standard URL. | String |
| GoogleChronicleBackstory.Events.src.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.src.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.src.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.src.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.src.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.src.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.src.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.src.process.commandLine | Stores the command line string for the process. | String |
| GoogleChronicleBackstory.Events.src.process.productSpecificProcessId | Stores the product specific process ID. | String |
| GoogleChronicleBackstory.Events.src.process.productSpecificParentProcessId | Stores the product specific process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.src.process.file | Stores the file name of the file in use by the process. | String |
| GoogleChronicleBackstory.Events.src.process.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.src.process.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.src.process.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.src.process.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.src.process.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.src.process.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.src.process.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.src.process.parentPid | Stores the process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.src.process.pid | Stores the process ID. | String |
| GoogleChronicleBackstory.Events.src.registry.registryKey | Stores the registry key associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.src.registry.registryValueName | Stores the name of the registry value associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.src.registry.registryValueData | Stores the data associated with a registry value. | String |
| GoogleChronicleBackstory.Events.src.user.emailAddresses | Stores the email addresses for the user. | String |
| GoogleChronicleBackstory.Events.src.user.employeeId | Stores the human resources employee ID for the user. | String |
| GoogleChronicleBackstory.Events.src.user.firstName | Stores the first name for the user. | String |
| GoogleChronicleBackstory.Events.src.user.middleName | Stores the middle name for the user. | String |
| GoogleChronicleBackstory.Events.src.user.lastName | Stores the last name for the user. | String |
| GoogleChronicleBackstory.Events.src.user.groupid | Stores the group ID associated with a user. | String |
| GoogleChronicleBackstory.Events.src.user.phoneNumbers | Stores the phone numbers for the user. | String |
| GoogleChronicleBackstory.Events.src.user.title | Stores the job title for the user. | String |
| GoogleChronicleBackstory.Events.src.user.userDisplayName | Stores the display name for the user. | String |
| GoogleChronicleBackstory.Events.src.user.userid | Stores the user ID. | String |
| GoogleChronicleBackstory.Events.src.user.windowsSid | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | String |
| GoogleChronicleBackstory.Events.observer.assetId | Vendor\-specific unique device identifier. | String |
| GoogleChronicleBackstory.Events.observer.email | Email address. | String |
| GoogleChronicleBackstory.Events.observer.hostname | Client hostname or domain name field. | String |
| GoogleChronicleBackstory.Events.observer.platform | Platform operating system. | String |
| GoogleChronicleBackstory.Events.observer.platformPatchLevel | Platform operating system patch level. | String |
| GoogleChronicleBackstory.Events.observer.platformVersion | Platform operating system version. | String |
| GoogleChronicleBackstory.Events.observer.ip | IP address associated with a network connection. | String |
| GoogleChronicleBackstory.Events.observer.port | Source or destination network port number when a specific network connection is described within an event. | String |
| GoogleChronicleBackstory.Events.observer.mac | One or more MAC addresses associated with a device. | String |
| GoogleChronicleBackstory.Events.observer.administrativeDomain | Domain which the device belongs to \(for example, the Windows domain\). | String |
| GoogleChronicleBackstory.Events.observer.url | Standard URL. | String |
| GoogleChronicleBackstory.Events.observer.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.observer.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.observer.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.observer.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.observer.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.observer.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.observer.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.observer.process.commandLine | Stores the command line string for the process. | String |
| GoogleChronicleBackstory.Events.observer.process.productSpecificProcessId | Stores the product specific process ID. | String |
| GoogleChronicleBackstory.Events.observer.process.productSpecificParentProcessId | Stores the product specific process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.observer.process.file | Stores the file name of the file in use by the process. | String |
| GoogleChronicleBackstory.Events.observer.process.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.observer.process.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.observer.process.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.observer.process.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.observer.process.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.observer.process.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.observer.process.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.observer.process.parentPid | Stores the process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.observer.process.pid | Stores the process ID. | String |
| GoogleChronicleBackstory.Events.observer.registry.registryKey | Stores the registry key associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.observer.registry.registryValueName | Stores the name of the registry value associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.observer.registry.registryValueData | Stores the data associated with a registry value. | String |
| GoogleChronicleBackstory.Events.observer.user.emailAddresses | Stores the email addresses for the user. | String |
| GoogleChronicleBackstory.Events.observer.user.employeeId | Stores the human resources employee ID for the user. | String |
| GoogleChronicleBackstory.Events.observer.user.firstName | Stores the first name for the user. | String |
| GoogleChronicleBackstory.Events.observer.user.middleName | Stores the middle name for the user. | String |
| GoogleChronicleBackstory.Events.observer.user.lastName | Stores the last name for the user. | String |
| GoogleChronicleBackstory.Events.observer.user.groupid | Stores the group ID associated with a user. | String |
| GoogleChronicleBackstory.Events.observer.user.phoneNumbers | Stores the phone numbers for the user. | String |
| GoogleChronicleBackstory.Events.observer.user.title | Stores the job title for the user. | String |
| GoogleChronicleBackstory.Events.observer.user.userDisplayName | Stores the display name for the user. | String |
| GoogleChronicleBackstory.Events.observer.user.userid | Stores the user ID. | String |
| GoogleChronicleBackstory.Events.observer.user.windowsSid | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | String |
| GoogleChronicleBackstory.Events.about.assetId | Vendor\-specific unique device identifier. | String |
| GoogleChronicleBackstory.Events.about.email | Email address. | String |
| GoogleChronicleBackstory.Events.about.hostname | Client hostname or domain name field. | String |
| GoogleChronicleBackstory.Events.about.platform | Platform operating system. | String |
| GoogleChronicleBackstory.Events.about.platformPatchLevel | Platform operating system patch level. | String |
| GoogleChronicleBackstory.Events.about.platformVersion | Platform operating system version. | String |
| GoogleChronicleBackstory.Events.about.ip | IP address associated with a network connection. | String |
| GoogleChronicleBackstory.Events.about.port | Source or destination network port number when a specific network connection is described within an event. | String |
| GoogleChronicleBackstory.Events.about.mac | One or more MAC addresses associated with a device. | String |
| GoogleChronicleBackstory.Events.about.administrativeDomain | Domain which the device belongs to \(for example, the Windows domain\). | String |
| GoogleChronicleBackstory.Events.about.url | Standard URL. | String |
| GoogleChronicleBackstory.Events.about.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.about.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.about.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.about.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.about.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.about.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.about.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.about.process.commandLine | Stores the command line string for the process. | String |
| GoogleChronicleBackstory.Events.about.process.productSpecificProcessId | Stores the product specific process ID. | String |
| GoogleChronicleBackstory.Events.about.process.productSpecificParentProcessId | Stores the product specific process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.about.process.file | Stores the file name of the file in use by the process. | String |
| GoogleChronicleBackstory.Events.about.process.file.fileMetadata | Metadata associated with the file. | String |
| GoogleChronicleBackstory.Events.about.process.file.fullPath | Full path identifying the location of the file on the system. | String |
| GoogleChronicleBackstory.Events.about.process.file.md5 | MD5 hash value of the file. | String |
| GoogleChronicleBackstory.Events.about.process.file.mimeType | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | String |
| GoogleChronicleBackstory.Events.about.process.file.sha1 | SHA\-1 hash value of the file. | String |
| GoogleChronicleBackstory.Events.about.process.file.sha256 | SHA\-256 hash value of the file. | String |
| GoogleChronicleBackstory.Events.about.process.file.size | Size of the file. | String |
| GoogleChronicleBackstory.Events.about.process.parentPid | Stores the process ID for the parent process. | String |
| GoogleChronicleBackstory.Events.about.process.pid | Stores the process ID. | String |
| GoogleChronicleBackstory.Events.about.registry.registryKey | Stores the registry key associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.about.registry.registryValueName | Stores the name of the registry value associated with an application or system component. | String |
| GoogleChronicleBackstory.Events.about.registry.registryValueData | Stores the data associated with a registry value. | String |
| GoogleChronicleBackstory.Events.about.user.emailAddresses | Stores the email addresses for the user. | String |
| GoogleChronicleBackstory.Events.about.user.employeeId | Stores the human resources employee ID for the user. | String |
| GoogleChronicleBackstory.Events.about.user.firstName | Stores the first name for the user. | String |
| GoogleChronicleBackstory.Events.about.user.middleName | Stores the middle name for the user. | String |
| GoogleChronicleBackstory.Events.about.user.lastName | Stores the last name for the user. | String |
| GoogleChronicleBackstory.Events.about.user.groupid | Stores the group ID associated with a user. | String |
| GoogleChronicleBackstory.Events.about.user.phoneNumbers | Stores the phone numbers for the user. | String |
| GoogleChronicleBackstory.Events.about.user.title | Stores the job title for the user. | String |
| GoogleChronicleBackstory.Events.about.user.userDisplayName | Stores the display name for the user. | String |
| GoogleChronicleBackstory.Events.about.user.userid | Stores the user ID. | String |
| GoogleChronicleBackstory.Events.about.user.windowsSid | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | String |
| GoogleChronicleBackstory.Events.network.applicationProtocol | Indicates the network application protocol. | String |
| GoogleChronicleBackstory.Events.network.direction | Indicates the direction of network traffic. | String |
| GoogleChronicleBackstory.Events.network.email | Specifies the email address for the sender/recipient. | String |
| GoogleChronicleBackstory.Events.network.ipProtocol | Indicates the IP protocol. | String |
| GoogleChronicleBackstory.Events.network.receivedBytes | Specifies the number of bytes received. | String |
| GoogleChronicleBackstory.Events.network.sentBytes | Specifies the number of bytes sent. | String |
| GoogleChronicleBackstory.Events.network.dhcp.clientHostname | Hostname for the client. | String |
| GoogleChronicleBackstory.Events.network.dhcp.clientIdentifier | Client identifier. | String |
| GoogleChronicleBackstory.Events.network.dhcp.file | Filename for the boot image. | String |
| GoogleChronicleBackstory.Events.network.dhcp.flags | Value for the DHCP flags field. | String |
| GoogleChronicleBackstory.Events.network.dhcp.hlen | Hardware address length. | String |
| GoogleChronicleBackstory.Events.network.dhcp.hops | DHCP hop count. | String |
| GoogleChronicleBackstory.Events.network.dhcp.htype | Hardware address type. | String |
| GoogleChronicleBackstory.Events.network.dhcp.leaseTimeSeconds | Client\-requested lease time for an IP address in seconds. | String |
| GoogleChronicleBackstory.Events.network.dhcp.opcode | BOOTP op code. | String |
| GoogleChronicleBackstory.Events.network.dhcp.requestedAddress | Client identifier. | String |
| GoogleChronicleBackstory.Events.network.dhcp.seconds | Seconds elapsed since the client began the address acquisition/renewal process. | String |
| GoogleChronicleBackstory.Events.network.dhcp.sname | Name of the server which the client has requested to boot from. | String |
| GoogleChronicleBackstory.Events.network.dhcp.transactionId | Client transaction ID. | String |
| GoogleChronicleBackstory.Events.network.dhcp.type | DHCP message type. | String |
| GoogleChronicleBackstory.Events.network.dhcp.chaddr | IP address for the client hardware. | String |
| GoogleChronicleBackstory.Events.network.dhcp.ciaddr | IP address for the client. | String |
| GoogleChronicleBackstory.Events.network.dhcp.giaddr | IP address for the relay agent. | String |
| GoogleChronicleBackstory.Events.network.dhcp.siaddr | IP address for the next bootstrap server. | String |
| GoogleChronicleBackstory.Events.network.dhcp.yiaddr | Your IP address. | String |
| GoogleChronicleBackstory.Events.network.dns.authoritative | Set to true for authoritative DNS servers. | String |
| GoogleChronicleBackstory.Events.network.dns.id | Stores the DNS query identifier. | String |
| GoogleChronicleBackstory.Events.network.dns.response | Set to true if the event is a DNS response. | String |
| GoogleChronicleBackstory.Events.network.dns.opcode | Stores the DNS OpCode used to specify the type of DNS query \(standard, inverse, server status, etc.\). | String |
| GoogleChronicleBackstory.Events.network.dns.recursionAvailable | Set to true if a recursive DNS lookup is available. | String |
| GoogleChronicleBackstory.Events.network.dns.recursionDesired | Set to true if a recursive DNS lookup is requested. | String |
| GoogleChronicleBackstory.Events.network.dns.responseCode | Stores the DNS response code as defined by RFC 1035, Domain Names \- Implementation and Specification. | String |
| GoogleChronicleBackstory.Events.network.dns.truncated | Set to true if this is a truncated DNS response. | String |
| GoogleChronicleBackstory.Events.network.dns.questions.name | Stores the domain name. | String |
| GoogleChronicleBackstory.Events.network.dns.questions.class | Stores the code specifying the class of the query. | String |
| GoogleChronicleBackstory.Events.network.dns.questions.type | Stores the code specifying the type of the query. | String |
| GoogleChronicleBackstory.Events.network.dns.answers.binaryData | Stores the raw bytes of any non\-UTF8 strings that might be included as part of a DNS response. | String |
| GoogleChronicleBackstory.Events.network.dns.answers.class | Stores the code specifying the class of the resource record. | String |
| GoogleChronicleBackstory.Events.network.dns.answers.data | Stores the payload or response to the DNS question for all responses encoded in UTF\-8 format. | String |
| GoogleChronicleBackstory.Events.network.dns.answers.name | Stores the name of the owner of the resource record. | String |
| GoogleChronicleBackstory.Events.network.dns.answers.ttl | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | String |
| GoogleChronicleBackstory.Events.network.dns.answers.type | Stores the code specifying the type of the resource record. | String |
| GoogleChronicleBackstory.Events.network.dns.authority.binaryData | Stores the raw bytes of any non\-UTF8 strings that might be included as part of a DNS response. | String |
| GoogleChronicleBackstory.Events.network.dns.authority.class | Stores the code specifying the class of the resource record. | String |
| GoogleChronicleBackstory.Events.network.dns.authority.data | Stores the payload or response to the DNS question for all responses encoded in UTF\-8 format. | String |
| GoogleChronicleBackstory.Events.network.dns.authority.name | Stores the name of the owner of the resource record. | String |
| GoogleChronicleBackstory.Events.network.dns.authority.ttl | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | String |
| GoogleChronicleBackstory.Events.network.dns.authority.type | Stores the code specifying the type of the resource record. | String |
| GoogleChronicleBackstory.Events.network.dns.additional.binaryData | Stores the raw bytes of any non\-UTF8 strings that might be included as part of a DNS response. | String |
| GoogleChronicleBackstory.Events.network.dns.additional.class | Stores the code specifying the class of the resource record. | String |
| GoogleChronicleBackstory.Events.network.dns.additional.data | Stores the payload or response to the DNS question for all responses encoded in UTF\-8 format. | String |
| GoogleChronicleBackstory.Events.network.dns.additional.name | Stores the name of the owner of the resource record. | String |
| GoogleChronicleBackstory.Events.network.dns.additional.ttl | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | String |
| GoogleChronicleBackstory.Events.network.dns.additional.type | Stores the code specifying the type of the resource record. | String |
| GoogleChronicleBackstory.Events.network.email.from | Stores the from email address. | String |
| GoogleChronicleBackstory.Events.network.email.replyTo | Stores the reply\_to email address. | String |
| GoogleChronicleBackstory.Events.network.email.to | Stores the to email addresses. | String |
| GoogleChronicleBackstory.Events.network.email.cc | Stores the cc email addresses. | String |
| GoogleChronicleBackstory.Events.network.email.bcc | Stores the bcc email addresses. | String |
| GoogleChronicleBackstory.Events.network.email.mailId | Stores the mail \(or message\) ID. | String |
| GoogleChronicleBackstory.Events.network.email.subject | Stores the email subject line. | String |
| GoogleChronicleBackstory.Events.network.ftp.command | Stores the FTP command. | String |
| GoogleChronicleBackstory.Events.network.http.method | Stores the HTTP request method. | String |
| GoogleChronicleBackstory.Events.network.http.referralUrl | Stores the URL for the HTTP referer. | String |
| GoogleChronicleBackstory.Events.network.http.responseCode | Stores the HTTP response status code, which indicates whether a specific HTTP request has been successfully completed. | String |
| GoogleChronicleBackstory.Events.network.http.useragent | Stores the User\-Agent request header which includes the application type, operating system, software vendor or software version of the requesting software user agent. | String |
| GoogleChronicleBackstory.Events.authentication.authType | Type of system an authentication event is associated with \(Chronicle UDM\). | String |
| GoogleChronicleBackstory.Events.authentication.mechanism | Mechanism\(s\) used for authentication. | String |
| GoogleChronicleBackstory.Events.securityResult.about | Provide a description of the security result. | String |
| GoogleChronicleBackstory.Events.securityResult.action | Specify a security action. | String |
| GoogleChronicleBackstory.Events.securityResult.category | Specify a security category. | String |
| GoogleChronicleBackstory.Events.securityResult.confidence | Specify a confidence with regards to a security event as estimated by the product. | String |
| GoogleChronicleBackstory.Events.securityResult.confidenceDetails | Additional detail with regards to the confidence of a security event as estimated by the product vendor. | String |
| GoogleChronicleBackstory.Events.securityResult.priority | Specify a priority with regards to a security event as estimated by the product vendor. | String |
| GoogleChronicleBackstory.Events.securityResult.priorityDetails | Vendor\-specific information about the security result priority. | String |
| GoogleChronicleBackstory.Events.securityResult.ruleId | Identifier for the security rule. | String |
| GoogleChronicleBackstory.Events.securityResult.ruleName | Name of the security rule. | String |
| GoogleChronicleBackstory.Events.securityResult.severity | Severity of a security event as estimated by the product vendor using values defined by the Chronicle UDM. | String |
| GoogleChronicleBackstory.Events.securityResult.severityDetails | Severity for a security event as estimated by the product vendor. | String |
| GoogleChronicleBackstory.Events.securityResult.threatName | Name of the security threat. | String |
| GoogleChronicleBackstory.Events.securityResult.urlBackToProduct | URL to direct you to the source product console for this security event. | String |

There are no outputs for this script.

## Script Example
```!ListDeviceEvents asset_identifier="ray-xxx-laptop"```

##### Context Example
```
{
    "GoogleChronicleBackstory.Events": [
        {
            "principal": {
                "ip": [
                    "10.0.XX.XX"
                ], 
                "mac": [
                    "88:a6:XX:XX:XX:XX"
                ], 
                "hostname": "ray-xxx-laptop"
            }, 
            "target": {
                "ip": [
                    "8.8.8.8"
                ]
            }, 
            "network": {
                "applicationProtocol": "DNS", 
                "dns": {
                    "questions": [
                        {
                            "type": 1, 
                            "name": "is5-ssl.mzstatic.com"
                        }
                    ], 
                    "answers": [
                        {
                            "type": 1, 
                            "data": "104.118.212.43", 
                            "name": "is5-ssl.mzstatic.com", 
                            "ttl": 11111
                        }
                    ], 
                    "response": true
                }
            }, 
            
            "collectedTimestamp": "2020-01-02T00:00:00Z", 
            "productName": "ExtraHop", 
            "eventTimestamp": "2020-01-01T23:59:38Z", 
            "eventType": "NETWORK_DNS"
        
        }
    ]
}
```

##### Human Readable Output
>### Event(s) Details
>|Event Timestamp|Event Type|Principal Asset Identifier|Target Asset Identifier|Queried Domain|
>|---|---|---|---|---|
>| 2020-01-01T23:59:38Z | NETWORK_DNS | ray-xxx-laptop | 8.8.8.8 | ninthdecimal.com |
>
>View events in Chronicle
>
>Maximum number of events specified in page_size has been returned. There might still be more events in your Chronicle account. >To fetch the next set of events, execute the command with the start time as 2020-01-01T23:59:38Z
