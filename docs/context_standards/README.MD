# Overview
Demisto organizes incident data in a tree of objects called the *Incident Context*. Any integration commands or scripts that run, will add data into the context at a predefined location. This also applies to commands that run within playbook execution.

When building new integrations the entry context should be returned according to this standard. 

If there is no matching item in the standard, reach out to the architect team to check if your addition merits an update or change of the standard. 

If the data is vendor/tool specific, it can be assigned its own context path.

Below are examples of how each entity should be formed in the entry context.

## File
The following is the format for a file.

```python
"File": {
        "Name": "STRING, The full file name (including file extension).",
        "EntryID": "STRING, The ID for locating the file in the War Room.",
        "Size": "INT, The size of the file in bytes.",
        "MD5": "STRING, The MD5 hash of the file.",
        "SHA1": "STRING, The SHA1 hash of the file.",
        "SHA256": "STRING, The SHA256 hash of the file.",
        "SHA512": "STRING The SHA512 hash of the file.",
        "SSDeep": "STRING, The ssdeep hash of the file (same as displayed in file entries).",
        "Extension": "STRING, The file extension, for example: "xls".",
        "Type": "STRING, The file type, as determined by libmagic (same as displayed in file entries).",
        "Hostname": "STRING, The name of the host where the file was found. Should match Path.",
        "Path": "STRING, The path where the file is located.",
        "Company": "STRING, The name of the company that released a binary.",
        "ProductName": "STRING, The name of the product to which this file belongs.",
        "DigitalSignature": {
            "Publisher": "STRING, The publisher of the digital signature for the file."
        },
        "Actor": "STRING, The actor reference.",
        "Tags": "STRING, Tags of the file.",
        "Signature": {
            "Authentihash": "STRING, The authentication hash.",
            "Copyright": "STRING, Copyright information.",
            "Description": "STRING, A description of the signature.",
            "FileVersion": "STRING, The file version.",
            "InternalName": "STRING, The internal name of the file.",
            "OriginalName": "STRING, The original name of the file."            
        },
        "Malicious": {
             "Vendor": "STRING, The vendor that reported the file as malicious.",
             "Description": "STRING, A description explaining why the file was determined to be malicious."
        }
}
```

## Report
The following is the format for a report.

```python
"Report": {
        "Name": "STRING, The name of the file or document.",
        "EntryID": "STRING, The ID of the War Room entry, where the report file/data is located.",
        "Size": "INT, The size of the report (in bytes).",
        "Brand": "STRING, The brand of the integration that generated the report.",
}
```

## IP
The following is the format for an IP entity

```python
"IP": {
    "Malicious":{
        "Vendor": "STRING, The vendor reporting the IP address as malicious.",
        "Description": "STRING, A description explaining why the IP address was reported as malicious."
    },
    "Address": "STRING, IP address",
    "ASN": "STRING, The autonomous system name for the IP address, for example: "AS8948".",
    "Hostname": "STRING, The hostname that is mapped to this IP address.",
    "Geo":{
        "Location": "STRING, The geolocation where the IP address is located, in the format: latitude:longitude.",
        "Country": "STRING, The country in which the IP address is located.",
        "Description": "STRING, Additional information about the location."
    },
    "DetectionEngines": "NUMBER, The total number of engines that checked the indicator.",
    "PositiveDetections": "NUMBEr, The number of engines that positively detected the indicator as malicious."
}
```

## Endpoint
The following is the format for an Endpoint.

```python
"Endpoint": {
    "Hostname": "STRING, The hostname that is mapped to this endpoint.",
    "ID": "STRING, The unique ID within the tool retrieving the endpoint.",
    "IPAddress": "STRING, The IP address of the endpoint.",
    "Domain": "STRING, The domain of the endpoint.",
    "MACAddress": "STRING, The MAC address of the endpoint.",
    "DHCPServer": "STRING, The DHCP server of the endpoint.",
    "OS": "STRING, Endpoint OS.",
    "OSVersion": "STRING, OS version.",
    "BIOSVersion": "STRING, BIOS version.",
    "Model": "STRING, The model of the machine or device.",
    "Memory": "INT, Memory on this endpoint.",
    "Processors": "INT, The number of processors.",
    "Processor": "STRING, The model of the processor."
}
```

## Ticket
The following is the format for a ticket.
```python
"Ticket": {
    "ID": "STRING, The ID of the ticket.",
    "Creator": "STRING, The user who created the ticket.",
    "Assignee": "STRING, The user assigned to the ticket.",
    "State": "STRING, The status of the ticket. Can be "closed", "open", or "on hold"."
}
```

## Email
The following is the format for an Email.
```python
"Email": {
    "To": "STRING, The recipient of the email.",
    "From": "STRING, The sender of the email.",
    "CC": "STRING, Email addresses CC'ed to the email.",
    "BCC": "STRING, Email addresses BCC'ed to the email.",
    "Format": "STRING, The format of the email.",
    "Body/HTML": "STRING, The HTML version of the email.",
    "Body/Text": "STRING, The plain-text version of the email.",
    "Subject": "STRING, The subject of the email.",
    "Headers": "STRING, The headers of the email.",
    "Attachments": [
        "entryID"
    ]
}
```

## Domain
The following is the format for a Domain. Please note that for WHOIS, the entity is a dictionary nested for the key "WHOIS".
```python
"Domain": {
    "Name": "STRING, The domain name, for example: "google.com".",
    "DNS": "STRING, A list of IP objects resolved by DNS.",
    "DetectionEngines": "NUMBER, The total number of engines that checked the indicator.",
    "PositiveDetections": "NUMBER, The number of engines that positively detected the indicator as malicious.",
    "CreationDate": "DATE, The date that the domain was created.",
    "DomainStatus": "STRING, The status of the domain.",
    "ExpirationDate": "DATE, The expiration date of the domain.",
    "NameServers": "STRING, Name servers of the domain.",
    "Organization": "STRING, The organization of the domain.",
    "Subdomains": "STRING, Subdomains of the domain.",
    "UpdatedDate": "DATE, The date that the domain was last updated.",
    "Admin": {
        "Country": "STRING, The country of the domain administrator.",
        "Email": "STRING, The email address of the domain administrator.",
        "Name": "STRING, The name of the domain administrator.",
        "Phone": "STRING, The phone number of the domain administrator."
    },
    "Registrant": {
        "Country": "STRING, The country of the registrant.",
        "Email": "STRING, The email address of the registrant.",
        "Name": "STRING, The name of the registrant.",
        "Phone": "STRING, The phone number for receiving abuse reports.",
        "Email": "STRING, The email address for receiving abuse reports."
    },
    "WHOIS": {
        "DomainStatus": "STRING, The status of the domain.",
        "NameServers": "STRING, A list of name servers, for example: "ns1.bla.com, ns2.bla.com".",
        "CreationDate": "DATE, The date that the domain was created.",
        "UpdatedDate": "DATE, The date that the domain was last updated.",
        "ExpirationDate": "DATE, The date that the domain expires.",
        "Registrant": {
            "Name": "STRING, The name of the registrant.",
            "Email": "STRING, The email address of the registrant.",
            "Phone": "STRING, The phone number of the registrant."
        },
        "Registrar": {
            "Name": "STRING, The name of the registrar, for example: "GoDaddy".",
            "AbuseEmail": "STRING, The email address of the contact for reporting abuse.",
            "AbusePhone": "STRING, The phone number of contact for reporting abuse."
        },
        "Admin": {
            "Name": "STRING, The name of the domain administrator.",
            "Email": "STRING, The email address of the domain administrator.",
            "Phone": "STRING, The phone number of the domain administrator."
        }
    },
    "WHOIS/History": "List of Whois objects",
    "Malicious":{
        "Vendor": "STRING, The vendor reporting the domain as malicious.",
        "Description": "STRING, A description explaining why the domain was reported as malicious."
    },
}
```
## URL
The following is the format for a URL entity.
```python
"URL": {
    "Data": "STRING, The URL",
    "Malicious": {
        "Vendor": "STRING, The vendor reporting the URL as malicious.",
        "Description": "STRING, A description of the malicious URL."
    },
    "DetectionEngines": "NUMBER, The total number of engines that checked the indicator.",
    "PositiveDetections": "NUMBER, The number of engines that positively detected the indicator as malicious.",
}
```

## CVE
The following is the format for a CVE.
```python
"CVE": {
    "ID": "STRING, The ID of the CVE, for example: "CVE-2015-1653".",
    "CVSS": "STRING, The CVSS of the CVE, for example: "10.0".",
    "Published": "DATE, The timestamp of when the CVE was published.",
    "Modified": "DATE, The timestamp of when the CVE was last modified.",
    "Description": "STRING, A description of the CVE."
}
```

## Account
The following is the format for an Account entity.
```python
"Account": {
    "Type": "STRING, The account type. The most common value is "AD", but can be "LocalOS", "Google", "AppleID", ... ",
    "ID": "STRING, The unique ID for the account (integration specific). For AD accounts this is the Distinguished Name (DN).",
    "Username": "STRING, The username in the relevant system.",
    "DisplayName": "STRING, The display name",
    "Groups": "STRING, Groups to which the account belongs (integration specific). For example, for AD these are groups of which the account is memberOf.",
    "Domain": "STRING, The domain of the account.",
    "OrganizationUnit": "STRING, The Organization Unit (OU) of the account.",
    "Email": {
        "Address": "STRING, The email address of the account."
    }
}
```

## Registry Key
The following is the format for a Registry Key.
```python
"RegistryKey": {
    "Path": "STRING, The path to the registry key",
    "Name": "STRING, The name of registry key.",
    "Value": "STRING, The value at the given RegistryKey."
}
```

## Rule
The following is the format for a Rule.
```python
"Rule": {
    "Name": "STRING, The name of the rule.",
    "Condition": "STRING, The condition for the rule."
}
```

## Event
The following is the format for an Event.
```python
"Event": {
    "Type": "STRING, The type of event, for example: "ePO", "Protectwise", "DAM".",
    "ID": "STRING, The unique identifier of the event.",
    "Name": "STRING, The name of the event.",
    "Sensor": "STRING, The sensor that indicated the event.",
    "Rule": "STRING, The rule that triggered the event."
}
```

## Directory
The following is the format for a Directory.
```python
"Directory": {
    "Path": "STRING, The directory path. Can be "local" or "UNC".",
    "Endpoint": "STRING, Whether the directory is found on a specific endpoint."
}
```

## Service
The following is the format for a Service.
```python
"Service": {
    "Name": "STRING, The name of the service.",
    "BinPath": "STRING, The path of the /bin folder.",
    "CommandLine": "STRING, The full command line (including arguments).",
    "StartType": "STRING, How the service was started.",
    "State": "STRING, The status of the service."
}
```

## Process
The following is the format for a process.
```python
"Process": {
    "Name": "STRING, The name of the process.",
    "PID": "STRING, The PID of the process.",
    "Hostname": "STRING, The endpoint on which the process was seen.",
    "MD5": "STRING, The MD5 hash of the process.",
    "SHA1": "STRING, The SHA1 hash of the process.",
    "CommandLine": "STRING, The full command line (including arguments).",
    "Path": "STRING, The file system path to the binary file.",
    "Start Time": "DATE, The timestamp of the process start time.",
    "End Time": "DATE, The timestamp of the process end time.",
    "Parent": "STRING, Parent process objects.",
    "Sibling": "LIST, Sibling process objects.",
    "Child": "LIST, Child process objects."
}
```

## Host
The following is the format for a host.
```python
"Host": {
    "Domain": "STRING, The domain of the host.",
    "Hostname": "STRING, The name of the host.",
    "BIOVersion": "STRING, The BIOS version of the host.",
    "ID": "STRING, The unique ID within the tool retrieving the host.",
    "DHCPServer": "STRING, The DHCP server.",
    "IP": "STRING, The IP address of the host.",
    "MACAddress": "STRING, The MAC address of the host.",
    "Memory": "STRING, Memory on the host.",
    "Model": "STRING, The model of the host.",
    "OS": "STRING, Host OS.",
    "OSVersion": "STRING, The OS version of the host.",
    "Processor": "STRING, The processor of the host.",
    "Processors": "INT, The number of processors that the host is using.'" 
}
```
## InfoFile
The following is the expected format for an InfoFile
```python
"InfoFile": {
    "Name": "STRING, The file name.",
    "EntryID": "STRING, The ID for locating the file in the War Room.",
    "Size": "INT, The size of the file (in bytes).",
    "Type": "STRING, The file type, as determined by libmagic (same as displayed in file entries).",
    "Extension": "STRING, The file extension.",
    "Info": "STRING, Basic information about the file."
}
```

## DBot Score
The following is the format for a DBot Score entry.
```python
"DBotScore": {
    "Indicator": "The indicator that was tested.",
    "Type": "The indicator type.",
    "Vendor": "The vendor used to calculate the score.",
    "Score": "The actual score."
}
```
