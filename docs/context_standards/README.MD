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
        "Name": "STRING, Full Filename e.g. data.xls",
        "EntryID": "STRING, If the file is in the war room, where it can be found",
        "Size": "INT, Size of the file in bytes",
        "MD5": "STRING, MD5 Hash of the file",
        "SHA1": "STRING, SHA1 Hash of the file",
        "SHA256": "STRING, SHA256 hash of the file",
        "SSDeep": "STRING, The ssdeep value for the file (same as we display in file entries)",
        "Extension": "STRING, the file extension e.g. xls",
        "Type": "STRING, File type as determined by libmagic (same as we display in file entries)",
        "Hostname": "STRING, name of the host where the file was found. Should match Path",
        "Path": "STRING, Path where the file was found",
        "Company": "STRING, name of the company that released a binary",
        "ProductName": "STRING, name of the product to which this file belongs",
        "DigitalSignature": {
            "Publisher": "STRING, Publisher of the digital signature for the file."
        }
}
```

## Report
The following is the format for a report.

```python
"Report": {
        "Name": "STRING, File or document name",
        "EntryID": "STRING, ID of the war room entry where the report file/data is found",
        "Size": "INT, size of the report in bytes",
        "Brand": "STRING, brand of the integration which generated the report",
}
```

## IP
The following is the format for an IP entity

```python
"IP": {
    "Malicious":{
        "Vendor": "STRING, Vendor reporting malicious",
        "Description": "STRING, Description about why IP was determined malicious"
    },
    "Address": "STRING, IP address",
    "ASN": "STRING, Autonomous System name for the IP. E.g. AS8948",
    "Hostname": "STRING, hostname mapped to this IP",
    "Geo":{
        "Location": "STRING, in format latitude, longitude",
        "Country": "STRING, Country IP is found",
        "Description": "STRING, If more information is known about the location, put it here"
    }
}
```

## Endpoint
The following is the format for an Endpoint.

```python
"Endpoint": {
    "Hostname": "STRING, hostname mapped to this Endpoint",
    "ID": "STRING, The unique ID within the tool retrieving the endpoint",
    "IPAddress": "STRING, IP Address of the endpoint",
    "Domain": "STRING, domain of the endpoint",
    "MACAddress": "STRING, MAC Address of the endpoint",
    "DHCPServer": "STRING, DHCP server of the endpoint",
    "OS": "STRING, Operating System of the endpoint",
    "OSVersion": "STRING, Version of the Operating System",
    "BIOSVersion": "STRING, Version of the BIOS",
    "Model": "STRING, the machine or device model, if available",
    "Memory": "INT, Amount of memory on this endpoint",
    "Processors": "INT, Number of processors",
    "Processor": "STRING, Model of processor"
}
```

## Ticket
The following is the format for a ticket.
```python
"Ticket": {
    "ID": "STRING, ID of the ticket",
    "Creator": "STRING, Individual who created the ticket",
    "Assignee": "STRING, Who is assigned the ticket",
    "State": "STRING, Status of the ticket e.g. closed, open, on hold"
}
```

## Email
The following is the format for an Email.
```python
"Email": {
    "To": "STRING, Recipient of the email",
    "From": "STRING, Sender of the email",
    "CC": "STRING, Email Addresses that are CC'd",
    "BCC": "STRING, Email Addresses that are BCC'd",
    "Format": "STRING, Format of the email",
    "Body/HTML": "STRING, HTML version of the email",
    "Body/Text": "STRING, Text version of the email",
    "Subject": "STRING, Subject of the email",
    "Headers": "STRING, Hedaers of the email",
    "Attachments": [
        "entryID"
    ]
}
```

## Domain
The following is the format for a Domain. Please note that for WHOIS, the entity is a dictionary nested for the key "WHOIS".
```python
"Domain": {
    "Name": "STRING, the domain name e.g. google.com",
    "DNS": "STRING, IPs resolved by DNS. List of IP objects",
    "WHOIS": {
        "DomainStatus": "STRING, Status of the domain",
        "NameServers": "STRING, List of nameservers e.g. 'ns1.bla.com, ns2.bla.com'",
        "CreationDate": "DATE, Date the domain was created",
        "UpdatedDate": "DATE, Date the domain was last updated",
        "ExpirationDate": "DATE, Date the domain expires",
        "Registrant": {
            "Name": "STRING, Name of the registrant",
            "Email": "STRING, Email of the registrant",
            "Phone": "STRING, Phone Number of the registrant"
        },
        "Registrar": {
            "Name": "STRING, Registrar name e.g. GoDaddy",
            "AbuseEmail": "STRING, Email address of the abuse contact",
            "AbusePhone": "STRING, Phone number of the abuse contact"
        },
        "Admin": {
            "Name": "STRING, Name of the domain admin",
            "Email": "STRING, Email address of the domain admin",
            "Phone": "STRING, Phone number of the domain admin"
        }
    },
    "WHOIS/History": "List of whois objects",
    "Malicious":{
        "Vendor": "STRING, Vendor reporting malicious",
        "Description": "STRING, Description about why Domain was determined malicious"
    },
}
```
## URL
The following is the format for a URL entity.
```python
"URL": {
    "Data": "STRING, The URL",
    "Malicious": {
        "Vendor": "STRING, Vendor reporting the malicious status",
        "Description": "STRING, Description of the malicious url"
    }
}
```

## CVE
The following is the format for a CVE.
```python
"CVE": {
    "ID": "STRING, ID of the CVE e.g. CVE-2015-1653",
    "CVSS": "STRING, e.g. 10.0",
    "Published": "DATE, timestamp",
    "Modified": "DATE, timestamp",
    "Description": "STRING, Description of the CVE"
}
```

## Account
The following is the format for an Account entity.
```python
"Account": {
    "Type": "STRING, most common value is AD. but can be LocalOS, Google, AppleID, ... ",
    "ID": "STRING, integration-specific unique ID for the account. For AD accounts this is the Distinguished Name.",
    "Email": "STRING, email for the account e.g. johnd@acme.com",
    "Username": "STRING, username in the relevant system, e.g. johnd",
    "DisplayName": "STRING, e.g. 'John Doe'",
    "Groups": "STRING, integration-specific groups to which the account belongs e.g. for AD these are groups that the account is memberOf"
}
```

## Registry Key
The following is the format for a Registry Key.
```python
"RegistryKey": {
    "Path": "STRING, Path to the registry key",
    "Name": "STRING, Name of registry key",
    "Value": "STRING, Value at the given RegistryKey"
}
```

## Rule
The following is the format for a Rule.
```python
"Rule": {
    "Name": "STRING, Name of the rule",
    "Condition": "STRING, Condition for the rule"
}
```

## Event
The following is the format for an Event.
```python
"Event": {
    "Type": "STRING, Type of event e.g. ePO, Protectwise, DAM",
    "ID": "STRING, Unique identifier for the event",
    "Name": "STRING, Name of the event",
    "Sensor": "STRING, Sensor that indicated the event",
    "Rule": "STRING, rule that triggered the event"
}
```

## Directory
The following is the format for a Directory.
```python
"Directory": {
    "Path": "STRING, can be local or UNC e.g. for a network share",
    "Endpoint": "STRING, if found on a specific endpoint"
}
```

## Service
The following is the format for a Service.
```python
"Service": {
    "Name": "STRING, Name of the service",
    "BinPath": "STRING, Path of the Bin",
    "CommandLine": "STRING, full commandline including arguments",
    "StartType": "STRING, How the service was started",
    "State": "STRING, Status of the service"
}
```

## Process
The following is the format for a process.
```python
"Process": {
    "Name": "STRING, Name of the process",
    "PID": "STRING, PID of the process",
    "Hostname": "STRING, endpoint where the process was seen",
    "MD5": "STRING, MD5 hash of the process",
    "SHA1": "STRING, SHA1 hash of the process",
    "CommandLine": "STRING, full commandline including arguments",
    "Path": "STRING, Filesystem path to the binary file",
    "Start Time": "DATE, timestamp",
    "End Time": "DATE, timestamp",
    "Parent": "STRING, process object",
    "Sibling": "LIST, Sibling process objects",
    "Child": "LIST, of Child process objects"
}
```

## InfoFile
The following is the expected format for an InfoFile
```python
"InfoFile": {
    "Name": "STRING, FileName",
    "EntryID": "STRING, If the file is in the war room, where it can be found",
    "Size": "INT, Size of the file in bytes",
    "Type": "STRING, File type as determined by libmagic (same as we display in file entries)",
    "Extension": "STRING, the file extension e.g. xls",
    "Info": "STRING, Basic information of the file"
}
```

## DBot Score
The following is the format for a DBot Score entry.
```python
"DBotScore": {
    "Indicator": "STRING, The indicator that was tested",
    "Type": "STRING, Indicator type",
    "Vendor": "STRING, Vendor used to calculate the score",
    "Score": "INT, The actual score",
}
```