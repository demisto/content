# Overview

To understand Incident Context, we must first know what an incident is. When we refer to "Incidents" in Demisto, we are talking about events. These events could be malicious files found in an email, someone losing their device, and even abnormal outbound traffic. How an analyst reacts to these incidents depends on the information they have at hand to make an informed decision. It is with the Incident Context, that this is achieved.   

Context is a map (dictionary) /JSON object that is created for each incident and is used to store structured results from the integration commands and automation scripts. The context keys are strings and the values can be strings, numbers, objects, and arrays.

The main use of context is to pass data between playbook tasks. Another usage is to capture the important structured data from automations and display the data in the incident summary.

Since context is used within playbooks, it is critical that the context outputs remain reproducible. Meaning, that the structure of the context does not change. 

Let's look at a real world example that can show you how context is used:

## URLScan

```python

    dbot_score = {
        'Indicator': 'malware.wicar.org',
        'Score': 3,
        'Type': 'url'
    }
    
    url_cont = {
        'Data': 'malware.wicar.org',
        'Malicious': {
            'Description': 'Match found in Urlscan.io database',
            'Vendor': 'urlscan.io'
        }
    }
    
    cont = {
        'ASN': 'AS40630',
        'Certificates': {
            'Issuer': 'Google Internet Authority G3',
            'SubjectName': '*.googleapis.com',
            'ValidFrom': '2018-12-04 09:33:00',
            'ValidTo': '2019-02-26 09:33:00'
        },
        'Country': ['US', 'EU', 'IE', 'DE', 'NL'],
        'Data': 'malware.wicar.org',
    }

    ec = {
        'URLScan(val.URL && val.URL == obj.URL)': cont, # Please see the section on DT below
        'DBotScore': dbot_score,
        'URL': url_cont
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response,
        'HumanReadable': tableToMarkdown('{} - Scan Results'.format(url_query), human_readable),
        'EntryContext': ec
    })
```

In this example, we are pushing three different dictionaries into the context. ```cont``` which contains the context specific to URLScan, ```dbot_score``` which contains the DBot score context, and ```URL``` which is part of the context standard for URLs.

In the Integration settings, we see:

![screen shot 2019-01-09 at 14 54 40](https://user-images.githubusercontent.com/42912128/50900672-90a7c800-141e-11e9-946d-8d5352e279ec.png)

These paths can be seen in the context found in the war room, here:

![screen shot 2019-01-09 at 14 57 17](https://user-images.githubusercontent.com/42912128/50900776-e3817f80-141e-11e9-8263-d75cf6cf2dc0.png)


**Please Note:** When improving or replacing an existing integration, verify that the context outputs are backwards compatible. Otherwise, changes can break playbooks and prevent them from running.

# Context
Context is defined by an integration by adding the following to the results command:
```
ec = 'VirusTotal.IP(val.Address==obj.Address)': {
    'Address': '8.8.8.8'.,
    'ASN': 'BLA_ASN',
    'Domain': ['google.com']
}

demisto.results({
    'Type': entryTypes['note'],
    'ContentsFormat': formats['markdown'],
    'Contents': raw_content_obj,
    'HumanReadable': human_readable_obj,
    'EntryContext': ec
})
```

## DT (Demisto Transform Language)
In the above example, we observe the entry context using ```(val.Address==obj.Address)```. This works to *tie together* related entry context objects. In this instance, we are using the value of the Address key as the unique identifier to search through the existing context and link related objects. This prevents data from being overwritten as well as further enriches an existing entry with more information. Learn more about linking context [here](https://github.com/demisto/etc/wiki/Demisto-Code-Conventions#linking-context).


## Adding Context to an Integration
When adding context to an integration, we must explicitly define what the context paths are so they will be accessible. See below to understand how context should be defined in the Integration Settings.

<img src="https://user-images.githubusercontent.com/42912128/50211819-42089000-0382-11e9-8a7f-421a92a89620.png" width="700" align="middle">

When fully configured, the example above will produce the results shown below:

<img src="https://user-images.githubusercontent.com/42912128/50211940-8431d180-0382-11e9-8e0c-a57672b4fcc1.png" width="250" align="middle">

## Context Code Conventions
Demisto uses a standardised format for it's context paths and should match the following:
```
ProductName.Object.Field
```

## Examples
Examples of how other Integrations have defined Context are as follows:
```
Panorama.SecurityRule.Name
Panorama.SecurityRule.IPAddress

AWS.S3.Buckets.Policy.Version
AWS.S3.Buckets.Policy.PolicyId


Centreon.Service.Name
Centreon.Service.ServiceId
Centreon.Service.Description
```

In the context menu, you will see three fields; Context Path, Description and Type. Their uses are as follows:
* **Context Path** - This is a Dot Notation representation of the path to access the context
* **Description** - A short description of what the context is
* **Type** - Indicating the type of value that is located at the path enables Demisto to format the data correctly