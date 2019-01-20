# Overview
DBot is the Demisto machine learning bot which ingests information about indicators to determine if they are malicious or not. Since DBot requires a very specific dataset, we must format our data as per this article.


**Please Note**: We are unable to use the Demisto Transformers (DT) within the DBot score context. 

For example, using the following in your DBot cpntext, will not work:

```python
DBotScore(val.Indicator == obj.Indicator)
```

## Context Format
```python
      "DBotScore": {
          "Indicator" : "foo@demi.com",
          "Type": "email",
          "Vendor": "JoeSecurity",
          "Score": 3
      } 
```

The DBot score must be at the root level of the context and contain **all** of the keys listed below.

| Key | Meaning |
| --- | ---|
| Indicator | Can be: IP, SHA1, MD5, SHA256, Email, or Url |
| Type | Can be: ip, file, email, or url|
| Vendor | This is the vendor reporting the score of the indicator|
| Score | An int representing the status of the indicator. See Score Types below|


## Score Types
Dbot uses an integer to represent the reputation of an indicator.

| Number | Reputation |
| --- | --- |
| 0 | Unknown |
| 1 | Good |
| 2 | Suspicious |
| 3 | Bad |

## Malicious
If the DBot score is returned as a "3" or "Bad", we need to add to the context that a malicious indicator was found. To do this, we add an additional key to the URL, IP, or File context called "Malicious" as shown below:

```python
demisto.results({
     "Type": entryTypes["note"],
     "EntryContext": {
        "URL": {
            "Data": "STRING, The URL",
            "Malicious": {
                "Vendor": "STRING, Vendor reporting the malicious status",
                "Description": "STRING, Description of the malicious url"
            }
        },
         "File": {
            "Data": "STRING, The File Hash",
            "Malicious": {
                "Vendor": "STRING, Vendor reporting the malicious status",
                "Description": "STRING, Description of the malicious hash"
            }
        },
         "IP": {
            "Data": "STRING, The IP",
            "Malicious":{
                "Vendor": "STRING, Vendor reporting malicious",
                "Description": "STRING, Description about why IP was determined malicious"
    },
        },
         "Domain": {
            "Data": "STRING, The Domain",
            "Malicious": {
                "Vendor": "STRING, Vendor reporting the malicious status",
                "Description": "STRING, Description of the malicious domain"
            }
        }
    }
})
```

Malicious has two key values, "Vendor" and "Description". Vendor is the entity reporting the malicious indicator and description explains briefly what was found. For example:


```python
"URL": {
    "Data": "http://viruswarehouse.com",
    "Malicious": {
        "Vendor": "VirusTotal",
        "Description": "Wannacry ransomware detected"
    }
}
```

