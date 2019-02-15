# Demisto Transform Language (DT)

## An explanation of the wizardry
Demisto Transform Language (commonly referred to as "DT") is used for various functions within Demisto related to Context. In it's most basic sense, DT is a query langauge for JSON objects. If you are familiar with JSONQuery, this should be very familiar to you.

## Context Example
We are going to use the following as our example context and go over the various ways that DT can be used to access, aggregate, and mutate data.

```python
{
    "URL": {
        "Data": "google.com"
    },
    "IP": {
        "Hostname": "google-public-dns-a.google.com",
        "RecordedFuture": {
            "FirstSeen": "2010-04-27T12:46:51.000Z",
            "Criticality": "None",
            "LastSeen": "2019-02-06T11:13:38.139Z"
        },
        "Address": "8.8.8.8",
        "Geo": {
            "Country": "United States",
            "Location": "37.751, -97.822"
        },
        "ASN": 15169
    },
    "DBotScore": [{
        "Vendor": "urlscan.io",
        "Indicator": "google.com",
        "Score": 0,
        "Type": "url"
    }, {
        "Vendor": "ipinfo",
        "Indicator": "8.8.8.8",
        "Score": 0,
        "Type": "ip"
    }, {
        "Vendor": "Recorded Future",
        "Indicator": "8.8.8.8",
        "Score": 0,
        "Type": "ip"
    }, {
        "Vendor": "VirusTotal",
        "Indicator": "8.8.8.8",
        "Score": 1,
        "Type": "ip"
    }],
    "URLScan": {
        "URL": "google.com",
        "Country": ["IE"],
        "Certificates": [{
            "SubjectName": "www.google.com",
            "ValidFrom": "2018-12-19 08:16:00",
            "ValidTo": "2019-03-13 08:16:00",
            "Issuer": "Google Internet Authority G3"
        }, {
            "SubjectName": "*.google.com",
            "ValidFrom": "2018-12-19 08:17:39",
            "ValidTo": "2019-03-13 08:17:00",
            "Issuer": "Google Internet Authority G3"
        }, {
            "SubjectName": "www.google.de",
            "ValidFrom": "2018-12-19 08:16:00",
            "ValidTo": "2019-03-13 08:16:00",
            "Issuer": "Google Internet Authority G3"
        }, {
            "SubjectName": "*.g.doubleclick.net",
            "ValidFrom": "2018-12-19 08:17:00",
            "ValidTo": "2019-03-13 08:17:00",
            "Issuer": "Google Internet Authority G3"
        }, {
            "SubjectName": "*.apis.google.com",
            "ValidFrom": "2018-12-19 08:16:00",
            "ValidTo": "2019-03-13 08:16:00",
            "Issuer": "Google Internet Authority G3"
        }],
        "ASN": "AS15169"
    },
    "MaxMind": {
        "Address": "8.8.8.8",
        "ISP": "Google",
        "UserType": "business",
        "Organization": "Google LLC",
        "ISO_Code": "US",
        "Geo": {
            "Location": "37.751, -97.822",
            "Country": "United States",
            "Continent": "North America",
            "Accuracy": 1000
        },
        "ASN": 15169,
        "RegisteredCountry": "United States"
    }
}
```

### Nested Values
DT can go deep. Deep like cosmic brownies and Jimi Hendrix at 2am deep. But in its essence, we are dealing with a dictionary of key values. Let's look at the following example.

Using the context example noted above, these are the various ways that DT can be used to access nested keys.

| Example | Result |
| --- | --- |
| ```${MaxMind.Geo.Continent}``` | North America |
| ```${IP.Hostname}``` | google-public-dns-a.google.com |
| ```${IP.RecordedFuture.FirstSeen}``` |  2010-04-27T12:46:51.000Z |


### Dealing with Arrays
We access array values just as we would any other dictionary (or JSON) key in dot notation, with an index.

**Indexes start at 0!** The first is not "1", we are dealing with code, not sheep.

Let's take a look at the above context.

Under "URLScan", we have an array called "Certificates". If we wanted to access the "SubjectName" value of the first entry, we would use the following DT statement.

| Example | Result |
| --- | --- |
| `${URLScan.Certificates.SubjectName}` | \["www.google.com", "*.google.com", "www.google.de", "\*.g.doubleclick.net", "\*.apis.google.com"] |
| ```${URLScan.Certificates.[0].SubjectName}``` | www.google.com |
| `${URLScan.Certificates.[0:2].SubjectName}` | \["www.google.com", "*.google.com", "www.google.de"] |

If you want to retrieve a range of results, you can use ```[0:9]``` where "0" is the beginning of the array and "9" is the 9th position in the array.

### Selectors
DT also allows for conditions within the statement itself and uses Javascript to select the context items. This functions as a way to bind results together by embedding a selection into the DT string.

You will notice that `val` is used quite often in the DT string. This is a Javascript method that exposes the value at the given context path.

The following are a few examples of selector methods:

| Example | Result | Description |
| --- | --- | --- |
| ```${DBotScore.Vendor(val == 'urlscan.io')} ``` | `urlscan.io` | will return only Vendors that exactly match the Acrobat description. |
| ```${URLScan.Certificates.SubjectName(val.indexOf('www') == 0)}``` | `[www.google.com, www.google.de]` | will return any SubjectName that starts with "www" |
| ```${URLScan.Certificates.SubjectName(val.indexOf('doubleclick') >= 0)}``` | `*.g.doubleclick.net` | will return any SubjectName that contains doubleclick. |
| ```${URLScan.Country(val.toUpperCase().indexOf('IE') >= 0)}``` | `IE` | will return any Country that contains IE or ie or any mixed case. |
| ```${URLScan.Certificates(val.SubjectName.indexOf('de')==val.length-2).ValidTo}``` | `2019-03-13 08:16:00` | will return all ValidTo for certificates that have SubjectName ending with de. Please notice that we tested a relative path to “SubjectName” (“de”) and returned a different path (“ValidTo”). |
| ```${URLScan.Certificates(val.ValidFrom == val1---URLScan.Certificates.[0].ValidFrom).SubjectName} ``` | `["www.google.com", "www.google.de", "*.apis.google.com"]`| will return all SubjectNames for Certificates that have the same ValidTo time as the first Certificate in the array. Please notice that the bind value (val1) does not start with ‘.’ and will DT the context from the top context. |

Selectors are great for avoiding duplicate entries and can be used to add context to existing entries.

An example of how this may be used in your code is the following:
```python
ec = {
        "Vendor": "Recorded Future",
        "Indicator": "8.8.8.8",
        "Score": 0,
        "Type": "ip"
    }


demisto.results({
 Type: entryTypes.note,
 Contents: 'related',
 ContentsFormat: formats.json,
 HumanReadable: 'md',
 EntryContext: {'DBotScore(val.Indicator && val.Indicator == obj.Indicator)': ec 
})
```

The code snippet ```'DBotScore(val.Indicator && val.Indicator == obj.Indicator)``` will look for entries in the context whose name found under "Indicator" are the same. If it finds a match, it will update the existing context, If it does not, it will create a new entry in the context because it views the entry as "unique" to the existing values.

### Mutators
Since DT is Javascript based, it is also capable of mutating a result in the event that your integration may need a different format of the result. A classic use case for this would be using joining a server address obtained from another integration to an endpoint found by your integration to create a url which may be used by your integration at a later time.

Here are a few examples:

| Example | Result | Description |
| --- | --- | --- |
|```${URLScan.Certificates(val.SubjectName.indexOf("doubleclick") > -1).ValidFrom=foo(val);function foo(aa) { return aa + "Z"; }}``` | `2018-12-19 08:17:00Z` | Returns the timestamp where the SubjectName contains the word "doubleclick". Then it appends "Z" to the value |
| ```${MaxMind.Organization=val.toLowerCase()}``` | `google llc` | returns all the organizations but in lower case. |
| ```${DBotScore.Vendor(val.indexOf('Recorded')>=0)=val.toLowerCase()}``` | `"Recorded Future"` | returns all the Vendors containing “Recorded” but in lower case. |
| ```${DBotScore.type=val.ip +': ' + val.Vendor} ``` | `["ip: ipinfo", "ip: Recorded Future", "ip: VirusTotal"]` | returns the concatenated ip and vendor for all DBotScores. |


