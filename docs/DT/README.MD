# Demisto Transform Language (DT)

## An explanation of the wizardry
Demisto Transform Language (commonly referred to as "DT") is used for various functions within Demisto related to Context. In it's most basic sense, DT allows us to map context from previous tasks and use them in our current task. For example if we wanted to add updated information to the context for an indicator, we would use DT to update it as opposed to creating another entry.

## Using DT
If you know Javascript, this will be familiar to you. If you don't know Javascript, I'm sorry. It will make some sense since it is really just learning a different syntax.

### Nested Values
DT can go deep. Deep like cosmic brownies and Jimi Hendrix at 2am deep. But in its essence, we are dealing with a dictionary of key values. Let's look at the following example.

```python
{
    "IP": {
        "Geo": {
            "Country": "United States",
            "Location": "37.751, -97.822"
        },
        "ASN": 15169,
        "Address": "8.8.8.8"
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

If we wanted to access the "Continent" value under "Geo" in "Maxmind", we would use the following.
```python
${MaxMind.Geo.Continent}
```

### Dealing with Arrays
We access array values just as we would any other dictionary (or JSON) key in dot notation, with an index.

**Indexes start at 0!** The first is not "1", we are dealing with code, not sheep.

Let's take a look at the following context.

```python
{
    "URL": {
        "Data": "google.com"
    },
    "DBotScore": {
        "Vendor": "urlscan.io",
        "Indicator": "google.com",
        "Score": 0,
        "Type": "url"
    },
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
    }
}
```

Under "URLScan", we have an array called "Certificates". If we wanted to access the "SubjectName" value of the first entry, we would use the following DT statement.

```python
${URLScan.Certificates.[0].SubjectName}
```

If you want to retrieve a range of results, you can use ```[0:9]``` where "0" is the beginning of the array and "9" is the 9th position in the array.

### Selectors
DT also allows for condtions within the statement itself. This functions as a way to bind results together by embedding a selection into the DT string.

The following are a few examples of selector methods:

| Example | Description |
| --- | ---|
| ```${File.type.description(val == 'Acrobat PDF document version 1.4')} ``` | will return only descriptions that exactly match the Acrobat description. |
| ```${File.type.description(val.indexOf('Acrobat') == 0)}``` | will return any description that starts with the word “Acrobat” |
| ```${File.type.description(val.indexOf('PDF') >= 0)}``` | will return any description that contains PDF. |
| ```${File.type.description(val.toUpperCase().indexOf('PDF') >= 0)}``` | will return any description that contains PDF or pdf or any mixed case. |
| ```${File.type(val.mime.indexOf('pdf')==val.length-3).description}``` | will return all descriptions for files that have mime ending with pdf. Please notice that we tested a relative path to “type” (“mime”) and returned a different path (“description”). |
| ```${File.type(val.mime == val1---File.[0].type.mime).description} ``` | will return all descriptions for files that have the same mime type as the first file in the array. Please notice that the bind value (val1) does not start with ‘.’ and will DT the context from the top context. |

Selectors are great for avoiding duplicate entries and can be used to add context to existing entries.

An example of how this may be used in your code is the following:
```python
demisto.results({
 Type: entryTypes.note,
 Contents: 'related',
 ContentsFormat: formats.json,
 HumanReadable: 'md',
 EntryContext: {'Endpoints(val.name && val.name == obj.name)': [{'name':'two', 'time': new Date().toString(), 'some_other_key': Math.random()}]}
})
```

The code snippet ```'Endpoints(val.name && val.name == obj.name)``` will look for entries in the context whose name found under "Endpoint" are the same. If it finds a match, it will update the existing context, If it does not, it will create a new entry in the context because it views the entry as "unique" to the existing values.

### Mutators
DT is also capable of mutating a result in the event that your integration may need a different format of the result. A classic use case for this would be using joining a server address obtained from another integration to an endpoint found by your integration to create a url which may be used by your integration at a later time.

Here are a few examples:

| Example | Description |
| --- | --- |
| ```${File.type.description=val.toLowerCase()}``` | returns all the descriptions but in lower case. |
| ```${File.type.description(val.indexOf('pdf')>=0)=val.toLowerCase()}``` | returns all the descriptions containing “pdf” but in lower case. |
| ```${File.type=val.mime +': ' + val.description} ``` | returns the concatenated mime and description for all files. |
| ```${File.type={MIME: val.mime, Description: val.description}}``` | returns for each file an object with two fields. |


