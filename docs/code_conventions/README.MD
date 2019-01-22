# Overview
The purpose of standardising our code conventions is to ensure uniformity among all integrations. This section outlines some of the code conventions that we, here at Demisto, use.

## Dates
We do not use epoch time for customer facing results (Context, Human Readable, etc.). If the API you are working with requires the time format to be in epoch, then convert the date string into epoch as needed. Where possible, use the human readable format of date ```%Y-%m-%dT%H:%M:%S```

```python
time_epoch = '499137720'
formatted_time = formatEpochDate(time_epoch)
print(formatted_time)
>>> '1985-10-26T01:22:00'
```

**Please note:** If the response returned is in epoch, it is best practices to convert it to ```%Y-%m-%dT%H:%M:%S```

## JSON, Dictionaries, and Object Formatting
Object should be easy to read. Therefore, if your JSON, dict, or object contains more than one value (or key value pair), it should follow the following format.
```python
demisto.results({ 
    'Type' : entryTypes['note'], 
    'ContentsFormat' : formats['json'], 
    'Contents' : content
})
```

Do not list multiple items on one line as demonstrated below:
```python
demisto.results({ 'Type' : entryTypes['note'], 'ContentsFormat' : formats['json'], 'Contents' : content })
```

## Global Variables / Integration Constants
When using a global variable or Integration Constant, the variable name must be in all caps. This makes it easier to quickly find inputs in your code. For example:
```python
API_VERSION = "v1"
USERNAME = demisto.params().get("url")
```

**Please restrain from naming variables as shown below**
```python
apiVersion = "v1"
url = demisto.params().get("url")
```

## Arguments
When naming an argument, the name should be all lowercase with spaces replaced by underscores. See the example below:

### Do this:
```
!cylance-get-incident incident_id
```
 ### Not this:
 ```python
!cylance-get-incident incidentId
```

Additionally, arguments are to be passed through the ```sample_function_command``` function and must not reside in the primary ```sample_function``` function. Observe the following:

**Do This**

```python
def sample_function(arg1):
    response = arg1 + 'is the argument'
    return response

def sample_function_command():
    arg1 = demisto.args().get('arg1')
    response = sample_function(arg1)
    demisto.results('This is the response - {}'.format(response))
```

**Not This**
```python
def sample_function():
    arg1 = demisto.args().get('arg1')
    response = arg1 + 'is the argument'
    demisto.results('This is the response - {}'.format(response))
```

## Command Functions
Command functions should be split into two functions. We will look at "sample_function" as an example below:

### sample_function
This part of the function should contain all of your business logic such as calling an API, filtering results, and performing queries. 
```python
def sample_function():
    r = http_request()
    res = filter_results(r)
    results = magic_box(res)
    return results
```

### sample_function_command
This is where we will post results in context as well as return the human readable results. The name will always use the "_command" suffix. Additionally, the function should not receive any arguments or parameters in order to work. They should be passed to the ```sample_function``` explicitly.
```python
def sample_function_command():
    results = sample_function()
    human_readable = human_readable_format_tool(results)
    context = context_format_tool(results)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': results,
        'HumanReadable': human_readable,
        'EntryContext': context
    })
```


## Helper Functions
Functions that are minor and serve the purpose of supporting a main function are to be placed towards the top of the integration under the name "HELPER FUNCTIONS". For example:
```python
''' HELPER FUNCTIONS '''
# Returns an item in a list at a given index
def list_tool(item, number):
    if isinstance(item, list):
        return str(item[number])
    else:
        return item
```

## Return Errors, Do Not Raise Them
All code we write is 100% bug free. But on the off chance that a feature works in a way other than intended, we return the error as opposed to raising it. See below:

### Do this:
```return_error(e.message)```
### Not this:
```raise Exception('A new feature has been discovered!')```


## Variable Naming
When we name variables, we prefer to keep them named as below:

### Do this:
```variable_name```

### Not this:
```variableName```

## Outputs
When naming outputs for context, we use the below format:

```Brandname.Object.Property```

For example:
```IPInfo.IP.ASN```

**Please note:** Your integration may have different design requirements. If you are unsure whether to include something in the context, please consult with a content designer.

## Linking Context
Wherever possible, we try to link context together. This will prevent a command from overwriting existing data, or from creating duplicate entries in the context. To do this, observe the following:

```python  
    ec = ({
        'URLScan(val.URL && val.URL == obj.URL)': cont_array,
        'URL': url_array,
        'IP': ip_array,
        'Domain': dom_array
    })
```

In this instance, the ```val.URL && val.URL == obj.URL``` links together the results retrieved from this integration with results already in the context where the value of the URL is the same.

## Logging
In some cases, it may be necessary to pass some information to the logs in order to better assist ourselves with debugging in the future. 

First, we need to ensure that debug level logging is enabled by going to Settings -> About -> Troubleshooting and selecting "Debug" for Log Level.
 
To post to the logs, we use the following:
```
demisto.debug('This is some information we want in the logs')
```

```LOG``` is also available for logging and will print to the logs only when  ```LOG.print_log()``` is executed. This is used to print trace logs.

The ```@logger``` decorator is also available for use in Demisto. When the decorator is placed at the top of each function, the logger will print the function name as well as all of the argument values to the ```LOG```.


## No Printing Sensitive Data To The Log
This should go without saying, however when an integration is ready to be used as part of a public release (meaning you are done debugging it) we **always** remove print statements that are not absolutely necessary.

## Catch Me If You Can
As mentioned above, we only write code with 100% success rates, but we do come across surprise features quite often. Since we don't want a surprise to cause an issue, it is important to wrap your command block in a "Try-Catch" as demonstrated below:

```python
''' EXECUTION '''
LOG('command is %s' % (demisto.command(), ))

try:
    if demisto.command() == 'test-module':
        test_get_session()
        demisto.results('ok')

    if demisto.command() == 'atd-login':
        get_session_command()

except Exception, e:
    return_error(e.message)
```


## Common Server Functions
Before writing a function that seems like a workaround for something that should already exist, check the script helper to see if a function already exists. Examples of Common Server Functions are as noted below:

### fileResult
This will return a file in the War Room by using the syntax below:

```python
filename = "foo.txt",
file_content = "hello foo"

demisto.results(fileResult(filename, file_content))
```

File type can be specified, but defaults to "None" when not provided.

### formatEpochDate
Formats an epoch date to human readable

```python
t = '499137720'
human_readable = formatEpochDate(t)
print human_readable
--> '1985-10-26T01:22:00'

```

### tableToMarkdown
This surprisingly will transform your JSON, dict or other table into Markdown

```python
name = 'Sample Table'
t = {'first':'Foo', 'second': 'bar', 'third': 'baz', 'forth': ''}
headers = ['Input', 'Output']
tableToMarkdown(name, t, headers=headers, removeNull=True)
```
The above will create the table seen below:
| Input  |  Output |
|---|---|
| first  |  foo |
| second  |  bar |
| third  | baz  |

In the War Room, a table would appear as such:
<img width="788" src="https://user-images.githubusercontent.com/42912128/50571324-46846e00-0db0-11e9-9888-ddd9dc275541.png">

You may also use ```headerTransform``` to convert the existing keys into formatted headers.

### demisto.command()
```demisto.command()``` is typically used to tie a function to a command in demisto. see the example below:
```python
    if demisto.command() == 'ip':
        ip_search_command()
```


### demisto.params()
```demisto.params()``` returns a dict of parameters for the given integration. This is used to grab global variables in an integration as seen below:

```python
    APIKEY = demisto.params().get('apikey')
    ACCOUNT_ID = demisto.params().get('account')
    MODE = demisto.params().get('mode')
    INSECURE = demisto.params().get('insecure')
```

### demisto.args()
```demisto.args()``` returns a dict of arguments for a given command. We use this to get non-global variables. See below:

```python
    url = demisto.args().get('url')
```
 The argument above can be seen in the integration settings as shown below:
 
 <img width="644" src="https://user-images.githubusercontent.com/42912128/50575189-ac4d1600-0e01-11e9-83fc-7a8f6f8ce55a.png">
 
 When the command is executed, we see the arguments in the war room as part of the command. See the example below:
 
 <img width="758" src="https://user-images.githubusercontent.com/42912128/50575199-fd5d0a00-0e01-11e9-9d54-944eb7c6f287.png">


### demisto.results()
```demisto.results()``` is used to post a result in the war room and returns different values depending on the entry type or format.

See the following examples:

**Note**
```python
demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': r,
            'HumanReadable': tableToMarkdown('URLScan.io query results for {}'.format(raw_query), hr_md, HUMAN_READBALE_HEADERS, removeNull=True),
            'EntryContext': ec
        })
```

The above produces the following in the war room:
<img width="1203" src="https://user-images.githubusercontent.com/42912128/50571425-8b110900-0db2-11e9-9786-f9d2bcb2d8b6.png">

**JSON**
```python
return {
            'Type': entryTypes['json'],
            'Contents': incidents,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(INCIDETS, outputs, INCIDENTS_HEADERS),
            'EntryContext': {
                'PagerDuty.Incidents(val.ID==obj.ID)': contexts
            }
        }
```

Will produce a JSON entry in the war room as follows:

<img width="572" src="https://user-images.githubusercontent.com/42912128/50571474-877e8180-0db4-11e9-86be-4f87bfe2147e.png">

**Error**
```python
demisto.results({
                  'Type': entryTypes['error'],
                  'ContentsFormat': formats['text'],
                  'Contents': 'Could not find "' + demisto.args().get('lastPackedFileInWarroom', '') + '" file in war room'
              })
```

Will produce an error in the war room as seen below:

<img width="907" src="https://user-images.githubusercontent.com/42912128/50571503-ed6b0900-0db4-11e9-8e9e-dc23f5ff403c.png">


**Note**
```python
demisto.results({
       ‘Type’: entryTypes[‘note’],
       ‘ContentsFormat’: formats[‘markdown’],
       ‘Contents’: results,
       ‘HumanReadable’: human_readable,
       ‘EntryContext’: context
   })
```
Will produce a note in the war room as seen below:

<img width="743" src="https://user-images.githubusercontent.com/42912128/50571514-4cc91900-0db5-11e9-9f89-ae4a607ff2ba.png">

### AutoExtract
As part of ```demisto.results()``` there is a field called ```IgnoreAutoExtract``` which prevents the built-in autoextract tool from enriching IPs, URLs, Files, and other indicators from the result. To use this, see the example below:

```python
demisto.results({
    'Type': entryTypes['note'],
    'ContentsFormat': formats['text'],
    'Contents': command_id,
    'HumanReadable': message,
    'IgnoreAutoExtract': True,
    'EntryContext': {
        'SEPM.Quarantine': context
    }
})
```
**Please Note:** By default, IgnoreAutoExtract is set to ```False```.

## Quality Examples of Integrations
* [McAfee Advanced Threat Defence](https://github.com/demisto/content/blob/master/Integrations/integration-McAfee-ATD.yml)
* [Joe Security](https://github.com/demisto/content/blob/master/Integrations/integration-JoeSecurity.yml)
* [Cybereason](https://github.com/demisto/content/blob/master/Integrations/integration-Cybereason.yml)
* [Anything written by this guy **except** Minemeld](https://github.com/yardensade)
