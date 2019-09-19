# Overview
The purpose of standardising our code conventions is to ensure uniformity among all integrations. This section outlines some of the code conventions that we, here at Demisto, use.


## Imports 
- Defined at the top of the file 
- Disable insecure warnings
```python
import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
```

## Constants 
- Defined at the top of the file below the imports. 
- Don't define here global variables - only constants

```python
''' CONSTANTS '''
API_SUFFIX = "/api/v1/suffix"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
```

**Please restrain from naming constants as shown below**
```python
apiVersion = "v1"
url = demisto.params().get("url")
```

## Main function 
- Create `main` function and in the main extract all the integration parameters
- Implement **_command** function for each integration command (e.g. `say_hello_command(client, demisto.args())`)
- Wrap the commands with try/except in the main, in order to handle the exceptions properly. `return_error()` receives error message and returns error entry back into Demisto. It will also print the full error to the Demisto logs. 
- For logs use `demisto.info()`, `demisto.debug()`, and `LOG()` functions.
- In the main function, initialize the Client instance, and pass that client to `_command` functions.
```python
def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # Remove trailing slash to prevent wrong URL path to service
    server_url = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']

    verify_certificate = not demisto.params().get('insecure', False)

    # How many time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days')

    proxies = handle_proxy()

    LOG('Command being called is %s' % (demisto.command()))

    try:
        client = Client(server_url, verify_certificate, username, password, proxies)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_outputs(result, None)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'helloworld-say-hello':
            return_outputs(*say_hello_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error("Failed to execute {} command. Error: {}".format(), e)
        raise


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
```


## Client class
- Client is necessary in order to prevent passing arguments from function to function and prevent using global variables
- Client will contain `http_request` function
- Client will implement the 3rd party service API
- Client will contain all the necessary params to establish connection and authentication with the 3rd party API.

```python
class Client:
    """
    Client will implement the service API, should not contain Demisto logic.
    Should do requests and return data
    """
    def __init__(self, url, verify, username, password, proxies=None):
        self.base_url = "{}{}".format(url, API_SUFFIX)
        self.verify = verify
        self.username = username
        self.password = password
        self.proxies = proxies

    def http_request(self, method, url_suffix, params=None, data=None):
        full_url = self.base_url + url_suffix

        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            params=params,
            json=data,
            auth=(self.username, self.password),
            proxies=self.proxies
        )

        if res.status_code not in [200, 204]:
            raise ValueError('Error in API call to url [%s]. Status Code: [%d]. Reason: %s' % (full_url, res.status_code, res.text))

        try:
            return res.json()
        except Exception:
            raise ValueError(
                "Failed to parse http response to JSON format. Original response body: \n{}".format(res.text))

    def say_hello(self, name):
        return "Hello {}".format(name)

    def say_hello_http_request(self, name):
        """
        initiates a http request to test url
        """
        data = self.http_request("GET", "/hello/" + name)
        return data["result"]

    def list_incidents(self):
        """
        returns dummy incident data, just for the example.
        """
        return [
            {
                "incident_id": 1,
                "description": "Hello incident 1",
                "created_time": datetime.utcnow().strftime(DATE_FORMAT)
            },
            {
                "incident_id": 2,
                "description": "Hello incident 2",
                "created_time": datetime.utcnow().strftime(DATE_FORMAT)
            }
        ]
```

## Command Functions
- Each integration command should have corresponding `_command` function
- **_command** function should use `Client` class functions
- **_command** function should be unit testable - it means avoid usage of global functions like `demisto.results()`, `return_error()`, `return_outputs()`
- **_command** function will receive `client` instance and `args` (`demisto.args()` dictionary)
- **_command** function will return 3 variables, readable_output, outputs, raw_response
- In the `main` use `return_outputs(*say_hello_command(client, demisto.args()))` to extract the outputs and return them to warroom.
```python
def say_hello_command(client: Client, args):
    name = args.get('name')

    result = client.say_hello(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = "## {}".format(result)
    outputs = {
        "hello": result
    }

    return (
        readable_output,
        outputs,
        result # raw response - the original response
    )


def main():
    """
    SOME CODE HERE...
    """
    try:
        client = Client(server_url, verify_certificate, username, password, proxies)
        
        """
        SOME CODE HERE...
        """
        if demisto.command() == 'helloworld-say-hello':
            return_outputs(*say_hello_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error("Failed to execute {} command. Error: {}".format(), e)
        raise
```

## test-module
- `test-module` will execute when the **Test** button pressed in the integration instance setting page.
- if test module returns the string `"ok"` then the test will be green success, any other string the test will show red.
```python
if demisto.command() == 'test-module':
    # This is the call made when pressing the integration Test button.
    result = test_module(client)
    return_outputs(result, None)
```
```python
def test_module(client: Client):
    """
    returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.
    """
    result = client.say_hello("DBot")
    if "Hello DBot" == result:
        return 'ok'
    else:
        return 'Test failed because ......'
```

## fetch-incidents
- [fetch-incidents](https://github.com/demisto/content/blob/master/docs/fetching_incidents/README.md) will be executed if `Fetch incidents` checkbox in the integration settings will be enabled. This function will be executed periodically.
- Must be unit testable
- Should receive `last_run` param instead of executing `demisto.getLastRun()`
- Should return `next_run` back to main, instead of executing `demisto.setLastRun()` inside the `fetch_incidents` function
- Should return `incidents` back to main instead of executing `demisto.incidents()` inside the `fetch_incidents` function
```python
def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each 1 minute.

    :return: next_run, list of incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT)

    incidents = []
    items = client.list_incidents()
    for item in items:
        incident_created_time = item["created_time"]
        incident = {
            "name": item["description"],
            "occurred": datetime.strptime(incident_created_time, "%Y-%m-%dT%H:%M:%SZ"),
            "rawJSON": json.dumps(item)
        }

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > last_fetch:
            last_fetch = incident_created_time
            incidents.append(incident)

    next_run = {"last_fetch": last_fetch}
    return next_run, incidents

def main():
    """
    SOME CODE HERE
    """
    try:
        client = Client(server_url, verify_certificate, username, password, proxies)

        if demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    # Log exceptions
    except Exception as e:
        return_error("Failed to execute {} command. Error: {}".format(), e)
        raise
```


## Exceptions and Errors
- Since we don't want a surprise to cause an issue, it is important to wrap your command block in a "Try-Catch" as demonstrated below:
- Raise exceptions anywhere you need in the code, but in the main catch them and use `return_error` - this way you will return nice error message to warroom istead of stack trace.
- `return_error` second argument is error, you can pass Exception object.
- You can always `demisto.error("some error message")` log your error
```python
def main():
    try:
        if demisto.command() == 'test-module':
            test_get_session()
            demisto.results('ok')
    
        if demisto.command() == 'atd-login':
            get_session_command()
    
    except Exception as e:
        return_error(str(e), e)
```


## Unit Tests
Every integration must have unit tests.

- Unit test must be in separate file called the same as the integration but with `_test.py` for example `HelloWorld_test.py`
- In order to mock http requests use [requests_mock](https://requests-mock.readthedocs.io/en/latest/)
- For mocks use [mocker](https://github.com/pytest-dev/pytest-mock/)

For example:
```python
from HelloWorld import Client, say_hello_command, say_hello_over_http_command


def test_say_hello():
    client = Client(url="https://test.com", verify=False, username="test", password="test")
    args = {
        "name": "Dbot"
    }
    _, outputs, _ = say_hello_command(client, args)

    assert outputs["hello"] == "Hello Dbot"


def test_say_hello_over_http(requests_mock):
    mock_response = {"result": "Hello Dbot"}
    requests_mock.get("https://test.com/api/v1/suffix/hello/Dbot", json=mock_response)

    client = Client(url="https://test.com", verify=False, username="test", password="test")
    args = {
        "name": "Dbot"
    }
    _, outputs, _ = say_hello_over_http_command(client, args)

    assert outputs["hello"] == "Hello Dbot"
```

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
For more information about the syntax of linking and Demisto Transform Language in general have a look [here](https://github.com/demisto/internal-content/tree/master/documentation/DT) 

## Logging
In some cases, it may be necessary to pass some information to the logs in order to better assist ourselves with debugging in the future. 

First, we need to ensure that debug level logging is enabled by going to Settings -> About -> Troubleshooting and selecting "Debug" for Log Level.
 
To post to the logs, we use the following:
```python
demisto.debug('This is some information we want in the logs')
```

```LOG``` is also available for logging and will print to the logs only when  ```LOG.print_log()``` is executed. This is used to print trace logs.
```python
try:
    LOG('message 1')
    if demisto.command() == 'virustotal-get-ip':
        LOG('message 2')
        get_ip_command()

except Exception, ex:
    LOG(ex.message)
    LOG.print_log() # all the above messages will be printed to logs only when LOG.print_log() executed
```

The ```@logger``` decorator is also available for use in Demisto. When the decorator is placed at the top of each function, the logger will print the function name as well as all of the argument values to the ```LOG```.
```python
@logger
def get_ip(ip):
    ip_data = http_request('POST', '/v1/api/ip' + ip)
    return ip_data
```

## No Printing Sensitive Data To The Log
This should go without saying, however when an integration is ready to be used as part of a public release (meaning you are done debugging it) we **always** remove print statements that are not absolutely necessary.


## Dates
We do not use epoch time for customer facing results (Context, Human Readable, etc.). If the API you are working with requires the time format to be in epoch, then convert the date string into epoch as needed. Where possible, use the human readable format of date ```%Y-%m-%dT%H:%M:%S```

```python
time_epoch = 499137720
formatted_time = timestamp_to_datestring(time_epoch, "%Y-%m-%dT%H:%M:%S")
print(formatted_time)
>>> '1985-10-26T01:22:00'
```

**Please note:** If the response returned is in epoch, it is best practices to convert it to ```%Y-%m-%dT%H:%M:%S```

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


### return_outputs
```return_outputs``` is used to return results to warroom
    
See the following examples:

**Note**
```python
def return_outputs(readable_output, outputs, raw_response=None):
    """
    This function wraps the demisto.results(), makes the usage of returning results to the user more intuitively.

    :type readable_output: ``str``
    :param readable_output: markdown string that will be presented in the warroom, should be human readable -
        (HumanReadable)

    :type outputs: ``dict``
    :param outputs: the outputs that will be returned to playbook/investigation context (originally EntryContext)

    :type raw_response: ``dict`` | ``list``
    :param raw_response: must be dictionary, if not provided then will be equal to outputs. usually must be the original
    raw response from the 3rd party service (originally Contents)

    :return: None
    :rtype: ``None``
    """
    
return_outputs("## Some h2 header", {"some": "json into context"}, {"some":"raw JSON/dict"})
```


**Error**
```python
return_error(message="error has occured: API Key is incorrect", error=ex)
```

Will produce an error in the war room as seen below:

<img width="907" src="https://user-images.githubusercontent.com/42912128/50571503-ed6b0900-0db4-11e9-8e9e-dc23f5ff403c.png">


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
* [Proofpoint TAP v2](https://github.com/demisto/content/tree/master/Integrations/ProofpointTAP_v2)
