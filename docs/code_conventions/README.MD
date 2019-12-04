# Python Code Conventions
We use standardized code conventions to ensure uniformity across all Demisto Integrations. This section outlines our code conventions.

New integrations and scripts should follow these conventions. When working on small fixes and modifications to existing code, follow the conventions used in the existing code.

**Note:** Demisto supports also JavaScript integrations and scripts. Our preferred development language is Python, and all new integrations and scripts should be developed in Python, which also provides a wider set of capabilities compared to the available JavaScript support. Simple scripts may still be developed in JavaScript using the conventions provided by the default script template used in the Demisto IDE.

## Example Code and Templates
For an example of a **Hello World** integration see [HelloWorld](../../Integrations/HelloWorld/).

For quick starts templates see [Templates directory](../../Templates).

## Python 2 vs 3
All new integrations and scripts should be written in Python 3. Python 2 is supported only for existing integrations and scripts.

## Imports 
You define imports and disable insecure warning at the top of the file.
```python
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
```

## Constants 
You define constants in the file below the imports. It is important that you do not define global variables in the constants section.

```python
''' CONSTANTS '''
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
```

**IMPORTANT**: The example below shows the incorrect way to name constants.
```python
apiVersion = "v1"
url = demisto.params().get("url")
```

## Main function 
These are the best practices for defining the Main function.
- Create the `main` function and in the main extract all the integration parameters.
- Implement the **_command** function for each integration command (e.g., `say_hello_command(client, demisto.args())`)
- To properly handle exceptions, wrap the commands with try/except in the main. The `return_error()` function receives error message and returns error entry back into Demisto. It will also print the full error to the Demisto logs. 
- For logging, use the `LOG("write some log here")` function.
- In the main function, initialize the Client instance, and pass that client to `_command` functions.
```python
def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # Remove trailing slash to prevent wrong URL path to service
    base_url = urljoin(demisto.params()['url'], '/api/v1/suffix')

    verify_certificate = not demisto.params().get('insecure', False)

    # How many time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

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
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
```


## Client class
These are the best practices for defining the Client class.
- Client should inherit from **BaseClient**. **BaseClient** defined in **CommonServerPython**.
- Client is necessary in order to prevent passing arguments from one function to another function, and to prevent using global variables.
- Client will contain the `_http_request` function.
- Client will implement the 3rd party service API.
- Client will contain all the necessary params to establish connection and authentication with the 3rd party API.

```python
class Client(BaseClient):
    """
    Client will implement the service API, should not contain Demisto logic.
    Should do requests and return data
    """

    def say_hello(self, name):
        return f'Hello {name}'

    def say_hello_http_request(self, name):
        """
        initiates a http request to test url
        """
        data = self._http_request(
            method='GET',
            url_suffix='/hello/' + name
        )
        return data.get('result')

    def list_incidents(self):
        """
        returns dummy incident data, just for the example.
        """
        return [
            {
                'incident_id': 1,
                'description': 'Hello incident 1',
                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
            },
            {
                'incident_id': 2,
                'description': 'Hello incident 2',
                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
            }
        ]
```

## Command Functions
These are the best practices for defining the command functions.
- Each integration command should have a corresponding `_command` function.
- Each **_command** function should use `Client` class functions.
- Each **_command** function should be unit testable. This means you should avoid using global functions, such as `demisto.results()`, `return_error()`, or `return_outputs()`.
- The **_command** function will receive `client` instance and `args` (`demisto.args()` dictionary).
- The **_command** function will return 3 variables: readable_output, outputs, raw_response
- To extract the outputs and return them to the War Room, in the `main` use `return_outputs(*say_hello_command(client, demisto.args()))`.
```python
def say_hello_command(client, args):
    """
    Returns Hello {somename}

    Args:
        client: HelloWorld client
        args: all command arguments

    Returns:
        Hello {someone}

        readable_output: This will be presented in Warroom - should be in markdown syntax - human readable
        outputs: Dictionary/JSON - saved in incident context in order to be used as input for other tasks in the
                 playbook
        raw_response: Used for debugging/troubleshooting purposes - will be shown only if the command executed with
                      raw-response=true
    """
    name = args.get('name')

    result = client.say_hello(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'hello': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def main():
    """
    SOME CODE HERE...
    """
    try:
        client = Client(
            base_url=server_url, 
            verify=verify_certificate, 
            auth=(username, password),
            proxy=proxy)
        
        """
        SOME CODE HERE...
        """
        if demisto.command() == 'helloworld-say-hello':
            return_outputs(*say_hello_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')
```


## IOC Reputation Commands
There are two implementation requirements for reputation commands (aka `!file`, `!email`, `!domain`, `!url`, and `!ip`) that are enforced by checks in the [hook_validations](../../Tests/scripts/hook_validations/integration.py).
- The reputation command's argument of the same name must have `default` set to `True`.
- The reputation command's argument of the same name must have `isArray` set to `True`.

For more details on these two command argument properties look at the [yaml-file-integration/README.md](../../docs/yaml-file-integration/README.MD#commands) in our `docs` folder.


## test-module
- When users click the **Test** button, the `test-module` will execute when the **Test** button pressed in the integration instance setting page.
- If the test module returns the string `"ok"` then the test will be green (success). All other string will be red.
```python
if demisto.command() == 'test-module':
    # This is the call made when pressing the integration Test button.
    result = test_module(client)
    demisto.results(result)
```
```python
def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test
    """

    result = client.say_hello('DBot')
    if 'Hello DBot' == result:
        return 'ok'
    else:
        return 'Test failed because ......'
```

## fetch-incidents
These are the best practices for defining fetch-incidents.
- The [fetch-incidents](https://github.com/demisto/content/blob/master/docs/fetching_incidents) function will be executed when the `Fetch incidents` checkbox is selected in the integration settings. This function will be executed periodically.
- The fetch-incidents function must be unit testable.
- Should receive the `last_run` param instead of executing the `demisto.getLastRun()` function.
- Should return `next_run` back to main, instead of executing `demisto.setLastRun()` inside the `fetch_incidents` function.
- Should return `incidents` back to main instead of executing `demisto.incidents()` inside the `fetch_incidents` function.
```python
def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client: HelloWorld client
        last_run: The greatest incident created_time we fetched from last fetch
        first_fetch_time: If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = last_fetch
    incidents = []
    items = client.list_incidents()
    for item in items:
        incident_created_time = dateparser.parse(item['created_time'])
        incident = {
            'name': item['description'],
            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents

def main():
    """
    SOME CODE HERE
    """
    try:
        client = Client(
            base_url=server_url, 
            verify=verify_certificate, 
            auth=(username, password),
            proxy=proxy)

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
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')
```


## Exceptions and Errors
These are the best practices for defining the exceptions and errors.
- To avoid unexpected issues, it is important to wrap your command block in a "Try-Catch". See the example below.
- Raise exceptions in the code where needed, but in the main catch them and use the `return_error` function. This will enable acceptable error messages in the War Room, instead of stack trace.
- If the `return_error` second argument is error, you can pass Exception object.
- You can always use `demisto.error("some error message")` to log your error.
```python
def main():
    try:
        if demisto.command() == 'test-module':
            test_get_session()
            demisto.results('ok')
    
        if demisto.command() == 'atd-login':
            get_session_command()
    
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')
```


## Unit Tests
Every integration must have unit tests.

- Unit tests must be in a separate file, which should have the same name as the integration but be appended with `_test.py` for example `HelloWorld_test.py`
- To mock http requests use [requests_mock](https://requests-mock.readthedocs.io/en/latest/).
- For mocks use [mocker](https://github.com/pytest-dev/pytest-mock/).

For example:
```python
from HelloWorld import Client, say_hello_command, say_hello_over_http_command


def test_say_hello():
    client = Client(
        base_url="https://test.com", 
        verify=False, 
        auth=("test", "test"),
        proxy=False)

    args = {
        "name": "Dbot"
    }
    _, outputs, _ = say_hello_command(client, args)

    assert outputs["hello"] == "Hello Dbot"


def test_say_hello_over_http(requests_mock):
    mock_response = {"result": "Hello Dbot"}
    requests_mock.get("https://test.com/api/v1/suffix/hello/Dbot", json=mock_response)

    client = Client(
        base_url="https://test.com", 
        verify=False, 
        auth=("test", "test"),
        proxy=False)

    args = {
        "name": "Dbot"
    }
    _, outputs, _ = say_hello_over_http_command(client, args)

    assert outputs["hello"] == "Hello Dbot"
```

## Variable Naming
When naming variables use the following convention.

### Do this:
```variable_name```

### Do not do this:
```variableName```

## Outputs
When naming outputs for context use the following convention.

```Brandname.Object.Property```

For example:
```IPInfo.IP.ASN```

Make sure you read and understand [Context and Outputs](https://github.com/demisto/content/blob/master/docs/context_and_ouputs).

Make sure you follow our [context standards](https://github.com/demisto/content/tree/master/docs/context_standards) when naming indicator outputs.

#### Linking Context
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
For more information about the syntax of linking and Demisto Transform Language in general have a look [here](https://github.com/demisto/content/blob/master/docs/context_and_ouputs) 

## Logging
In some cases, it may be necessary to pass information to the logs to assist future debugging. 

First, we need to ensure that the debug level logging is enabled. Go to **Settings -> About -> Troubleshooting** and select **Debug** for Log Level.
 
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

You can also use the ```@logger``` decorator in Demisto. When the decorator is placed at the top of each function, the logger will print the function name as well as all of the argument values to the ```LOG```.
```python
@logger
def get_ip(ip):
    ip_data = http_request('POST', '/v1/api/ip' + ip)
    return ip_data
```

## Do No Print Sensitive Data to The Log
This section is critical.When an integration is ready to be used as part of a public release (meaning you are done debugging it), we **ALWAYS** remove print statements that are not absolutely necessary.


## Dates
We do not use epoch time for customer facing results (Context, Human Readable, etc.). If the API you are working with requires the time format to be in epoch, then convert the date string into epoch as needed. Where possible, use the human readable format of the date ```%Y-%m-%dT%H:%M:%S```

```python
time_epoch = 499137720
formatted_time = timestamp_to_datestring(time_epoch, "%Y-%m-%dT%H:%M:%S")
print(formatted_time)
>>> '1985-10-26T01:22:00'
```

**Note:** If the response returned is in epoch, it is a best practice to convert it to ```%Y-%m-%dT%H:%M:%S```.

## Common Server Functions
Before writing a function that seems like a workaround for something that should already exist, check the script helper to see if a function already exists. Examples of Common Server Functions are noted below:

### fileResult
This will return a file to the War Room by using the following syntax:

```python
filename = "foo.txt",
file_content = "hello foo"

demisto.results(fileResult(filename, file_content))
```

You can specify the file type, but it defaults to "None" when not provided.


### tableToMarkdown
This will transform your JSON, dict, or other table into a Markdown table.

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

In the War Room, this is how a table will appear:
<img width="788" src="https://user-images.githubusercontent.com/42912128/50571324-46846e00-0db0-11e9-9888-ddd9dc275541.png">

You may also use ```headerTransform``` to convert the existing keys into formatted headers.

### demisto.command()
```demisto.command()``` is typically used to tie a function to a command in Demisto, for example:
```python
    if demisto.command() == 'ip':
        ip_search_command()
```


### demisto.params()
```demisto.params()``` returns a dict of parameters for the given integration. This is used to grab global variables in an integration, for example:

```python
    APIKEY = demisto.params().get('apikey')
    ACCOUNT_ID = demisto.params().get('account')
    MODE = demisto.params().get('mode')
    INSECURE = demisto.params().get('insecure')
```

### demisto.args()
```demisto.args()``` returns a dict of arguments for a given command. We use this to get non-global variables, for example:

```python
    url = demisto.args().get('url')
```
 The argument above can be seen in the integration settings as shown below:
 
 <img width="644" src="https://user-images.githubusercontent.com/42912128/50575189-ac4d1600-0e01-11e9-83fc-7a8f6f8ce55a.png">
 
 After the command is executed, the arguments are displayed in the War Room as part of the command, for example:
 
 <img width="758" src="https://user-images.githubusercontent.com/42912128/50575199-fd5d0a00-0e01-11e9-9d54-944eb7c6f287.png">


### return_outputs
```return_outputs``` is used to return results to the War Room, for example:
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

Will produce an error in the War Room, for example:

<img width="907" src="https://user-images.githubusercontent.com/42912128/50571503-ed6b0900-0db4-11e9-8e9e-dc23f5ff403c.png">


### AutoExtract
As part of ```demisto.results()``` there is a field called ```IgnoreAutoExtract```, which prevents the built-in auto-extract tool from enriching IPs, URLs, files, and other indicators from the result. For example:

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
**Note:** By default, IgnoreAutoExtract is set to ```False```.

## Quality Examples of Integrations
* [Proofpoint TAP v2](https://github.com/demisto/content/tree/master/Integrations/ProofpointTAP_v2)
