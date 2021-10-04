# Using the templates:
Every category of integration has a unique, corresponding template. Copy the integration from its folder to a new folder under `Integrations`.
Each template contains standard commands (such as `!ip` and `!file`), outputs (such as DBotScore, IP, Email, etc.).

It also contains examples of how to use basic Demisto functions (such as return_outputs and assign_params) and Demisto code conventions.

Use the template as a guideline and feel free to modify as needed.
# Using the BaseClient:
## Overview
The BaseClient class is meant to contain all of the HTTP requests made to the API. It is used as a wrapper to the API. **Do not use the BaseClient as it is, use a new `Client` class as demonstrated below**.
Commands in the BaseClient should call the private `BaseClient._http_request` method.
## Initiate the BaseClient
#### Parameters:
* *base_url (str)* **required**:  
    Base server address with suffix, for example: https://example.com/api/v2/.
* *verify (bool)*: 
    Whether the request should verify the SSL certificate. **Default is `True`**.
* *proxy (bool)*: 
    Whether to run the integration using the system proxy. **Default is `False`**.
* *ok_codes (tuple)*:
    The request codes to accept as OK, for example: (200, 201, 204). 
    If you specify `None`, will use requests.Response.ok. **Default is `None`**
* *headers (dict)*:
    The request headers, for example: `{'Accept': 'application/json'}`.
    **Default is `None`**
* *auth (dict or tuple)*:
    The request authorization, for example: (username, password).
    **Default is `None`**
#### Example:
```python
base_client = BaseClient(
    'https://example.com/api/v2/',
    verify=False,
    proxy=True,
    ok_codes=(200, 201, 204),
    headers={'Authorization': 'Bearer <TOKEN>'}
)
```

### **the _http_request method**
_http_request is a universal method that can handle any request and throw standard errors if needed. The format is such that users (and the developers) can understand.
#### Parameters:
* method (str) **required**:
    The HTTP method, for example, GET, POST, and so on.

* url_suffix: (str) **required**
    The API endpoint.

* full_url (str)
    Bypasses the use of self._base_url + url_suffix. This is useful if you need to
    make a request to an address outside of the scope of the integration
    API. **Default is `None`**

* headers (dict):
    Headers to send in the request. If None, will use self._headers. **Default is `None`**

* auth (tuple):
    The authorization tuple (usually username/password) to enable Basic/Digest/Custom HTTP Auth.
    if None, will use self._auth. **Default is `None`**

* params (dict):
    URL parameters to specify the query. **Default is `None`**

* data (dict):
    The data to send in a 'POST' request. **Default is `None`**

* json_data (dict):
    The dictionary to send in a 'POST' request. **Default is `None`**.

* files (dict):
    The file data to send in a 'POST' request. **Default is `None`**.

* timeout: (float):
    The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. **Default is `10`**.

* resp_type (str):
    Determines which data format to return from the HTTP request. The default
    is 'json'. Other options are 'text', 'content', 'xml' or 'response'. Use 'response'
        to return the full response object. **Default is `json`**.

* ok_codes (tuple):
    The request codes to accept as OK, for example: (200, 201, 204). If you specify
    `None`, will use self._ok_codes. **Default is `None`**.

The method returns depends on the resp_type parameter
can be ``dict``, ``str``, ``requests.Response`` or ``ElemntTree``

# How to use in integration:
Never use raw `BaseClient`. Base client is meant to be inherited from.
### Example:
```python
class Client(BaseClient):
    def get_something(self, id_of_something: str) -> dict:
        suffix = 'something'
        params = {
            'somethingId': id_of_something
        }
        return self._http_request('GET', suffix, params=params)

def get_something_command(client: Client, args: Dict) -> Tuple(str, dict, dict):
    id_of_something = args.get('id')
    raw_response = client.get_something(id_of_something)
    if raw_response:
        # Transform information into Output and readable_output
        return readable_output, output, raw_response
    return f'No results for something ID: {id_of_something}', None, None

def main():
    command = demisto.command()
    params = demisto.params()
    verify = params.get('verify') == 'true'
    proxy = params.get('verify') == 'false' 
    client = Client(
    'https://example.com/api/v2/',
    verify=verify,
    proxy=proxy,
    ok_codes=(200, 201, 204),
    headers={'Authorization': 'Bearer <TOKEN>'}
    )

    # Switch case
    commands = {
        'get-something': get_something_command
    }
    return_outputs(*commands[command](client, demisto.args()))

if __name__ == 'builtins':
    main()
```

### Break in to code flow:
1. **Running main:**
   ```python
    # Runs main when running command in Demisto
    if __name__ == 'builtins':
        main()
    ```
2. **Setting up enviroment in main function:**
   ```python
   def main():
        # Gets command name from demisto, lets say command is 'get-something'
        command = demisto.command()

        # Gets parameters from demisto.params
        params = demisto.params()
        verify = params.get('verify') == 'true'
        proxy = params.get('verify') == 'false' 

        # Initiate Client object
        client = Client(
        'https://example.com/api/v2/',
        verify=verify,
        proxy=proxy,
        ok_codes=(200, 201, 204),
        headers={'Authorization': 'Bearer <TOKEN>'}
        )

        # Switch case, commands dict
        commands = {
            'get-something': get_something_command
        }
        
        # Run the command 
        return_outputs(*commands[command](client, demisto.args()))
    ```
3. **Running the desired command:**
   ```python
   def get_something_command(client: Client, args: Dict) -> Tuple(str, dict, dict):
        # Gets argument from args
        id_of_something = args.get('id')
        # Run the request from the client
        raw_response = client.get_something(id_of_something)
        if raw_response:
            # Transform information into Output and readable_output
            do something...
            return readable_output, outputs, raw_response
        return f'No results for something ID: {id_of_something}', None, None
    ```
4. **Setting up arguments for `_http_request` and running function:**
   ```python
       def get_something(self, id_of_something: str) -> dict:
        suffix = 'something'
        params = {
            'somethingId': id_of_something
        }
        return self._http_request('GET', suffix, params=params)
    ```
5. **Collapsing back to the `return_outputs` function**
