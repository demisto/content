# XSIAM End to End Tests
The purpose of XSIAM end to end tests is to run basic regression tests. The tests run against a real tenant of XSIAM, 
check for total number of packs. 


### Prerequisites
The tests use XSIAM client. XSIAM authentication requires api key, api url and api key id.
You need to pass 3 arguments to the tests.

**--cloud_machine (string)** - tenant name, for example *test_machine*, a string indicates a specific tenant. should be consistent with other files (cloud_servers_path, cloud_servers_api_keys)

**--cloud_servers_path (file path)** - a path to a json file that contains XSIAM tenant authentication details, like api url. Example:
```json
{
    "test_machine": {
        "demisto_version": "8.3.0",
        "base_url": "https://api-test-machine.us.test.com",
        "x-xdr-auth-id": "101"
    }
}
```

**--cloud_servers_api_keys (file path)** - a path to a json file that contains XSIAM tenant API Key.
Example:
```json
{
    "test_machine": "PUT_HERE_A_REAL_API_KEY"
}
```

### How to execute
```bash
python -m pytest Tests/tests_end_to_end_xsiam -v --disable-warnings --cloud_machine machine1 --cloud_servers_path Tests/tests_end_to_end_xsiam/test_cloud_server_path.json --cloud_servers_api_keys Tests/tests_end_to_end_xsiam/test_cloud_api_keys.json
```