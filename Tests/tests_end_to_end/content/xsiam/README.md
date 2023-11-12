# XSIAM End to End Tests
The purpose of XSIAM end-to-end tests is to run basic regression tests. The tests run against a real tenant of XSIAM, 
check for total number of packs. 


### Prerequisites
The tests use XSIAM client. XSIAM authentication requires api key, api url and api key id.
In order to run the test locally it is required to set up the environment variables for XSIAM machine:
* DEMISTO_BASE_URL
* DEMISTO_API_KEY
* XSIAM_AUTH_ID


### How to execute (Working directory should be content-root)
```bash
export DEMISTO_BASE_URL=<XSOAR_NG_API_URL>
export DEMISTO_API_KEY=<XSOAR_NG_API_KEY>
export XSIAM_AUTH_ID=<DEMISTO_API_KEY_ID>
python -m pytest Tests/tests_end_to_end/xsiam -v --disable-warnings --cloud_machine machine1 --cloud_servers_path Tests/tests_end_to_end/xsiam/test_cloud_server_path.json --cloud_servers_api_keys Tests/tests_end_to_end/xsiam/test_cloud_api_keys.json
```