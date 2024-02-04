# XSOAR-NG End to End Tests
The purpose of XSOAR-NG end-to-end tests is to run basic regression tests for specific integrations. The tests run against a real tenant of XSOAR-NG.

### Prerequisites
The tests use XSOAR-NG client. XSOAR-NG authentication requires api key, api url and api key id.
In order to run the test locally it is required to set up the environment variables for XSOAR-NG machine:
* DEMISTO_BASE_URL
* DEMISTO_API_KEY
* XSIAM_AUTH_ID


### Integration Credentials
In order to run the e2e XSOAR-NG tests it is required to define the required credentials for these tests.
You can create the `integration_secrets.json` file **outside** the content repo.


The structure of the file should be:

```json
{
    "integrations": [
        {"name": "test1", "instance_name": "test1", "params": {"paramA":  "a"}},
        {"name": "test2", "instance_name": "test2", "params": {"paramB":  "b"}}
    ]
}
```

### How to execute (Working directory should be content-root)
```bash
export DEMISTO_BASE_URL=<XSOAR_NG_API_URL>
export DEMISTO_API_KEY=<XSOAR_NG_API_KEY>
export XSIAM_AUTH_ID=<XSOAR_NG_API_KEY_ID>
touch ~/Desktop/integration_secrets.json  # fill up the file according to Integration Credentials section not under content repo!!!!.
python -m pytest Tests/tests_e2e/content/xsoar_saas -v --disable-warnings --integration_secrets_path <path>
```