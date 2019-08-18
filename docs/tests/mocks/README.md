# Mocks

## Overview
The mocking mechanism enables recording and playback of traffic to a file, instead of sending traffic to the integration
instance.

The mocking mechanism is not used for tests that have no integrations.

## Configuration
Currently, the only configuration option for the mocking mechanism is to exclude integrations from it.
You can do this by adding the **integration id** and a reason to the **unmockable_integrations** dictionary in **Tests/conf.json**

## Mocking mechanism outputs in CircleCI
When a CircleCI build is triggered, the mocking mechanism will print information in the "Run Tests" section:

**Test run**

When a test run starts, you can see the mocking mechanism method that is being used with the test.

Example:

`------ Test playbook: MISP V2 Test with integration(s): MISP V2 start ------ (Mock: Playback)`

The mocking mechanism method will appear at the end of the line, possible methods:
- Playback - A mock file exists and is being used to simulate responses.
- Recording - A new mock file is being recorded, the real instance is being used.
- Disabled - The mocking mechanism is bypassed entirely, only the real instance is being used.


If test fails while using a mock file to simulate responses, you will see the following line in the test run:

`Test failed with mock, recording new mock file.`

**Test Summary**

In the test summary, there are three sections that are relevant to mocking:
- **Failed Tests** that did not use the mocking mechanism are marked with `(Mock Disabled)`
- **Tests with failed playback and successful re-recording**
- **Successful tests with empty mock files** - Tests in this section had a problem using the mocking mechanism:

  Either there were no http requests or no traffic is passed through the proxy. Investigate the playbook and the integrations. If the integration has no http traffic, add to unmockable_integrations in conf.json.

- **Unmockable Integrations** - This section lists all integrations that do not use the mocking mechanism, along with reasons for that.


## How it works
**Prerequisite Knowledge**

- In our CI process, an AMI machine is created. It runs the Demisto service.
- Python integrations run on docker.
- Docker containers communicate with the outside world using a network bridge between the container and the host (in our case, the AMI machine).
- **Mitmproxy** is an open source proxy application that allows intercepting HTTP and HTTPS connections between any HTTP(S) client.


**The Juicy Part**

Mitmproxy is installed on the AMI machine. For every test that does not bypass the mocking mechanism:
1. The proxy service starts running (in recording or playback mode, depending on if a mock file exists).
2. Demisto is configured with the IP of docker bridge on the AMI's side.
3. Proxy and Unsecure parameters are set to "True".
4. The test playbook is run.

If a test failure occurs during playback, the same procedure is done, only in recording mode.
If a test failure occurs during recording, the test is marked as a failure.


## Identifying and debugging a problematic integration/test
**If the integration bypasses the mocking mechanism**

Check that the integration is configured not to run through proxy by default.


**Symptoms of a problematic test**
- Test keeps failing when the mocking mechanism is in "recording" mode.
- Test succeeds, but keeps appearing in the *Tests with failed playback and successful re-recording* section
- Test succeeds, but keeps appearing in the *Successful tests with empty mock files* section


## Troubleshooting
1. Add the integrations of the test to `unmockable_integrations` in conf.json.
If it still fails, the problem is likely unrelated to the mocking meachanism.
2. Identify the problem and apply the solution from the table below:

    | Symptom | Problem  | Solution |
    | ------------- | ------------- | ------------- |
    | Mock file is empty | Test/Integration is not sending requests by design  | Add to unmockable_integrations with this reason  |
    | Mock file is empty / connection errors | "Proxy" logic is faulty/inverted/non-existent | fix/add the logic or explain in unmockable_integrations  |
    | Errors regarding unauthorized/invalid certificate | "Unsecure" logic is faulty/inverted/non-existent | fix/add the logic or explain in unmockable_integrations  |
    | Playback fails, recording succeeds, integration and playbook were not changed | Playbook is sending requests that don't have responses in the playback file | Modify the test to send consistent requests, or bypass the mocking mechanism |

3. (Temporary) If a problem still exists, please contact @BenJoParadise to check if the problem is caused by the mocking mechanism.  

# Debugging a problematic integration / playbook
In order to fix an integration/playbook so it will work with the mocking mechanism, please follow these steps
## Setting up a test environment
1. Install mitmproxy on your local environment by running `brew install mitmproxy`
2. Find your IP by running `ifconfig en0 inet`
3. In Demisto, go to settings -> about -> troubleshooting and enter the following details:
    * http_proxy: `http://<Your IP>:9997`
    * https_proxy: `http://<Your IP>:9997`
4. run `/reset_containers` in the CLI.

## Running the test
To start the proxy server, run `mitmdump -k -v -p 9997` or `mitmproxy -k -v -p 9997` (for more information)

If you want to use a web-gui interface you can run: `mitmweb  -p 9997 --web-port 7070 -k  -v`

You can see the proxy traffic (and errors) in the terminal window where you ran the command.

To stop the proxy server, click **control + c**

Depending on the issue, you may need to preform one or some of the following steps:
* Run instance test with proxy/unsecure parameters checked/unchecked
* With proxy and unsecure enabled, run the test playbook or the problematic integration command.
