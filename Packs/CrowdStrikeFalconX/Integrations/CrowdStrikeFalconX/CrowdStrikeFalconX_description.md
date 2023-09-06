## CrowdStrike Falcon Intelligence Sandbox
To create a client ID and client secret (the password in the integration) refer to [CrowdStrike Falcon X API Client and keys](https://falcon.crowdstrike.com/support/api-clients-and-keys).

The process for submitting files contains 2 commands:
* cs-fx-upload-file
* cs-fx-submit-uploaded-file
First we upload the file and retrieve its SHA256 hash. Then, we use that ID to upload the file to the sandbox.
If you want to upload a file to the sandbox in a single command, use the cs-fx-upload-file and supply the following argument and value: submit_file=yes.

For more information on CrowdStrike Falcon Intelligence Sandbox, see the [CrowdStrike Falcon Intelligence Sandbox FAQ](https://www.crowdstrike.com/endpoint-security-products/falcon-x-threat-intelligence/crowdstrike-falcon-x-faq/).

Notice: Submitting indicators using the **cs-fx-submit-url** command of this integration might make the indicator data publicly available.  See the vendor’s documentation for more details
