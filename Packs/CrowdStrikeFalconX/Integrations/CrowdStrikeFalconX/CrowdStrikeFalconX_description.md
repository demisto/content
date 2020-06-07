## CrowdStrike Falcon X
In order to crate a client ID and client secret (the password in the integration) please use the instructions here:

The submitting file process contains 2 commands:
* cs-fx-upload-file
* cs-fx-submit-uploaded-file
First we upload the file and getting its sha256, then using that identification to upload the file to the sandbox.
If you wish to upload a file to the sandbox in one command, please use cs-fx-upload-file with the argument submit_file=yes.

For more information on CrowdStrike Falcon X, see the [CrowdStrike Falcon X FAQ](https://www.crowdstrike.com/endpoint-security-products/falcon-x-threat-intelligence/crowdstrike-falcon-x-faq/).

