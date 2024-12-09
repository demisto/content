# Doppel XSOAR Pack

## Overview

Doppel is a Modern Digital Risk Protection Solution, that detects the phishing and brand cyber attacks on the emerging channels. Doppel scans millions of channels online which includes, social media, domains, paid ads, dark web, emerging channels, etc. Doppel can identify the malicious content and cyber threats, and enables their customers to take down the digital risks proactively.

## Features supported by the Doppel XSOAR pack

1. Mirror Incidents- Alerts from Doppel are mirrored as per the configured schedule.
2. Command: Create Alert- Command to create an alert in Doppel.
3. Command: Get Alert- Command to fetch alert details from Doppel.
4. Command: Get Alerts- Command to fetch list of alerts from Doppel.
5. Command: Update Alert- Command to update alert details from Doppel.
6. Command: Create Abuse Alert-Command to create abuse alert details from Doppel.

## Setup local Development environment for modifying the Doppel pack

1. Clone the XSOAR content Github repository to your local machine
2. Open the content directory in VS Code.
3. Install [XSOAR extension for VS Code](https://xsoar.pan.dev/docs/concepts/vscode-extension) as mentioned in this XSOAR documentation
4. Execute the command *XSOAR: install local development environment*, either from VSCode Command Pallete, or by right-clicking a file.
5. Create a Python virtual environment and install demisto-sdk with following commmand:
   `pip install demisto-sdk`
6. Go to the integration or a script. Right-click it, and select Setup integration/script environment. If this command is successful, you will notice that the 4 debug configurations are created in the .vscode/launch.json.
   1. Docker: Debug (Doppel)
   2. Docker: Debug tests (Doppel)
   3. *Python: Debug Integration locally*
   4. Python: Debug Tests
   
7. Put breakpoint in the source code and try to launching *Python: Debug Integration locally* debug configurations.
8. The breakpoint should get hit, however, as you do not have params, commands and arguments configured, the program will though an exception.

## Configure the Demisto params, command and arguments

While debugging the integration script, you want make sure that the integration configuration (URL and API Key) and command with it's input are picked automatically without an hardcoded source code. Please follow below steps to configure the environment for the same:

### Setup Integration configuration

1. Go to /vscode/launch.json.
2. In the *Python: Debug Integration locally* configuration please initialize the following variables. Please do not remove any other environment variables if there are already any.
   `
   "env": {
            "DEMISTO_PARAMS": "{\"url\": \"https://api.doppel.com\",\"credentials\": {\"password\": \"<API-KEY>\"}}"
         },
   `
3. With above variable, `demisto.params()` function will give you corrent app configuration


### Setup commands and arguments for debugging

1. Create a file `/content/Packs/Doppel/Integrations/Doppel/.args_command.json`
2. Decide which command you want to debug and initialize the file.
3. For example if you want to debug the `get-alert` command with input argument for `id` equals to `TST-31`, you should have the following content in the file:
   `{
    "cmd": "get-alert",
    "id": "TST-31"
   }`
4. Click on the debug button for *Python: Debug Integration locally*. The breackpoint will hit and you will get the correct params, command and args while debugging.


## Test the pack on XSOAR tenant

Once you have made sure the commands are working as expected and now you want to test the commands on the actual XSOAR tenant, you need to perform the following steps:

### Connect your local dev environment to XSOAR tenant

1. Press `Ctrl+shift+p` and run *XSOAR: Configure XSOAR Connection*
2. Enter the XSOAR Server Connection details.
3. We used the XSOAR API key to setup the connection that can be generated from XSOAR tenant by going to:
   `Settings and info >> Settings >> Integrations >> API Keys`

### Upload the pack to XSOAR tenant

Upload the current app pack to XSOAR tenant using the following command:
    `demisto-sdk upload -i Packs/Doppel`
    OR
    `demisto-sdk upload -i Packs/Doppel --insecure` if you do not want to validate the certificate while uploading the pack.
The above command will upload and install the pack on your XSOAR tenant. You can configure and test the new features.


## Unit test

It is important that all the Unit tests pass before we push the latest modification to the pack.

1. To run the unit tests, you need to make sure you have following dependencies installed in your virtual envirionment
    `pip install requests-mock`
    `pip install pytest-mock`
2. Change directory to `Packs/Doppel/Integrations/Doppel`
3. Run the following command to execute all unit tests
   `pytest`

