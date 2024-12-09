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
1. Go to /vscode/launch.json.
2. 
   