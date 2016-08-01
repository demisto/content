# Content Contribution Guide

## Contributing Playbooks

Our playbooks are described in an open format which we released called [COPS](https://github.com/demisto/COPS) to drive collaboration and interoperability within the InfoSec community. 

In order to add playbooks you need to save them in the open playbook format(yaml file) and create a Pull Request. 

You can also edit them visually inside the Demisto Platform and export to a yaml file.

Also you can create a PR to modify an existing playbook.

## Contributing Scripts

In addition to the actual scripts in a Py or JS file, you need to add a small section in the scripts.json file, with the script's display name, description, arguments and other metadata. 
Here is a description of scripts.json fields and structure:

``` json
{
            "name": "RemoteExec",
            "script": "RemoteExec.js",
            "type": "javascript",
            "visualScript": "",
            "tags": ["endpoint"],
            "arguments": [
                {
                    "name": "system",
                    "description": "Name of system on which to run the command",
                    "required": true,
                    "default": false
                },
                {
                    "name": "cmd",
                    "description": "Command to run",
                    "required": true,
                    "default": false
                }
            ],
            "comment": "Execute a command on a remote machine (without installing a D2 agent)",
            "system": true,
            "scriptTarget": 0,
            "dependsOn": { "must": ["ssh"] }
},
```

Enjoy and feel free to reach out to us on the DFIRCommunity Slack, or at using this repo issues.

