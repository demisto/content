# Content Contribution Guide

## Contributing Playbooks

Our playbooks are described in an open format we released called [COPS](https://github.com/demisto/COPS) to drive collaboration and interoperability within the InfoSec community.

In order to contribute playbooks you need to save them in the COPS format (as a yaml file) and create a Pull Request.

You can also edit them visually inside the Demisto Platform and then export to a yaml file.

To add a new playbook, or modify and enhance an existing playbook - just open a Pull Request in this repo.

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

If you have a suggestion or an opportunity for improvement that you've identified, please open an issue in this repo.
Enjoy and feel free to reach out to us on the [DFIR Community Slack channel](https://www.demisto.com/community/), or at [info@demisto.com](mailto:info@demisto.com)
