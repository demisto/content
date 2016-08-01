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

* name: Name for the script, that will be displayed in the Automation page
* script: The actual file name
* type: javascript or python
* tags: array of tags of the script
* arguments: array of script arguments
            * name: argument name
            * description: argument description - appears in automation page and in the CLI autocomplete
            * required: Whether the user must provide this argument to run the script - yes for mandatory, no for optional
            * default: (Only one "yes" per script) Argument can be provided without its name - e.g. !whois google.com instead of !whois domain=google.com
* comment: A brief description of the script's purpose and any other important things to know - appears in the Automation page and in the CLI autocomplete.
* system: "yes" if the script is provided with the platform and is locked and unmodifiable - set to "no" for scripts user creates from within the product.
* scriptTarget: 0 for server script, 1 for agent script (to be run on endpoint)
* dependsOn: depdencies on other scripts/integrations

Enjoy and feel free to reach out to us on the DFIRCommunity Slack, or at using this repo issues.
