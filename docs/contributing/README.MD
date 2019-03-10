# Content Contribution Guide

## How to contribute

Demisto content is MIT Licensed and accepts contributions via GitHub pull requests.
If you are a first time GitHub contributor, please look at these links explaining on how to create a Pull Request to a GitHub repo:
* https://guides.github.com/activities/forking/
* https://help.github.com/articles/creating-a-pull-request-from-a-fork/

**Working on your first Pull Request?** You can learn how from this *free* series [How to Contribute to an Open Source Project on GitHub](https://egghead.io/series/how-to-contribute-to-an-open-source-project-on-github)

## Contributing Playbooks

You can edit or create playbooks visually inside the Demisto Platform and then export to a yaml file.

To add a new playbook, or modify and enhance an existing playbook - just open a Pull Request in this repo.

Some requirements for playbooks yaml are:
1. Change playbook version to `-1`
2. Make sure all tasks (including 'Title' task) have a description
3. If the playbook is dependant on some sub-playbook not part of this repo, please add it too in same Pull Request
4. It should be added under the Playbooks folder, using the naming convention starting with prefix `playbook-`

## Contributing Scripts

Each of our scripts comes as a self-contained yaml file that includes the script itself (in Python or Javascript) as well as its description, arguments, and more.

Here is a description of the script yaml format's fields and structure:

``` yaml
commonfields:
  id: TextFromHTML
  version: 1
name: TextFromHTML
script: |-
  import re
  body = re.search(r'<body.*/body>', demisto.args()['html'], re.M + re.S + re.I)
  if body and body.group(0):
      data = re.sub(r'<.*?>', '', body.group(0))
      entities = {'quot': '"', 'amp': '&', 'apos': "'", 'lt': '<', 'gt': '>', 'nbsp': ' ', 'copy': '(C)', 'reg': '(R)', 'tilde': '~', 'ldquo': '"', 'rdquo': '"', 'hellip': '...'}
      for e in entities:
          data = data.replace('&' + e + ';', entities[e])
      demisto.results(data)
  else:
      demisto.results('Could not extract text')
type: python
tags:
- Utility
comment: Extract regular text from the given HTML
system: true
args:
- name: html
  required: true
  default: true
  description: The HTML to strip tags from
scripttarget: 0
dependson: {}
timeout: 0s
```

* id: internal id for the script - make sure it doesn't conflict with an existing script
* name: Name for the script, that will be displayed in the Automation page
* script: The script itself in Python or Javascript
* type: `javascript` or `python`
* tags: array of tags of the script
* comment: A brief description of the script's purpose and any other important things to know - appears in the Automation page and in the CLI autocomplete.
* args: array of script arguments
	* name: argument name
    * description: argument description - appears in automation page and in the CLI autocomplete
    * required: Whether the user must provide this argument to run the script - true for mandatory, false for optional
    * default: (Only one "true" per script) Argument can be provided without its name - e.g. `!whois google.com` instead of `!whois domain=google.com`
* system: "yes" if the script is provided with the platform and is locked and unmodifiable - set to "false" for scripts user creates from within the product.
* scriptTarget: 0 for server script, 1 for agent script (to be run by the Demisto d2 dissolvable agent on the endpoint side)
* dependsOn: The commands required for the script to be used - if these commands are unavailable (e.g. because no integration that implements them has been configured) then the script will not appear in the CLI's autocomplete (it can still be viewed and edited on the Automation page).
* dockerimage: The Docker image name the automation needs to run on, if empty will use default demisto docker image (demisto/python)

Some requirements for scripts yaml are:
1. Make sure it has a description
2. It should be added under the Script folder, using the naming convention starting with prefix `script-`
3. If the script uses some Docker image, make sure it's publicly available on docker hub

## Contributing Integrations

Integrations are build with BYOI feature inside demisto platform, to be later exported to yaml format.

Some requirements for integrations yaml are:
1. Change integration version to `-1`
2. Make sure the integration and each of its commands, inputs and outputs have a description
3. If the integrations uses some Docker image, make sure it's publicly available on docker hub
4. It should be added under the Integrations folder, using the naming convention starting with prefix `integration-`