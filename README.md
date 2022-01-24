![Content logo](xsoar_content_logo.png)

[![CircleCI](https://circleci.com/gh/demisto/content.svg?style=svg)](https://circleci.com/gh/demisto/content)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/demisto/content.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/demisto/content/context:python)
[![Open in Visual Studio Code](https://open.vscode.dev/badges/open-in-vscode.svg)](https://open.vscode.dev/demisto/content)

# Cortex XSOAR Platform - Content Repository
#### Demisto is now Cortex XSOAR.
This repo contains content provided by Demisto to automate and orchestrate your Security Operations. Here we will share our ever-growing list of playbooks, automation scripts, report templates and other useful content.

We security folks love to tinker, keep enhancing and sharpening our toolset and we decided to open up everything and make it a collaborative process for the entire security community. We want to create useful knowledge and build flexible, customizable tools, sharing them with each other as we go along.

We invite you to use the playbooks and scripts, modify them to suit your needs and see what works for you, get involved in the community discussion and of course remember to give back and contribute so that others can enjoy and learn from your hard work and build upon it to enhance it even further.

## Documentation
If you wish to develop and contribute Content, make sure to check our Content Developer Portal at: https://xsoar.pan.dev/

## Contributing
Contributions are welcome and appreciated. For instructions about adding/modifying content please see our [Content Contribution Guide](https://xsoar.pan.dev/docs/contributing/contributing).


## Playbooks
The Cortex XSOAR Platform includes a visual playbook editor - you can add and modify tasks, create control flow according to answers returned by your queries, and automate everything with your existing security tools, services and products. You can also export your work to a file in the COPS format, and import playbooks shared by your peers who have done the same.

We will be releasing more and more playbooks for interesting scenarios, so stay tuned. If you are working on an interesting playbook of your own, feel free to send us a Pull Request and let's build it together.

The spec for our open playbook format, COPS, can be found [here](https://github.com/demisto/COPS).

## Scripts
These scripts written in Python or Javascript perform Security Operations tasks.
The scripts are built to run inside the Cortex XSOAR Platform - they can query or send commands to a long list of existing security products, and react based on the output.

You can take your logic and the way you want to work and write your own scripts, allowing for maximum flexibility.
The services and products you use can be online Cloud-based or on-premises setups, and we have tools to support more complex topologies such as when the product's subnet is firewalled off.

## Integrations
Integrations written in Javascript or Python enable the Cortex XSOAR Platform to orchestrate security and IT products. Each integration provides capabilities in the form of commands and each command usually reflects a product capability (API) and returns both a human readable and computer readable response.

## Docker
We use docker to run python scripts and integrations in a controlled environment. You can configure an existing docker image from the [Cortex XSOAR Docker Hub Organization](https://hub.docker.com/u/demisto/) or create a new docker image to suite your needs. More information about how to use Docker is available [here](https://demisto.pan.dev/docs/docker). 

## Reports
Cortex XSOAR Platform support flexible reports written in JSON. All of our standard reports calculating various incident statistics and metrics are stored in this repo.


