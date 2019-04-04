![Content logo](demisto_content_logo.png)

[![CircleCI](https://circleci.com/gh/demisto/content.svg?style=svg)](https://circleci.com/gh/demisto/content)

# Demisto Platform - Content Repository
This repo contains content provided by Demisto to automate and orchestrate your Security Operations. Here we will share our ever-growing list of playbooks, automation scripts, report templates and other useful content.

We security folks love to tinker, keep enhancing and sharpening our toolset and we decided to open up everything and make it a collaborative process for the entire security community. We want to create useful knowledge and build flexible, customizable tools, sharing them with each other as we go along.

We invite you to use the playbooks and scripts, modify them to suit your needs and see what works for you, get involved in the community discussion and of course remember to give back and contribute so that others can enjoy and learn from your hard work and build upon it to enhance it even further.


## Playbooks
The Demisto Platform includes a visual playbook editor - you can add and modify tasks, create control flow according to answers returned by your queries, and automate everything with your existing security tools, services and products. You can also export your work to a file in the COPS format, and import playbooks shared by your peers who have done the same.

We will be releasing more and more playbooks for interesting scenarios, so stay tuned. If you are working on an interesting playbook of your own, feel free to send us a Pull Request and let's build it together.

The spec for our open playbook format, COPS, can be found [here](https://github.com/demisto/COPS).

## Scripts
These scripts written in Python or Javascript perform Security Operations tasks.
The scripts are built to run inside the Demisto Platform - they can query or send commands to a long list of existing security products, and react based on the output.

You can take your logic and the way you want to work and write your own scripts, allowing for maximum flexibility.
The services and products you use can be online Cloud-based or on-premises setups, and we have tools to support more complex topologies such as when the product's subnet is firewalled off.

## Integrations
Integrations written in Javascript or Python enable the Demisto Platform to orchestrate security and IT products. Each integration provides capabilities in the form of commands and each command usually reflects a product capability (API) and returns both a human readable and computer readable response.

### Creating an Integration
Let's look at Demisto and get started on your first integration.

[Follow the steps here to learn about the Demisto IDE](https://github.com/demisto/content/blob/master/docs/getting_started/README.MD)

### Code Conventions
The Demisto Code Conventions will help you understand how we format our Integrations and some of the tips and tricks we have developed over the years.

[Learn about the Demisto Code Conventions](https://github.com/demisto/content/blob/master/docs/code_conventions/README.MD)
 
### Context and Outputs
The Demisto platform relies heavily on collecting data from various endpoints (integrations) and creating a "Context" for them. This allows customers to be able to use the data to perform various tasks they may need to accomplish.

[Click here to learn about Context and Outputs](https://github.com/demisto/content/blob/master/docs/context_and_ouputs/README.MD)

### Context Standards
When we are working with data that is generic across all platforms, we format them according to our context standards. This helps integrations work interchangeably inside other playbooks.

[Learn about our Context Standards here](https://github.com/demisto/content/blob/master/docs/context_standards/README.MD)

### Docker
In some cases, it will be necessary to create a docker image to enable your integration to run. When this happens, we must create a new docker image using the steps outlined here:

[Create a Docker Image](https://github.com/demisto/content/blob/master/docs/docker/README.MD)
## Reports
Demisto Platform support flexible reports written in JSON. All of our standard reports calculating various incident statistics and metrics are stored in this repo.

## Contributing Content
For instructions about adding/modifying playbooks and scripts please see our [contributor guide](https://github.com/demisto/content/blob/master/docs/contributing/README.MD).

Enjoy and feel free to reach out to us on the [DFIR Community Slack channel](https://www.demisto.com/community/), or at [info@demisto.com](mailto:info@demisto.com)

## Git configuration
Copy the pre-commit hook from .hooks to .git/hooks. Run the following command from the repository root:

```sh
cp .hooks/* .git/hooks
```

# Documentation Directory

| Link | Description |
| --- | ---|
| [Tutorial Video](https://github.com/demisto/content/blob/master/docs/tutorial-video/README.md) | A step-by-step introduction to creating an integration |
| [Getting Started](https://github.com/demisto/content/blob/master/docs/getting_started/README.MD) | A brief explanation of the Demisto IDE |
| [Code Conventions](https://github.com/demisto/content/blob/master/docs/code_conventions/README.MD) | Our Code Conventions |
| [Context and Outputs](https://github.com/demisto/content/blob/master/docs/context_and_ouputs/README.MD) | Brief overview of Context and Outputs |
| [Context Conventions](https://github.com/demisto/content/blob/master/docs/context_standards/README.MD) | Conventions for the Demisto Standard Context |
| [Contributing](https://github.com/demisto/content/blob/master/docs/contributing/README.MD) | How to contribute to the Content Repo |
| [Creating Playbooks](https://github.com/demisto/content/blob/master/docs/creating_playbooks/README.MD) | How to create a Playbook |
| [DBot Score](https://github.com/demisto/content/blob/master/docs/dbot/README.md) | How the DBot Score works |
| [Demisto Transform Language (DT)](https://github.com/demisto/content/blob/master/docs/DT/README.MD) | Understanding Demisto Transform Language (DT) |
| [Docker](https://github.com/demisto/content/blob/master/docs/docker/README.MD) | How to use Docker |
| [Fetching Incidents](https://github.com/demisto/content/blob/master/docs/fetching_incidents/README.md) | How to Fetch Incidents |
| [Fetching Credentials](https://github.com/demisto/content/blob/master/docs/fetching_credentials/README.md) | How to Fetch Credentials |
| [Integration Documentation](https://github.com/demisto/content/blob/master/docs/integration_documentation/README.MD) | How to generate documentation for an integration |
| [YAML File](https://github.com/demisto/content/blob/master/docs/yaml-file-integration/README.MD) | Explanation of the Demisto YAML structure |
| [Integration Parameter Types](https://github.com/demisto/content/blob/master/docs/parameter_types/README.md) | Description of the various integration parameter types |
