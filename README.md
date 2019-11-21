![Content logo](demisto_content_logo.png)

[![CircleCI](https://circleci.com/gh/demisto/content.svg?style=svg)](https://circleci.com/gh/demisto/content)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/demisto/content.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/demisto/content/context:python)

# Demisto Platform - Content Repository
This repo contains content provided by Demisto to automate and orchestrate your Security Operations. Here we will share our ever-growing list of playbooks, automation scripts, report templates and other useful content.

We security folks love to tinker, keep enhancing and sharpening our toolset and we decided to open up everything and make it a collaborative process for the entire security community. We want to create useful knowledge and build flexible, customizable tools, sharing them with each other as we go along.

We invite you to use the playbooks and scripts, modify them to suit your needs and see what works for you, get involved in the community discussion and of course remember to give back and contribute so that others can enjoy and learn from your hard work and build upon it to enhance it even further.


## Demisto
- For more information about Demisto you can visit [here](https://www.paloaltonetworks.com/cortex/demisto)
- To join our community please visit [Demisto Community](https://go.demisto.com/join-our-slack-community)
- We have Partners website - visit [here](https://demisto.developers.paloaltonetworks.com/)
- For Demisto Components, Concepts, and Terminology visit [here](https://support.demisto.com/hc/en-us/articles/360005126713-Demisto-Components-Concepts-and-Terminology)

## Contributing
Contributions are welcome and appreciated. For instructions about adding/modifying content please see our [Content Contribution Guide](CONTRIBUTING.md).

### Creating an Integration
Let's look at Demisto and get started on your first integration.

[Follow the steps here to learn about the Demisto IDE](docs/getting_started)

### Code Conventions
The Demisto Code Conventions will help you understand how we format our Integrations and some of the tips and tricks we have developed over the years.

[Learn about the Demisto Code Conventions](docs/code_conventions)
 
### Context and Outputs
The Demisto platform relies heavily on collecting data from various endpoints (integrations) and creating a "Context" for them. This allows customers to be able to use the data to perform various tasks they may need to accomplish.

[Click here to learn about Context and Outputs](docs/context_and_ouputs)

### Context Standards
When we are working with data that is generic across all platforms, we format them according to our context standards. This helps integrations work interchangeably inside other playbooks.

[Learn about our Context Standards here](docs/context_standards)

### Docker
We use docker to run python scripts and integrations in a controlled environment. You can configure an existing docker image from the [Demisto Docker Hub Organization](https://hub.docker.com/u/demisto/) or create a new docker image to suite your needs. More information about how to use Docker is available here:

[Docker Images](docs/docker)

## Release Notes
For information about content release notes conventions, refer to our [release notes documentation](docs/release_notes).


# Documentation Directory

| Link | Description |
| --- | ---|
| [Getting Started](docs/getting_started) | Environment setup and a brief explanation of the Demisto IDE |
| [Package directory](docs/package_directory_structure) | Explanation of Python integration / automation script package directory structure |
| [Code Conventions](docs/code_conventions) | Our Code Conventions |
| [Linting](docs/linting) | How to run linting on Demisto integrations/scripts |
| [Unit Testing](docs/tests/unit-testing) | Explanation of How to Perform Unit Testing on Integrations/Scripts |
| [Integration Parameter Types](docs/parameter_types) | Description of the various integration parameter types |
| [Context and Outputs](docs/context_and_ouputs) | Brief overview of Context and Outputs |
| [Context Conventions](docs/context_standards) | Conventions for the Demisto Standard Context |
| [Contributing](CONTRIBUTING.md) | How to contribute to the Content Repo |
| [Creating Playbooks](docs/creating_playbooks) | How to create a Playbook |
| [DBot Score](docs/dbot) | How the DBot Score works |
| [Demisto Transform Language (DT)](docs/DT) | Understanding Demisto Transform Language (DT) |
| [Docker](docs/docker) | How to use Docker |
| [Fetching Incidents](docs/fetching_incidents) | How to Fetch Incidents |
| [Fetching Credentials](docs/fetching_credentials) | How to Fetch Credentials |
| [Integration Documentation](docs/integration_documentation) | How to generate documentation for an integration |
| [YAML File](docs/yaml-file-integration) | Explanation of the Demisto YAML structure |
| [Testing](docs/tests) | The Demisto Content Repo Testing Methods |
| [CircleCI](docs/tests/circleci) | How we test using CircleCI |
| [Mocks](docs/tests/mocks) | Explanation of how to test using mocked data |
| [GenericPolling Playbook](docs/genericpolling) | Explanation of how and when to use the GenericPolling playbook |
| [Release Notes](docs/release_notes) | Explanation of our content release notes conventions |

---
Enjoy and feel free to reach out to us on the [DFIR Community Slack channel](https://www.demisto.com/community/), or at [info@demisto.com](mailto:info@demisto.com).
