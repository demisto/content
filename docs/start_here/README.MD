# Welcome!
First and foremost, welcome to Demisto! We are happy to have you join our team. There are some things to know when it comes to the Demisto platform and the outline below should help you get started on the right foot.

If you have *ANY* questions, just ask. We will be more than happy to help you!

## Getting Started
If you have not already, set up your local instance for development. This part will take two steps, pulling and building the master version of the server, and pulling and building the web client.

We have some prebuilt scripts that will automate the steps outlined in the above two steps located below:

[Bash scripts for setting up your environment](https://github.com/demisto/etc/tree/master/bash_files)

### Manual Installation
[Set up your environment and build the server](https://github.com/demisto/server#demisto-server-component-in-golang)

[Build the web client](https://github.com/demisto/web-client#getting-started)

***

## Creating an Integration
After you have done the above, we will look at Demisto and get started on your first integration.

[Follow the steps here to learn about the Demisto IDE](/documentation/getting_started/README.MD)


## Code Conventions
The Demisto Code Conventions will help you understand how we format our Integrations and some of the tips and tricks we have developed over the years.

[Learn about the Demisto Code Conventions](/documentation/code_conventions/README.MD)
 
## Context and Outputs
The Demisto platform relies heavily on collecting data from various endpoints (integrations) and creating a "Context" for them. This allows customers to be able to use the data to perform various tasks they may need to accomplish.

[Click here to learn about Context and Outputs](/documentation/context_and_ouputs/README.MD)

## Context Standards
When we are working with data that is generic across all platforms, we format them according to our context standards. This helps integrations work interchangeably inside other playbooks.

[Learn about our Context Standards here](/documentation/context_standards/README.MD)

## Docker
In some cases, it will be necessary to create a docker image to enable your integration to run. When this happens, we must create a new docker image using the steps outlined here:

[Create a Docker Image](/documentation/docker/README.MD)

## The Integration YAML File
Demisto formats the integration as a YAML file. This allows us to set parameters that may not be available for a customer such as Tests, Server Version, and locking the integration from future changes.

[Learn about the YAML file here](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BThe-YAML-File%5D)

## Tests
Demisto uses CircleCI to provide testing for our integrations. This means when we create an integration, we must also create a test playbook.

[Learn about Test Playbooks here](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BTests%5D)

## Documentation
Documentation is how we tell a customer how the integration will work. It also serves as the first point for others to debug issues that may arise with your code (which never happens since we write bug-free code)

[Learn about Documentation here](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BDocumentation%5D)

## Contributing
Finally, you have had a design review, a code review and made sure that your integration is not going to sneak any "surprise features" into Demisto. You are ready to push your code.

[Learn about sending your code to the burning pits of wrath](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BContributing%5D)