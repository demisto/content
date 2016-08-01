# Demisto Platform - Content Repository
This repo contains content provided by Demisto to automate and orchestrate your Security Operations. Here we will share our ever-growing list of playbooks, automation scripts, report templates and other useful content.
We security folks love to tinker, keep enhancing and sharpening our toolset and we decided to open up everything and make it a collaborative process for the entire security community. We want to create useful knowledge and build flexible, customizable tools, sharing them with each other as we go along.
We invite you to use the playbooks and scripts, modify them to suit your needs and see what works for you, get involved in the community discussion and of course remember to give back and contribute so that others can enjoy and learn from your hard work and build upon it to enhance it even further.


## Playbooks
The Demisto Platform includes a visual playbook editor - you can add and modify tasks, create control flow according to answers returned by your queries, and automate everything with your existing security tools, services and products. You can also export your work to a file in the open playbook format, and import playbooks shared by your peers who have done the same.

We will be releasing more and more playbooks for interesting scenarios, so stay tuned. If you are working on an interesting playbook of your own, feel free to send us a Pull Request and let's build it together.

The spec for our new format can be found here:

## scripts
These scripts written in Python or Javascript that perform Security Operations tasks. The scripts are built to run inside the Demisto Platform - they can query or send commands to a long list of existing security products, and react based on the output. You can take your logic and the way you want to work and write your own scripts, allowing for maximum flexibility.
The services and products you use can be online Cloud-based or on-premises setups, and we have tools to support more complex topologies such as when the product's subnet is firewalled off.

# Adding content
## Adding Playbooks
Our playbooks are described in an open format which we are releasing to drive collaboration and interoperability within the InfoSec community. We realize every organization has different needs and we wanted to create something that allows for that flexibility.

In order to add playbooks you need to save them in the open playbook format and send a Pull Request. You can also edit them visually inside the Demisto Platform and export to a file.

## Adding Scripts
In addition to the actual scripts in a py or js file, you need to add a small section in the `scripts.json` file, with the script's display name, description, arguments and other metadata.
Here is a description of `scripts.json` fields and structure:


Enjoy and feel free to reach out to us on the DFIRCommunity Slack, or at <email-here>
