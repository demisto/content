Ansible is an IT automation tool. You can use it to configure systems, deploy software, and orchestrate more advanced IT tasks such as continuous deployments or zero downtime rolling updates.
Ansible Tower is a commercial offering that helps teams manage complex multi-tier deployments by adding control, knowledge, and delegation to Ansible-powered environments.

1. Set up Ansible Tower: <https://docs.ansible.com/ansible-tower/latest/html/quickstart/index.html> 
2. Make sure to remember the TOWER_SERVER_NAME and credentials specified during the installation process since you will need it to set up your integration.

Use the Ansible Tower login information to configure the integration: 

Server URL: https://<TOWER_SERVER_NAME>/
username: the username as specified during the installation process.
password: the value specified for admin_password in your inventory file.

Important!

Role-Based Access Controls (RBAC) are built in to Tower and allow different roles to perform different actions. You may receive an error message when you try to run some commands just based on your user permission.
For more information regarding the different system roles and their permissions, see <https://docs.ansible.com/ansible-tower/latest/html/userguide/security.html> (27.2.3.1 section).
