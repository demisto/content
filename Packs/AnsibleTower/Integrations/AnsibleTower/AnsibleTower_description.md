Ansible is an IT automation tool. It can configure systems, deploy software, and orchestrate more advanced IT tasks such as continuous deployments or zero downtime rolling updates.
Ansible Tower is a commercial offering that helps teams manage complex multi-tier deployments by adding control, knowledge, and delegation to Ansible-powered environments.

1. Setup Ansible Tower: <https://docs.ansible.com/ansible-tower/latest/html/quickstart/index.html> 
2. Once you setup Ansible Tower you holds TOWER_SERVER_NAME and credentials specified during the installation process.

Use the above login information to configure the integration: 

Server URL: https://<TOWER_SERVER_NAME>/
username: the username as specified during the installation process.
password: the password is the value specified for admin_password in your inventory file.

Important!

Role-Based Access Controls (RBAC) are built in to Tower and allow different roles to perform different actions. You may receive an error message for some commands you aim to run just based on your user permission.
For more information regarding the different system roles and their permissions, you can access <https://docs.ansible.com/ansible-tower/latest/html/userguide/security.html> (27.2.3.1 section)