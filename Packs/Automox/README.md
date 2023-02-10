# Automox Content Pack for XSOAR
The Automox Content Pack for XSOAR empowers users by providing the resources to administrate your IT organization, and remediate vulnerabilities with ease. Use the Automox integration to create device groups, update devices, and run policies. This content pack also includes a sub-playbook to use in your vulnerability remediation workflows to identify vulnerable devices, and automatically generate the remediation tasks necessary to patch them in the Automox platform.

# What does this pack do?
- Upload Vulnerability Reports
- Get and approve/reject batches of tasks
- Get, update, and delete device groups
- Get and update devices
- Get organizations and their users
- Get and run policies

This pack includes:
- Integrations:
    - **Automox**: Administrate your IT organization from XSOAR with comprehensive commands for the Automox platform.
- Playbooks:
    - **Upload Vulnerability Report to Automox**: This sub-playbook enables you to upload vulnerability data with ease. This playbook accepts the entryId of a vulnerability report CSV, and uploads it to Automox. After upload, remediation tasks are identified and created automatically for affected devices.
