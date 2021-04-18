# XSOAR - Simple Dev to Prod

This pack enables a simple Dev to Prod workflow for your XSOAR **custom content** items, such as playbooks, automations, BYOI integrations, custom fields, etc.  

You can use this pack to select and export your custom content to a zip, which can be manually imported into production, or you can use the Demisto REST API to automate the whole thing. 

It includes a pair of playbooks which should be run as Jobs in XSOAR, to export a selected custom content bundle, or enable an automated push of custom content from your XSOAR Development Server to the XSOAR Production Server.  For more information on jobs you can refer to the XSOAR documentation on [XSOAR Jobs](https://xsoar.pan.dev/docs/incidents/incident-jobs).


## Setup Instructions

The **JOB - XSOAR - Export Selected Custom Content** playbook makes it easy to quickly select only the custom content items you want to move to your production server!  Simply download the xsoar-custom-content.zip file from the Dev to Prod tab, and import on your production server under Settings -> Advanced -> Troubleshooting -> Import Custom Content.

To begin, you need to setup the following:

1. Ensure your **Common Scripts** Pack is updated via the Marketplace.  This pack makes use of the ZipFile automation from that pack.

2. Create an instance of the Demisto REST API integration for your XSOAR Development Server, where the instance name is **Demisto Dev**.

4. Create a Job on your Dev XSOAR Server, with the type set to **XSOAR Dev to Prod**, using the playbook **JOB - XSOAR - Export Selected Custom Content** (this is the default).

5. Run the job to select and export custom content items, you can download the zip file via the Dev to Prod tab on the layout.

## Optional - Push Custom Content to Prod

This pack also includes another playbook which can remove the manual effort of uploading custom content.  However this requires that your XSOAR Development Server have connectivity to the REST API of your XSOAR Production server on port 443.  Note that firewalls or WAFs between the XSOAR servers could potentially impact this push. 

The **JOB - XSOAR - Simple Dev to Prod** playbook uses an instance of the Demisto REST API integration that is configured against your XSOAR Production Server to enable pushing the custom content you select via the REST API.  

To begin, you need to setup the following:

1. Ensure your **Common Scripts** Pack is updated via the Marketplace.  This pack makes use of the ZipFile automation from that pack.

2. Create an instance of the Demisto REST API integration on your XSOAR Development Server, where the instance name is **Demisto Dev**.  

3. Create an instance of the Demisto REST API integration on your XSOAR Development Server, *for your XSOAR Production Server*, where the instance name is **Demisto Prod**.  
    * The instance configuration, select "Do not use by default", see below for more details.
    * The instance should point to the resolveable URL for the prod server, and requires an API KEY generated on the prod server.

4. Create a Job on your Dev XSOAR Server, with the type set to **XSOAR Dev to Prod**, using the playbook **JOB - XSOAR - Simple Dev to Prod**

5. Run the job to select custom content items to push to production, the playbook will ask you to confirm the items you selected, will take a backup of the custom content from Production, and then push to prod!


### Additional Recommended Settings 

If you are intending to use the **JOB - XSOAR - Simple Dev to Prod** playbook for the automated push to production, I recommend the following additional settings on your Development Server:

1. Set the server configuration **ignore.default.in.playbooks = true**, which prevents playbook tasks from using integration instances which are marked as "Do not use by default".
    * This ensures any other playbooks in your Development Server which use the Demisto Rest API integration don't try and use the Demisto Prod instance that you may have setup as part of this pack.
    * The "Do not use by default" setting also ensures that users running manually Demisto Rest API integration commands via the Command Line Interface (CLI) don't use the Demisto Prod instance by mistake.

2. Restrict access to the Demisto Prod integration instance commands to approved XSOAR Administrators.  This can be done via Settings -> Users and Roles -> Integration Permissions.  Refer to the XSOAR Administrator guide for [Integration Permissions](https://docs.paloaltonetworks.com/content/techdocs/en_US/cortex/cortex-xsoar/6-1/cortex-xsoar-admin/users-and-roles/integration-permissions.html#ida5e08d7e-348a-402b-bbfc-d051212913c0) for more details.
    * Permissions on the Demisto Prod instance should be restricted to users in the appropriate XSOAR roles (e.g. Administrators)
    * Note that restricting access will not prevent the playbooks from running, this is simply a good security best practice.


## Marketplace Packs

Please note that this workflow is only for **custom content**.  If your custom content makes use of packs from the Marketplace, then you should ensure to install the required Packs on your production server, along with any configurations (e.g. integration instances) required on the production server to allow use of the custom content you are exporting. 

