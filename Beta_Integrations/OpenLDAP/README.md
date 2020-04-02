## Overview
---
This integration enables using your OpenLDAP user authentication settings in Demisto. Users can log in to Demisto with their OpenLDAP username and passwords, and their permissions in Demisto will be set according to the groups and mapping set in AD Roles Mapping.  


## Use Cases
---
Use OpenLDAP user authentication groups to set user roles in Demisto.


## Configure OpenLDAP on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for OpenLDAP.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server IP or Host Name (e.g. 192.168.0.1)__
    * __Port. If not specified, default port is 389, or 636 for LDAPS.__
    * __User DN (e.g cn=admin,ou=users,dc=domain,dc=com)__
    * __Base DN (e.g. DC=domain,DC=com)__
    * __Auto populate groups__
    * __Groups Object Class__
    * __Groups Unique Identifier Attribute__
    * __Group Membership Identifier Attribute__
    * __User Object Class__
    * __User Unique Identifier Attribute__
    * __Page size__
    * __Connection Type__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.


## Additional Information
---
Steps required for setting AD roles Mapping:

1. Create OpenLDAP child entry of `User Account` template under wanted `Organisational Unit` and `Posix Group`, with `uid` as part of DN:
![user](https://user-images.githubusercontent.com/45535078/71556364-722c4980-2a40-11ea-850a-4b556f5f0f4b.png)


2. Create OpenLDAP child entry of `Posix Group` template, with created account from step 1 as `memberUid`:
![group](https://user-images.githubusercontent.com/45535078/71556408-04345200-2a41-11ea-8368-6eb430c1aa93.png)


3. In case of using different attributes and class/group templates (different `objectClass`), customize the following default values in instance configuration:
    * __Groups Object Class__
    * __Groups Unique Identifier Attribute__
    * __Group Membership Identifier Attribute__
    * __User Object Class__
    * __User Unique Identifier Attribute__

4. Navigate to __Settings__ > __USERS AND ROLES__ > __ROLES__.

5. Chose Role.

6. Add the created group from step 2 to `AD Roles Mapping`.
![mapping](https://user-images.githubusercontent.com/45535078/71556645-ee745c00-2a43-11ea-90da-764d0543f1ca.png)


7. Login to Demisto using `uid` or full DN and password of creted user from step 1. 


