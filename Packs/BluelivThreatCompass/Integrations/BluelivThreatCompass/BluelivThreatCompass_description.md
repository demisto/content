## Blueliv ThreatCompass
Some important things to take into account about the integration:
- The _login user_ must be _dedicated_ to Cortex XSOAR. In every call, Cortex XSOAR will have to re-login to the platform and for every login, Blueliv will automatically log out all other user sessions.
- There are three important parameters in the integration instance configuration:
    - **Organization ID**: can be found in the GUI URL. Iit is the number after the key "organizations". For example: for https://demisto.blueliv.com/dashboard/organizations/8/indexed the Organization ID will be 8.
    - **Module ID**: can be found in the GUI URL. It is the number after the key "modules". For example: for https://demisto.blueliv.com/dashboard/organizations/8/modules/59 the Module ID will be 59.
    - It is important that the value in **Module Type** matches the type of module referred by the Module ID. So, if the module with ID 59 (see previous point) is Data Leaks the value of Module Type should be Data Leaks.
