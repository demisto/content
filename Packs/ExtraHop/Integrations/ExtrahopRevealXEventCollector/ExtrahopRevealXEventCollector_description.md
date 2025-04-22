## Configure an instance for ExtraHop Reveal(x)

### How to create REST API Credentials:
* You must have system and access administration privileges.
1. Log in to RevealX 360.
2. Click the System Settings icon - at the top right of the page and then click All Administration.
3. Click API Access.
4. Click Create Credentials.
5. In the Name field, type a name for the credentials.
6. In the Privileges field, specify a privilege level for the credentials. The privilege level determines which actions can be performed with the credential. Do not grant more privileges to REST API credentials than needed because it can create a security risk. For example, applications that only retrieve metrics should not be granted credentials that grant administrative privileges. For more information about each privilege level, see User privileges. 
* Note: System and Access Administration privileges are similar to Full write privileges and allow the credentials to connect sensors and Trace appliances to RevealX 360.*
7. In the Packet Access field, specify whether you can retrieve packets and session keys with the credentials.
8. Click Save. The Copy REST API Credentials pane appears.
9. Under ID, click Copy to Clipboard and save the ID to your local machine.
10. Under Secret, click Copy to Clipboard and save the secret to your local machine.
11. Click Done.



