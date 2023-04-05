## WithSecure Help
 ### WithSecure Endpoint Protection
WithSecure Endpoint Protection is a cloud-based platform that provides effective endpoint protection against ransomware and advanced attacks.

### Authentication Process
To Create a Client ID and Client Secret, follow these steps
1. Login as EPP administrator in [Elements Security Center](https://elements.withsecure.com/).
2. Open API client view under Management section.
3. Change your scope to organization for which you want to create new pair of credentials. If you are a partner and you want to create credentials for company, then you have to change scope to the organization, for which credentials should be issued.
4. Click button Add new.
5. Insert description of new client credentials and choose whether client should be restricted to reading data, or should it also be allowed to edit it. Deselect checkbox "Read-only" if new credentials pair will be used for clients, that send requests, which modify data on the server. For example trigger new remote operation. If checkbox "Read-only" is unchecked, then client can request authentication token with scope connect.api.write.
6. After new pair of credentials is created follow displayed instructions. Remember to save secret value in safe place, because you won't be able to read that value again.
7. Select checkbox and click button Done.
8. New item should become visible in list.

API Documentation: [Authentication Reference](https://connect.withsecure.com/getting-started/elements#:~:text=API%20deprecation%20policy.-,Getting%20client%20credentials,-To%20use%20Elements).