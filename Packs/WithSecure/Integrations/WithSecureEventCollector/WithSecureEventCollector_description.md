## WithSecure Help
 ### WithSecure Endpoint Protection
WithSecure Endpoint Protection is a cloud-based platform that provides effective endpoint protection against ransomware and advanced attacks.

### Authentication Process
To create a Client ID and Client Secret:
1. Login as EPP administrator in [Elements Security Center](https://elements.withsecure.com/).
2. Open API client view under the Management section.
3. Change your scope to the organization for which you want to create new pair of credentials. If you are a partner and you want to create credentials for company, then you have to change the scope to the organization, for which credentials should be issued.
4. Click **Add new**.
5. Insert the description of the new client credentials and choose whether the client should be restricted to reading data, or should also be allowed to edit it. Deselect the "Read-only" checkbox if the new credentials pair will be used for clients that send requests, which modify data on the server. For example, trigger a new remote operation. If the "Read-only" checkbox is unchecked, then the client can request an authentication token with the connect.api.write scope.
6. After the new pair of credentials is created, follow the displayed instructions. Remember to save the secret value in a safe place, because you won't be able to access that value again.
7. Select **I have copied and stored the secret** checkbox and click **Done**.
8. The new item should become visible in the list.

API Documentation: [Authentication Reference](https://connect.withsecure.com/getting-started/elements#:~:text=API%20deprecation%20policy.-,Getting%20client%20credentials,-To%20use%20Elements).