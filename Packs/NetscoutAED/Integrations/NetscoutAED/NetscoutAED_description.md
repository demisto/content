## Netscout Arbor Edge Defense - AED

- Use the Netscout Arbor Edge Defense integration to detect and stop both inbound threats
  and outbound malicious communication from compromised internal devices.

### Generate API Key
Sightline uses token-based authentication to access the API. To authenticate with a token:

1. Log in to the CLI with your administrator user name and password.
2. To create the token, enter ***/ service aaa local apitoken generate*** *userName* *“tokenDescription”*

    - userName = the name of a valid Sightline user
    - tokenDescription = A brief description of the token. This description is appended to the token.

    The system responds with something similar to the following text:

        Added token: 4wtwfuxgaRyA0rGcpbTGLzKy4_j7iQmRJeTdyIBN

3. To save the configuration, enter ***/ config write***

4. (Optional) Enter the following command to view the generated token. This command identifies each user and the tokens associated with that user. ***/ service aaa local apitoken show***

    The system responds with something similar to the following text:

        admin:

        4wtwfuxgaRyA0rGcpbTGLzKy4_j7iQmRJeTdyIBN Example administrative user token

5. With every API request, include a header that specifies this token.

### Configuration params
**NOTE**: If using 6.0.2 or lower version, put your API Key in the **Password** field, leave the **User** field empty.