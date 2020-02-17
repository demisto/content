## Pentera Integration
### Create A Client
A client is Pentera's embodiment of the end-user's API client. It is the logical entity which holds authentication tokens, the tokens expiration dates, and the connection between the client and the user entities in the system.

In order to use the API, a user must first create a client in the UI.

##### Steps to create a client:
1. Login to the Pentera UI.
2. Go to Administration → API Clients.
3. Create a new client:
    1. Enter a name for the client (something meaningful to the user).
    2. Optional: Enter a description for the client.
    3. Create the client. You'll see the client appears in the client's table on the same page.
4. Issue a TGT token for the new client by pressing the Issue TGT button in the client's row in the table.
5. Copy the new TGT. You can click on the TGT field and a popup will appear with a "copy" button which will copy the entire TGT when clicked.
6. You're now ready to authenticate with the API, passing in both the Client ID and the TGT.