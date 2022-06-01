## Absolute

To configure an instance of Absolute, you need to obtain the following information.

* Server URL
* Token ID
* Secret Key

## Get your Token ID and Secret Key

### Token ID
* The token ID is a random GUIs string and is public information (like username). 
* It is associated with the same role and device group as the Absolute user account.

### Secret Key
The secret key is a random sequence of bits and is private and contains sensitive information.

### Create a Token ID and Secret Key
1. In the Absolute console, click the **+** (in the quick access toolbar) > **API Token**.
2. On the **API Token Management** page, click the **Create token** button. The Create Token dialog box appears.
3. Enter a **Token name** and **Description**.
4. Click **Save** (The Token Created dialog box displays your generated token ID).
5. Download the token ID and secret key or view the secret key.
Note: If you close this dialog box before downloading or copying the secret key, you cannot retrieve it later.

### Download the Token ID and Secret Key
1. Click **Download Token**.
2. Save the .token file.
3. Use a text editor to open and view the file.
4. To view the secret key:
   1. Click **View Secret Key**. The secret key is populated.
   2. Copy both values of the **Token ID** and **Secret key** to a text file and save the file.
5. Click **Close**.

#### Notes:
1. On the **API Token Management** page, the new token is added to your list of tokens.
2. If a 401 error causes the API authentication to fail, you can enable authentication debugging from the Absolute console.
3. The secret key is comparable to a password. Keep it secure, and do not share it with anyone.
