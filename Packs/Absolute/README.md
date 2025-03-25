# Absolute
Absolute enables you to manage and secure your data, devices, and applications with an unbreakable connection to every endpoint. Your sensitive data remains protected, even when accessed from outside your network.

## What does this pack do?
- Get or update a list of custom device fields.
- Create or remove a Freeze request for one or more devices.
- Get detailed information about a Freeze request. 
- Get, create, update, or delete a Freeze message.
- Initiate an un-enroll request on a list of eligible devices.
- Get a list of device records and the corresponding software application data for a device.
- Get a list of devices' geo location records and their corresponding data.
- Log Normalization - XDM mapping for key event types.

## Prerequisites

To configure an instance of Absolute, you need to obtain the following information.

* Server URL
* Token ID
   * A random GUI string with its public information (like username). 
   * It is associated with the same role and device group as the Absolute user account.
* Secret Key - A random sequence of bits and is private and contains sensitive information.

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

### Notes:
- On the **API Token Management** page, the new token is added to your list of tokens.
- If a 401 error causes the API authentication to fail, you can enable authentication debugging from the Absolute console.
- The secret key is comparable to a password. Keep it secure, and do not share it with anyone.

### Supported Event Types:
* [SIEM Events API](https://api.absolute.com/api-doc/doc.html%20target=%22_blank#tag/SIEM-Event-Reporting).

### Absolute Event Collector:
To enable the MongoDB Atlas Event Collector, follow these steps:
1. Go to **Settings** &rarr; **Configurations** &rarr; **Automation & Feed Integrations**.
2. In the search bar, type **Absolute**.
3. At the right-corner, click **+ Add instance**.
4. Follow the instruction in the prompt window to configure the Absolute Event Collector.