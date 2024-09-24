Use the Dropbox Event Collector integration to get Audit and Auth logs from dropbox using REST APIs.

Before you begin, in the [Dropbox app console](https://www.dropbox.com/developers/apps) Use the Dropbox Event Collector integration to get Audit and Auth logs from dropbox using REST APIs.

## Create an app in the Dropbox app console

1. Go to [Dropbox app console](https://www.dropbox.com/developers/apps) and click **Create app**.  
![Description Image](https://raw.githubusercontent.com/demisto/content/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.03.00.png)

2. Give full dropbox access (not just a single folder).  
![Description Image](https://raw.githubusercontent.com/demisto/content/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.03.22.png)

3. From the **Permissions** tab, in the **Sessions** section, select **events.read**.  
![Description Image](https://raw.githubusercontent.com/demisto/content/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.04.11.png)

4. In the **Settings** tab, note the **App key** and the **App secret**.  
![Description Image](https://raw.githubusercontent.com/demisto/content/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.04.34.png)

## Configuration Parameters

**Server URL**    
The endpoint to get the logs.

**App key and App secret**    
The App key and App secret.

## Test
In order to test the connection to the Dropbox app:
1. Fill in the required parameters.
2. Run the ***!dropbox-auth-start*** command from the [WarRoom](./incidents/war_room).
3. Follow the instructions that appear.
4. Run the ***!dropbox-auth-complete*** command with the code returned from Dropbox.
5. Run the ***!dropbox-auth-test*** command to verify success.
