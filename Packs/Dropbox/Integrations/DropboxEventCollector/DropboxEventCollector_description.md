Use the Dropbox Event Collector integration to get Audit and Auth logs from dropbox using REST APIs.

Before you begin, in the [Dropbox app console](https://www.dropbox.com/developers/apps) Use the Dropbox Event Collector integration to get Audit and Auth logs from dropbox using REST APIs.

## Create an app in the Dropbox app console

1. Go to [Dropbox app console](https://www.dropbox.com/developers/apps) and click **Create app**.  
![Description Image](../../doc_files/Screen_Shot_2022-06-13_at_10_03_00.png)

2. Give full dropbox access (not just a single folder).  
![Description Image](../../doc_files/Screen_Shot_2022-06-13_at_10_03_22.png)

3. From the **Permissions** tab, in the **Sessions** section, select **events.read**.  
![Description Image](../../doc_files/Screen_Shot_2022-06-13_at_10_04_11.png)

4. In the **Settings** tab, note the **App key** and the **App secret**.  
![Description Image](../../doc_files/Screen_Shot_2022-06-13_at_10_04_34.png)

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
