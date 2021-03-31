## The Hive Project
- This section explains how to configure the instance of TheHiveProject in Cortex XSOAR.


- Start by logging in to your Hive Project server
- Navigate to the user configuration
- The the user you would like to use as authantication in XSOAR, select `Create API Key`
- Copy the key then fill in the following in the instance:

**Host:** The host (such as https://127.0.0.1:9000)

**API Key:** The key you have just copied

- Optionally select whether you would like to create incidents from the incidents in Hive
- Optionally select whether you would like to use the default `incident type` and `classifiers`
- Ensure to tick `Trust any certificate (not secure)` if you are using self-signed certs
- Select whether you would like case mirroring enabled 