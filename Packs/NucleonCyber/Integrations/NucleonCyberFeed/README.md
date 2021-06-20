# NucleonCyber 
## About us
  NucleonCyber is a distributed, high-performance invisible and non-invasive platform that is tailored to secure environments from different common threats such as professional hacking groups, APTs and others. Our platform identifies what your adversaries are doing, how they’re doing it and whether they’re targeting you or your extended enterprise.

Use the NucleonCyber Feed integration to add our indicators  hashes, URLs, domains, and IP addresses to ours XSOAR platform.

## Configure NucleonCyber on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for NucleonCyberFeed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| isFetch | Fetch incidents | False |
| feedFetchInterval | Feed Fetch Interval | False |
| **API authentication details**                  |
| username | User Name | True |
| password |Password | True |
| usrn |Usrn | True |
| clientid |ClientID | True |
| first_fetch | First fetch time | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

**NOTE**  
for more info on feed integration -configurion parameters please check [here]( https://docs.paloaltonetworks.com/cortex/cortex-xsoar/5-5/cortex-xsoar-admin/manage-indicators/understand-indicators/feed-integrations.html )



4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.



#### Command

`nucleoncyber-get-ips` -prints ips to anyone.  
`nucleoncyber-get-urls` - prints urls to anyone.  
`nucleoncyber-get-hashes` - prints hashes to anyone.
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit |  the number opf ip to display | Optional - defult display 10 indicator | 

#### Command Example
```!`nucleoncyber-get-ips limit=100```





