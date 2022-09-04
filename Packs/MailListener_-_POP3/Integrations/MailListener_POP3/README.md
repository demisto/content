## Overview
---

Listens to a mailbox with POP3 forwarding enabled.

---

## Configure MailListener - POP3 on XSOAR

---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for MailListener - POP3. 
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch incidents__: Whether to fetch incidents or not
    * __Server URL__: Mail Server Hostname / IP address
    * __port__: POP3 Port
    * __credentials__: Username and password
    * __first_fetch__: First fetch time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year)
    * __Use SSL Connection__: Use SSL connection when connecting to the mail server.
    * __incidentFetchInterval__: Incidents Fetch Interval
4. Click __Test__ to validate the connection and the authentication.
