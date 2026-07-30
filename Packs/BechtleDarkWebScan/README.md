# BechtleDarkWebScan Pack

The dark web scan by Bechtle notifies you if login credentials to your company or files from your company are being sold on the dark web. Additionally, it checks other external attack vectors like attacks against your website, email security and offers OSINT information that cybercriminals could also abuse.


## What does this pack do?
* Send an email when leaked credentials to your company occur on the dark web
* Allow you to block compromised accounts in Active Directory at the click of a button
* Offer commands that help you gather information when you need it


## In This Pack

This pack offers you commands and playbooks to interact with information provided by the Bechtle Dark Web Scan.

### Integrations
* Connects to the [darkwebscan.app](https://darkwebscan.app/) API to fetch leaked credentials from your configured domains

### Playbooks
* **DarkWebScan Block AD User (Human-in-the-loop):** For every new leaked credential, send an email to a specified email address. The email contains the affected user name along with other relevant information. In the email, one can click on "Block user account in AD" or "Mark as resolved" to trigger automated response reactions accordingly.
* **DarkWebScan Notify via Email:** For every new leaked credential, send an email to a specified email address with information about the leak and the option to "Mark as resolved".


# Setup and Configuration

Prerequisites: An active subscription on darkwebscan.app

Setup:
- Install this pack only from the official source (Marketplace)
- Open the Setup for this Pack/Integration
- Choose an instance name
- Enter your API key from darkwebscan.app (If you don't know yours or you think you don't have one, please contact [darkwebscan.app/contact](https://darkwebscan.app/contact) )
- Optional: Add additional request headers as Key:Value pairs, one header per row (if required).
- Specify an incidents fetch interval. Recommended: 1 Hour. (Setting this on a too tight schedule might result in rate limiting issues)
- Optional: Specify a "First fetch time". This will create an incident for every leak reported from the Dark Web Scan in that time frame from the past.
- Maximum incidents per fetch: Recommended: 50 or lower
- "Fetches issues" checkbox: Checking this will result in every new identified leak being created as an issue. To handle this, it is recommended to activate one of the playbooks delivered with this Pack.


