# BechtleDarkWebScan Pack

The Bechtle Dark Web Scan notifies you if company credentials or files are sold on the dark web. It also monitors external attack vectors, such as website and email security, and provides OSINT information.


## What does this pack do?

* Send an email when leaked credentials to your company occur on the dark web
* Allow you to block compromised accounts in Active Directory at the click of a button
* Offer commands that help you gather information when you need it


## In This Pack

This pack offers you commands and playbooks to interact with information provided by the Bechtle Dark Web Scan.

### Integrations

* Connects to the [darkwebscan.app](https://darkwebscan.app/) API to fetch leaked credentials from your configured domains

### Playbooks

* **DarkWebScan Block AD User (Human-in-the-loop):** For every new leaked credential, send an email to a specified email address. The email contains the affected user name along with other relevant information. In the email, users can select "Block user account in AD" or "Mark as resolved" to trigger the corresponding automated response.
* **DarkWebScan Notify via Email:** For every new leaked credential, send an email to a specified email address with information about the leak and the option to "Mark as resolved".


## Setup and Configuration

Prerequisites: An active subscription on darkwebscan.app
* Install this pack only from the official source (Cortex Marketplace) 
* Open the Setup for this Pack/Integration
* Choose an instance name
* Enter your API key from darkwebscan.app. If you do not have an API key, contact [darkwebscan.app/contact](https://darkwebscan.app/contact).
* Optional: Add additional request headers as Key:Value pairs, one header per row (if required).
* Specify an incidents fetch interval. Recommended: 1 Hour. (Setting this on a too frequent schedule might result in rate limiting incidents)
* Optional: Specify a "First fetch time". This will create an incident for every leak reported from the Dark Web Scan in that time frame from the past.
* Maximum incidents per fetch: Recommended: 50 or lower
* "Fetches issues" checkbox: Checking this will result in every new identified leak being created as an incident. To handle this, it is recommended to activate one of the playbooks delivered with this Pack.


