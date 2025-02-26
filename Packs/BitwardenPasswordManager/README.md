# Bitwarden Password Manager

Bitwarden Password Manager integrates with Palo Alto Network’s Cortex XSIAM to fetch records of events that occur within your Teams or Enterprise organization.

This is a content pack for **Bitwarden Password Manager** includes both Integration and Modeling Rules.


## Overview

Bitwarden Password Manager helps organizations to store their passwords and other sensitive data securely.
The Password Manager is encrypted and have the abilities to identify compromised passwords.


## What does this pack contains?

- Rest API integration for your Bitwarden Password Manager.
- Modeling Rules for all security events:
  User Events
  Collection Events
  Organization Events
  Item Events
  Group Events
  Secrets Manager Events

## How to integrate with XSIAM?

### Generate API Keys in Bitwarden Password Manager
1. Login to **Bitwarden Admin Console** and go to **Settings** -> **Organization info** -> **View API key**
2. Copy the **client_id** and **client_secret**

For more information please check the Bitwarden Public API doccumentation -> [Click here](https://bitwarden.com/help/public-api/#authentication).

### XSIAM Configuration

1. In XSIAM left pane go to -> **Marketplace** and install the **Bitwarden Password Manager** content pack.
2. Next go to **Settings** -> **Data Sources** and look for the **Bitwarden Passwordd Manager** Data Source.
3. Enter your **client_id**, **client_secret** and **Bitwwarden API Server URL**