# SailPoint IdentityNow

## Overview
Digital transformation has opened up opportunities for greater agility and growth in today’s modern enterprises. But it’s also introducing challenges. Digital transformation has introduced an explosion of cloud, applications, data, and users to manage. Being able to effectively control ‘who can have access to what’ is the key and if not done properly can lead to potential risk to your business.

To address this potential risk, organizations are embracing the power and ease of SailPoint Identity Security. This innovative identity platform takes the complexity out of identity; making it intuitive for IT staff to configure and manage and enabling business users with the access they need to get their work done.

The SailPoint IdentityNow content pack enables XSOAR customers to utilize the deep, enriched contextual data and governance capabilities of the SailPoint Identity Security to better drive identity-aware security practices.

## Requirements
This content pack is compatibility with SailPoint IdentityNow.

## Important Note
This integration pack does not fetch incidents from IdentityNow. It rather utilizes "Generic Webhook" to create incidents on event triggers published by IdentityNow. One can achieve this by following the steps below:

1. Configure Cortex XSOAR Platform - Use the following link to configure Cortex XSOAR platform to initiate receiving of Event Triggers from IdentityNow platform.
- https://xsoar.pan.dev/docs/reference/integrations/generic-webhook
- Select "SailPoint IdentityNow Trigger" as the "Incident Type" in the "Generic Webhook" configuration.

2. Enable & Configure the Event Handler - IdentityNow Event Trigger can forward the events occurring within the platform to any external services/platform that have subscribed to the list of triggers available in IdentityNow. Request the IdentityNow team to enable/provide you with the 'identitynow-events-pan-xsoar' event handler designed for Cortex XSOAR. This is a standalone .nodejs microservice that assists with event trigger transform and relaying to Cortex XSOAR.
Following is a list of environment variables (added to the app.config.js) needed to configure this microservice:

| **Environment Variable** | **Description** |
| --- | --- |
| XSOAR_WEBHOOK_URL | This is the webhook URL that will be available once you configure the "Generic Webhook" in step 1. | 
| XSOAR_USERNAME | Username to connect to the "Generic Webhook". | 
| XSOAR_PASSWORD | Password to connect to the "Generic Webhook". |

3. Configure IdentityNow Platform - Use the following link to configure IdentityNow platform to subscribe to event triggers.
- https://community.sailpoint.com/t5/Admin-Help/Event-Triggers-in-SailPoint-s-Cloud-Services/ta-p/178285

Once you have configured all the above steps, whenever an event trigger will occur in IdentityNow, it will notify Cortex XSOAR (as Incidents) using the above setup.

