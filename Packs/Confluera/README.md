## Overview
This pack enables you to fetch real time data ( detections, progressions) from confluera's central brain called IQ-Hub portal.

## What does this pack do?

- Fetch list of detections present in IQ-Hub portal
- Fetch list of progressions available in IQ-Hub portal
- Get details of any specific progression needed by the user

This pack includes the :
- **Confluera** integration 
- The **IQ-HUB Automation** playbook
- **Confluera Incident** incident type
- an incident layout to display the real-time data coming from Iq-Hub portal in chart format.
- following 9 scripts :  
-- **ConflueraDetectionsCount** : Logs detections count present in confluera Iq-Hub portal.  
-- **ConflueraDetectionsData** : Logs detections data ( detection vs risk-contribution ) present in confluera Iq-Hub portal.  
-- **ConflueraDetectionsDataWarroom** : Logs detections data ( detection vs risk-contribution ), present in the confluera Iq-Hub portal, in bar chart format inside the confluera incident layout.  
-- **ConflueraDetectionsSummary** : Logs detections data ( categories of detections ) present in confluera Iq-Hub portal.  
-- **ConflueraDetectionsSummaryWarroom** : Logs detections data ( categories of detection ), present in the confluera Iq-Hub portal, in pie chart format inside the confluera incident layout.  
-- **ConflueraProgressionsCount** : Logs progressions count present in confluera Iq-Hub portal.  
-- **ConflueraProgressionData** : Logs progressions data ( progression vs risk-score ) present in confluera Iq-Hub portal.  
-- **ConflueraProgressionsDataWarroom** : Logs the progressions data ( progression vs risk-score ), present in the confluera Iq-Hub portal, in bar chart format inside the confluera incident layout.  
-- **IqHubLog** : Logs detections & progression counts along with respective links to confluera Iq-Hub portal.   

## How does this pack work 
Create an instance of the **Confluera** integration by providing the Iq-Hub url and login credential and start fetching real time data from IQ-Hub portal.  

## Integrations
This pack includes **Confluera** integration that implements the following Command.
- **confluera-fetch-detections** - Fetches list of detections present in confluera's Iq-Hub portal for past x hours. This command accpets **hours** as an argument which has default value set as **72 hours**.
- **confluera-fetch-progressions** - Fetches list of progressions present in confluera's Iq-Hub portal for past x hours.This command accpets **hours** as an argument which has default value set as **72 hours**.
- **confluera-fetch-trail-details** - Fetches progression details, present in confluera's Iq-Hub portal, of which provided trailId is a part of.This command accpets **trail_id** as an argument.
