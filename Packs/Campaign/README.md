When a suspicious email is detected, for example: phishing or spam, this pack can help you save investigation time by enabling you to efficiently and easily query past email incidents to find relevant incidents and identify an email campaign. 

## What does this pack do?

The pack includes the **FindEmailCampaign** script which enables you to: 
- Filter past email incidents according to multiple search criteria provided by the user as the script inputs. For example: incident types, email body and/or subject, email sender, similarity threshold between emails, and more.
- Define criteria for a collection of related email incidents to be considered a campaign: minimum number of incidents and minimum number of unique recipients. 

The script output indicates whether a campaign was identified. When a campaign is identified, more information about the campaign is provided: number of incidents involved in the campaign, indicators involved in the campaign and more.


## How does this pack work?

- An active instance of the integration you plan to use for fetching and ingesting suspicious email incidents, for example, Palo Alto Networks Cortex XDR, is required.
- The Phishing content pack is required because the **FindEmailCampaign** script uses the **FindDuplicateEmailIncidents** script from that pack.
