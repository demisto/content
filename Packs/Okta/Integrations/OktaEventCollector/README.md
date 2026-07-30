Collects the events log for authentication and Audit provided by Okta admin API

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Okta Log in Cortex

| **Parameter**                                                           | **Description**                                                                           | **Required** |
|-------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|--------------|
| Server URL                                                              | Okta URL (https://yourdomain.okta.com)                                                    | True         |
| Number of incidents to fetch per fetch                                  | The total number of incidents to retrieve in each fetch cycle                             | True         |
| proxy                                                                   | Use system proxy settings                                                                 | False        |
| API key                                                                 | The request API key                                                                       | True         |
| First fetch time interval                                               | The period (in days) to retrieve events from, if no time is saved in the system           | True         |

## Commands

You can execute these commands in a playbook.

### okta-get-events

***
Manual command to fetch events and display them.
