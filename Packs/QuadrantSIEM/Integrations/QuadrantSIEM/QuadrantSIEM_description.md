## Quadrant SIEM
The Quadrant SIEM integration fetches incidents from the Quadrant API. Quadrant is a MSSP SIEM and IDS/IPS security solution. Below is how to configure the integration.

- **How to find your Client ID and/or API Key**: Within your Quadrant portal,  go to Company Settings > Quadrant API. There you will find the Client ID and API Key.

- **Look Back Time**: In minutes. This setting is recommended to be at least 2 hours. Setting this too short risks missing alerts. Alerts are pulled in a time range of current time to current time + look back time. The last fetch alert ids are then compared with the current pulled alert ids to find new alerts. This is due to delay from alert trigger, analyst handling, then availability on the API, so can not pull in the time range of last fetch time to current time.

- **Category**: Below are the definitions of each category.
    - *reportable*: These comprise all of the alerts produced for a customer.
    - *benign*: These are alerts that Quadrant security personnel have determined are not necessary to investigate. They comprise the vast majority of alerts produced for a customer. The Quadrant SOC continuously fine-tunes the system filtering these alerts to ensure only those necessitating investigation are analyzed.
    - *investigated*: These are alerts that are analyzed by Quadrant security personnel.
    - *resolved*: These are alerts that Quadrant security personnel have analyzed and deemed not necessary to send to the customer.
    - *escalated*: These are all alerts that are sent to the customer.
    - *noncritical*: These are alerts sent to the customer that Quadrant security personnel consider to be noncritical.
    - *critical*: These are alerts sent to the customer that Quadrant security personnel consider to be critical.

---
[Learn More about Quadrant](https://quadrantsec.com/)
[View API Documentation](https://api.qis.io/docs)