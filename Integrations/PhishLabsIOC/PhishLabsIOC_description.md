The IOC feed in PhishLabs is divided into 2 endpoints:
###Global Feed
This is the feed that is shared across all of PhishLabs.
This feed consists of indicators that are classified as malicious by PhishLabs - 
URLs, domains and attachments(MD5 hashes). All the indicators from this feed are classified as malicious
in Demisto. To populate indicators from PhishLabs in Demisto, the `PhishLabsPopulateIndicators` script/playbooks
can be used.

###User Feed
This feed is exclusive for the user, and consists of emails that were sent to PhishLabs and were classified as
malicious emails. For each malicious email, an incident is created that contains the email details
and the extracted indicators. These indicators are not necessarily malicious though. In Demisto,
the user may choose whether to classify those indicators as malicious or suspicious. Incidents can be fetched
by enabling fetch incidents in the integration configuration.


