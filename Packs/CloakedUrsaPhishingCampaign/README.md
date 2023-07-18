This pack is part of the [Rapid Breach Response](https://cortex.marketplace.pan.dev/marketplace/details/MajorBreachesInvestigationandResponse/) pack.
## Cloaked Ursa: Targeting Diplomatic Missions with Phishing Lures

**Summary:**

Cloaked Ursa, a hacking group associated with Russia's Foreign Intelligence Service, has been persistently targeting diplomatic missions globally. Using phishing tactics, Their initial access attempts over the past two years have predominantly used phishing lures with a theme of diplomatic operations such as the following:

- Notes verbale (semiformal government-to-government diplomatic communications)
- Embassies’ operating status updates
- Schedules for diplomats
- Invitations to embassy events

Recently, Unit42 researchers observed a shift in their strategy, with a focus on targeting diplomats themselves. In Kyiv alone, at least 22 out of over 80 foreign missions were targeted.

**The playbook includes the following tasks:**

**IoCs Collection**
- Blog IoCs download

**Hunting:**
- Cortex XDR XQL exploitation patterns hunting
- Advanced SIEM exploitation patterns hunting
- Indicators hunting

The hunting queries are searching for the following activities:
  - Related LNK files execution command line
  - Dropped file names

**Mitigations:**
- Unit42 mitigation measures

**References:**

[Diplomats Beware: Cloaked Ursa Phishing With a Twist](https://unit42.paloaltonetworks.com/cloaked-ursa-phishing/)
