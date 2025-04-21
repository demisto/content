Phishing domains impersonating an organization's brand are a persistent threat that often slip through defenses. Analysts struggle to manually monitor certificate transparency logs and WHOIS registrations to catch phishing domains early.  

The Suspicious Domain Hunting pack equips analysts with automation to proactively hunt for phishing domains targeting their organization. CertStream integration ingests newly issued SSL certificates in real-time, while WHOIS data and threat intel feeds are checked for domain registrations using the company brand. Analysts save hours of manual effort and can disrupt phishing campaigns before emails reach users.

This pack includes playbooks that:

- Ingest and enrich certificate transparency events in real-time. 
- Correlate new SSL certs with WHOIS domain registration data.
- Check domain reputation against threat intel feeds.  
- Prioritize incidents for high risk domains impersonating the organization.
- Enable quick suspensions or takedowns of phishing domains.

Analysts also get out-of-the-box incident views and layouts tailored for Suspicious Domain Hunting, enabling efficient workflows to take action on high severity events.

##### What does this pack do?

- Monitors certificate transparency logs via CertStream.  
- Ingests and enriches SSL cert events as incidents.
- Checks domain WHOIS records for matches against organization brand.
- Correlates SSL data with WHOIS data to identify phishing domains. 
- Queries domain reputation against threat intel feeds.  
- Prioritizes incidents using criticality score if org domain is spoofed. 
- Includes playbooks to automatically suspend domains via registrar.
- Provides domain hunting views and layout for efficient analyst response.

##### Additional Information  

_Leverages the CertStream integration - configure your API key before installation_.

_Works best with Domain Reputation and Domain Enrichment integrations enabled_. 

_For takedown automation, API access to domain registrar required_.
