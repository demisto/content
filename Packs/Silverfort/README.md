Whenever Cortex XSOAR runs an investigation that entails a suspicion of compromised user account it leverages Silverfort’s visibility to gain wider context of the investigated user account and applies Silverfort’s proactive protection capabilities such as requiring MFA or blocking access altogether as part of Cortex playbooks.

##### What does this pack do?
Mutual data enrichment on user’s risk and triggering protective actions:
- Cortex XSOAR queries Silverfort whether  an investigated user account is a service account or a human user
- Cortex XSOAR queries Silverfort’s risk score for investigates user accounts
- Cortex XSOAR actively updates users’ risk scores at Silverfort based on its automated investigation 
- Silverfort blocks user access to resources or requires MFA based on Cortex playbook

Add helpful, relevant links below 
- https://www.silverfort.com/
- https://www.silverfort.com/request-a-demo/
- https://www.silverfort.com/portfolio-item/form-blocking-identity-based-threats-with-silverfort-palo-alto-networks-cortex-xsoar-2/