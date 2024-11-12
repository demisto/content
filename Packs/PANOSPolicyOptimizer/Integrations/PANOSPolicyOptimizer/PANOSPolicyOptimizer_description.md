The integration uses User Interface calls to manage the PANOS Policy Optimizer for AppID Adoption.

You now have a simple way to gain visibility into, control usage of, and safely enable applications in Security policy rules: Policy Optimizer. 

This new feature identifies port-based rules so you can convert them to application-based rules that allow the traffic or add applications to existing rules without compromising application availability. It also identifies rules configured with unused applications. Policy Optimizer information helps you analyze rule characteristics and prioritize which rules to migrate or clean up first.
Converting port-based rules to application-based rules enables you to include the applications you want to allow in an allow list and deny access to all other applications, which improves your security posture. Restricting application traffic to its default ports prevents evasive applications from running on non-standard ports. Removing unused applications from rules is a best practice that reduces the attack surface and keeps the rulebase clean.
You can use this new feature on:
* Firewalls that run PAN-OS version 9.0 and have App-ID enabled.
* Panorama running PAN-OS version 9.0. You don’t have to upgrade firewalls that Panorama manages to use the Policy Optimizer capabilities. However, to use these capabilities, managed firewalls must run PAN-OS 8.1 or later. If managed firewalls connect to Log Collectors, those Log Collectors must also run PAN-OS version 9.0. Managed PA-7000 Series firewalls that have a Log Processing Card (LPC) can also run PAN-OS 8.1 (or later).

For more information, visit the [Palo Alto Networks documentation](https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/app-id/security-policy-rule-optimization).

---
You need to create a separate integration instance for Palo Alto Networks Firewall and Palo Alto Networks. Unless specified otherwise, all commands are valid for both Firewall and Panorama.

---

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.