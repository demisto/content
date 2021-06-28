Threat Intelligence is core to incident response. If you integrate it into your incident response workflow, you can then map external threat data to what’s happening internally.  As hundreds of thousands of indicators may be created or updated on a daily basis, Cortex XSOAR provides the automations that allow you to perform many tasks related to threat intelligence indicators.
The TIM - Indicator Auto-Processing pack includes playbooks that automate the processing of indicators for many use cases such as tagging, checking for existence in various exclusion or other lists of interest, running enrichment for specific indicators and preparing indicators if necessary for a manual review in case additional approval is required. This helps you quickly separate relevant indicators from irrelevant ones. 
With this content pack, you can significantly reduce the time your threat intelligence analysts spend on reviewing hundreds of thousands of indicators by performing many pre-defined logics and processing tasks automatically.

##### What does this pack do?

The playbooks included in this pack help you automate repetitive tasks associated with with the handling of indicators:

- Check if indicators are related to internal exclusion lists such as business partners or other approved origin.
- Validate CIDR indicator size in order not to approve or deny large CIDR ranges.
- Create incidents for indicators that require additional analyst review and chain of approval.
- Run additional enrichment for indicators ingested by specific feeds.
- Check Whois to validate domains registrant and time of creation.
- Check if an indicator with a tag of *organizational_external_ip* has been updated and keeps or removes the tag according to the results.
- Process indicators against IP and CIDR lists.


_For more information, visit our [Cortex XSOAR Developer Docs](https://xsoar.pan.dev/docs/reference/index)._
