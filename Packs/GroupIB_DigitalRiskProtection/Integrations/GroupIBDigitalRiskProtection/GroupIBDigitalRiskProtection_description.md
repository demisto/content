### Group-IB Digital Risk Protection  

- This section explains how to configure the **Digital Risk Protection** instance in **Cortex XSOAR**.  

#### Step 1: Generate an API key  
1.1 Log in to your Group-IB DRP account at [drp.group-ib.com](https://drp.group-ib.com).  
1.2 Open your profile settings: [https://drp.group-ib.com/p/profile/](https://drp.group-ib.com/p/profile/).  
1.3 Click **Generate API key**. The key appears next to the button.  
1.4 Copy the key before you leave the page - it is shown only once.  

The key is used with HTTP Basic Auth: the login is your email address, the password is the API key.

#### Step 2: Set Up Connection Details  
2.1 **GIB DRP API URL:** the DRP **API** URL, not the address of the web interface. For the SaaS portal this is `https://drp.group-ib.com/client_api`.  
2.2 **Username:** the email address you log in to DRP with.  
2.3 **Password:** the API key from Step 1.  

#### Step 3: Configure Classifier and Mapper  
3.1 Set the **Classifier** and **Mapper** using the **Group-IB Digital Risk Protection** classifier and mapper.  
Note: Alternatively, you may configure your own setup if needed.  

#### Step 4: Choose What to Fetch  
4.1 **Filter by Violation Section** narrows the fetch to one DRP section - Web, Mobile Apps, Marketplace, Social Networks, Advertising or Instant Messengers.  
4.2 **Filter by Violation Type** narrows it to the violation types themselves - Phishing, Scam, Counterfeit, Malware, Piracy, Trademark, Partner policy compliance, No violation. Selecting exactly one type is filtered by the DRP API; selecting several is filtered by the integration after the fetch, which is equally correct but pulls more data.  
4.3 **Fetch only Violations awaiting approval** creates incidents only for violations Group-IB has sent you for a decision (approve state `under_review`) - the ones the buttons in Step 7 act on. Like **Filter by Violation Status**, it applies to creation only (Step 6): once a violation has an incident on this instance, the decision and the take-down still reach that incident.  
4.4 **Filter by Violation Status** creates incidents only for violations in the selected statuses. The default, `detected` and `in_response`, covers the violations still being worked on. A violation that arrives already over - `resolved`, `solved`, `legal`, `false_status`, or rejected by the customer - never creates an incident, whatever is selected, so a first fetch on a long-running tenant does not create an incident per resolved violation.  
4.5 **Incident severity** is applied to every incident this instance creates. To grade violations, configure one instance per severity: for example a Phishing-only instance at *Critical* alongside a Scam-only instance at *Medium*.  
4.6 **Create indicators from Violations** creates an indicator from the violation URI, for the selected violation types only. The indicator is created by the postprocessing playbook (Step 9) from the new incident, so it is linked to the incident and carries **Group-IB Digital Risk Protection** as its source. Only an `http` or `https` URL, a domain or an IPv4 address becomes an indicator; a marketplace seller id, a messenger handle or a `mail://` address creates none. Reputation follows the violation type: Counterfeit, Scam, Malware and Phishing as *Malicious*, Partner policy compliance, Piracy and Trademark as *Suspicious*, and No violation as *Benign*. Leave the parameter empty to create no indicators.  
4.7 **Expire the indicator when the violation is closed** expires that indicator when the violation is over (Step 8). Off by default: the indicator then stays active.  
4.8 **Close the incident when a violation is approved** makes the Approve Violation button (and the playbook) close the incident as *Resolved* with the approval. Off by default: the incident then stays open until DRP resolves the violation (Step 8). Rejecting always closes the incident as *False Positive*, since DRP does nothing more with a rejected violation.  

#### Step 5: Verify the Pre-Processing Rule  
5.1 This pack **ships an enabled rule** — `GIB DRP Rule All Types` — so there is normally nothing to create. To review it, go to **Settings → Objects Setup → Pre-Process Rules** (on some versions: *Settings → Integrations → Pre-Process Rules*):  
   - **Condition**: `"gibdrpid" is not empty (General)`.  
   - **Action**: `Run a script`.  
   - **Script**: `GIBDRPIncidentUpdate`.  
5.2 `GIBDRPIncidentUpdate` streams every Group-IB DRP incident that carries the same violation id page-by-page, updates each in place with a single `setIncident` call, and drops the incoming incident once a real duplicate was updated. Closed incidents are matched too, and are updated without being reopened - a violation whose incident was already closed must not come back as a new incident when DRP updates it.  
5.3 The rule is also what closes an incident when the work on its violation is over; see Step 8.  
5.4 The rule sees an incident only once Cortex XSOAR has created it. Two instances whose filters overlap and that start fetching at the same moment can therefore each create an incident for the same violation before either can see the other's - every later update is then folded into one of the two, but the pair stays. Give overlapping instances non-overlapping filters, or enable them a fetch interval apart; instances with non-overlapping filters are not affected.

#### Step 6: Creation Filters and Known Violations
6.1 The status and approval filters of Step 4 decide which violations get an incident; they do not decide which updates the instance receives. The instance pulls the update stream of its section, types and brands unfiltered and remembers the violations it created incidents for (the `found_incident_ids` cache in its fetch state). A remembered violation is passed through to the pre-processing rule on every change, whatever its status or approve state has become, so the rule can refresh and close the incident. A violation that is not remembered has to pass the filters to get an incident.  
6.2 **Known violations retention (days)** (advanced, default `365`) is how long a violation is remembered after the last fetch that carried it. A violation that changed within the retention stays known; one that went quiet for longer is treated as new again and filtered as such. `0` forgets everything, so every fetched violation is filtered as if it were new - and an update of an existing incident that the filters drop never reaches it.  
6.3 The cache is per instance. If two instances fetch the same violations, each creates its own incident; the pre-processing rule then folds later updates into whichever incident it finds, but the pair stays (5.4). Give overlapping instances non-overlapping filters by section, type or brand.  

#### Step 7: Resolving Violations from the Incident
7.1 The **GIB DRP Violation** layout has **Approve Violation** and **Reject Violation** buttons in the *Information From Group-IB* section. They run the `GIBDRPResolveViolation` automation, which sends the decision to Group-IB DRP.  
7.2 Both buttons appear only while the violation is waiting for you, that is while **GIB DRP Approve State** is `under_review`. Once the decision is made - from a button, from the playbook, or in the DRP portal - the approve state changes and the buttons are no longer offered.  
7.3 The decision is sent through the instance that fetched the incident. Without that, Cortex XSOAR would run the command on every enabled instance, and with several instances the ones that do not own the violation would fail the button.  
7.4 **Approve Violation** does not close the incident by default. An approval settles the customer's half of the case; the take-down continues in DRP afterwards, and the incident closes when the violation is resolved (Step 8). With **Close the incident when a violation is approved** enabled on the instance (4.8), the button closes the incident as *Resolved* at once.  
7.5 **Reject Violation** always closes the incident as *False Positive*: DRP does nothing more with a rejected violation, so nothing later would close the incident. If **Expire the indicator when the violation is closed** is enabled (4.7), the indicator created from the violation is expired as well.  
7.6 A violation can be changed only while its status is `detected` and its approve state is `under_review`. In any other state the button reports the violation's actual state and changes nothing.

#### Step 8: Automatic Incident Closing
8.1 A violation incident is closed when the work on the violation is over. Two outcomes end it: Group-IB DRP finished with the violation - status `resolved` (taken down; older API versions spell it `solved`) or `legal` (handed to legal) - which closes the incident as *Resolved*; or the violation turned out not to be one - DRP set `false_status`, or the customer rejected it - which closes the incident as *False Positive*.  
8.2 For an incident that already exists, the close is done by the `GIBDRPIncidentUpdate` Pre-Processing Rule as soon as the change arrives on a fetch. The fetch passes every change of a known violation through (Step 6), so the status and approval filters of the instance do not hold the close back.  
8.3 For a violation that is already over when its incident is created - which the fetch avoids (4.4), so this covers incidents created another way - the close is done by the **Group-IB Digital Risk Protection - Violation Incident Postprocessing** playbook.  
8.4 A rejection made from the incident (button or playbook) closes the incident at once (7.5). An approval does not, unless **Close the incident when a violation is approved** is enabled (4.8).  
8.5 With **Expire the indicator when the violation is closed** enabled (4.7), every close above also expires the indicator created from the violation.  
8.6 Filters by section, type and brand never hide an update, because a violation never changes those. A **Known violations retention** of `0` (6.2) does: the update is then filtered as if the violation were new.  

#### Step 9: The Postprocessing Playbook  
9.1 New **GIB DRP Violation** incidents run the **Group-IB Digital Risk Protection - Violation Incident Postprocessing** playbook. It closes an incident whose violation is already over (8.3), creates the violation's indicator when the instance asked for one (4.6), and, while Group-IB DRP is waiting for the customer's decision, assigns an analyst and asks whether to approve the violation. The decision goes through `GIBDRPResolveViolation`, to the instance that fetched the incident.  
