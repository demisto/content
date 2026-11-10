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
4.3 **Fetch only Violations awaiting approval** creates incidents only for violations Group-IB has sent you for a decision (approve state `under_review`) - the ones the **Approve Violation** and **Reject Violation** layout buttons act on. Like **Filter by Violation Status**, it applies to creation only (Step 6): once a violation has an incident on this instance, the decision and the take-down still reach that incident.  
4.4 **Filter by Violation Status** creates incidents only for violations in the selected statuses. The default, `detected` and `in_response`, covers the violations still being worked on. A violation that arrives already over - `resolved`, `solved`, `legal`, `false_status`, or rejected by the customer - never creates an incident, whatever is selected, so a first fetch on a long-running tenant does not create an incident per resolved violation.  
4.5 **Incident severity** is applied to every incident this instance creates. To grade violations, configure one instance per severity: for example a Phishing-only instance at *Critical* alongside a Scam-only instance at *Medium*.  
4.6 **Create indicators from Violations** creates an indicator from the violation URI, for the selected violation types only. The indicator is created by the postprocessing playbook from the new incident, so it is linked to the incident and carries **Group-IB Digital Risk Protection** as its source. Only an `http` or `https` URL, a domain or an IPv4 address becomes an indicator; a marketplace seller ID, a messenger handle or a `mail://` address creates none. Reputation follows the violation type: Counterfeit, Scam, Malware and Phishing as *Malicious*, Partner policy compliance, Piracy and Trademark as *Suspicious*, and No violation as *Benign*. Leave the parameter empty to create no indicators.  
4.7 **Expire the indicator when the violation is closed** expires that indicator when the violation is over - resolved, handed to legal, found false or rejected. Off by default: the indicator then stays active.  
4.8 **Close the incident when a violation is approved** makes the Approve Violation button (and the playbook) close the incident as *Resolved* with the approval. Off by default: the incident then stays open until DRP resolves the violation. Rejecting always closes the incident as *False Positive*, since DRP does nothing more with a rejected violation.  

#### Step 5: Verify the Pre-Processing Rule  
5.1 This pack **ships an enabled rule** — `GIB DRP Rule All Types` — so there is normally nothing to create. To review it, go to **Settings → Objects Setup → Pre-Process Rules** (on some versions: *Settings → Integrations → Pre-Process Rules*):  
   - **Condition**: `"gibdrpid" is not empty (General)`.  
   - **Action**: `Run a script`.  
   - **Script**: `GIBDRPIncidentUpdate`.  
5.2 `GIBDRPIncidentUpdate` streams every Group-IB DRP incident that carries the same violation ID page-by-page, updates each in place with a single `setIncident` call, and drops the incoming incident once a real duplicate was updated. Closed incidents are matched too, and are updated without being reopened - a violation whose incident was already closed must not come back as a new incident when DRP updates it.  
5.3 The rule is also what closes an incident when the work on its violation is over; see **Automatic Incident Closing** in the integration documentation.  
5.4 The rule sees an incident only once Cortex XSOAR has created it. Two instances whose filters overlap and that start fetching at the same moment can therefore each create an incident for the same violation before either can see the other's - every later update is then folded into one of the two, but the pair stays. Give overlapping instances non-overlapping filters, or enable them a fetch interval apart; instances with non-overlapping filters are not affected.

#### Step 6: Creation Filters and Known Violations
6.1 The status and approval filters of Step 4 decide which violations get an incident; they do not decide which updates the instance receives. The instance pulls the update stream of its section, types and brands unfiltered and remembers the violations it created incidents for (the `found_incident_ids` cache in its fetch state). A remembered violation is passed through to the pre-processing rule on every change, whatever its status or approve state has become, so the rule can refresh and close the incident. A violation that is not remembered has to pass the filters to get an incident.  
6.2 **Known violations retention (days)** (advanced, default `365`) is how long a violation is remembered after the last fetch that carried it. A violation that changed within the retention stays known; one that went quiet for longer is treated as new again and filtered as such. `0` forgets everything, so every fetched violation is filtered as if it were new - and an update of an existing incident that the filters drop never reaches it.  
6.3 The cache is per instance. If two instances fetch the same violations, each creates its own incident; the pre-processing rule then folds later updates into whichever incident it finds, but the pair stays (5.4). Give overlapping instances non-overlapping filters by section, type or brand.  

What happens once the instance is running - resolving violations from the incident, automatic incident closing and the postprocessing playbook - is described under **Violation Incidents** in the integration documentation.
