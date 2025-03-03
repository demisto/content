## FortiJump Vulnerability (CVE-2024-47575)

On October 25, 2023, a critical zero-day vulnerability was disclosed in **FortiManager**, a centralized management platform for Fortinet devices. This vulnerability, known as **FortiJump** and tracked as **CVE-2024-47575**, allows an unauthenticated attacker with network access to execute arbitrary code or commands on the affected system, potentially leading to complete system compromise. This vulnerability has been rated **Critical** severity (CVSS 9.8).

### Impacted Versions

The vulnerability impacts the following FortiManager versions:

- FortiManager versions **7.2.0** to **7.2.3**
- FortiManager versions **7.0.0** to **7.0.7**
- FortiManager versions **6.4.0** to **6.4.11**
- FortiManager versions **6.2.x** and earlier (Potentially Affected)

### Patched Versions

- FortiManager versions **7.2.4** and above
- FortiManager versions **7.0.8** and above
- FortiManager versions **6.4.12** and above

### This pack provides you with a first response kit which includes:

* Collect, Extract, and Enrich Indicators

* Threat Hunting using XQL Query Engine
   
  * Note: The 'fortinet_fortimanager_raw' dataset must be available for the XQL queries to function.

* Mitigations and Workarounds

#### References
[Fortinet PSIRT Advisory FG-IR-24-423](https://www.fortiguard.com/psirt/FG-IR-24-423)