This pack is part of the [Rapid Breach Response](https://xsoar.pan.dev/marketplace/details/MajorBreachesInvestigationandResponse) pack.

On **May 27th**, a new Microsoft Office Zero-Day was discovered by Nao_sec. 

The new Zero-Day is a remote code execution vulnerability that exists when MSDT is called using the URL protocol from a calling application such as Word. 

On **May 30th**, Microsoft assigned **CVE-2022-30190** to the MSDT vulnerability, aka **Follina vulnerability**.

This playbook includes the following tasks:

* Collect detection rules.
* Exploitation patterns hunting using Cortex XDR - XQL Engine and 3rd party SIEM products.
* Cortex XDR BIOCs coverage.
* Provides Microsoft workarounds and detection capabilities.

**More information:**

[Guidance for CVE-2022-30190 Microsoft Support Diagnostic Tool Vulnerability
](https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/)

**Note:** This is a beta playbook, which lets you implement and test pre-release software. Since the playbook is beta, it might contain bugs. Updates to the pack during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the pack to help us identify issues, fix them, and continually improve.


![CVE-2022-30190 - MSDT RCE](https://raw.githubusercontent.com/demisto/content/b3a0674bdf063de2404a3090fe866b15d4848c71/Packs/CVE_2022_30190/doc_files/CVE-2022-30190_-_MSDT_RCE.png)