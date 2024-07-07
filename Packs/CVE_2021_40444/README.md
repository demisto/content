This pack is part of the Rapid Breach Response pack.

CVE-2021-4044 refers to the MSHTML engine, that has been found vulnerable to arbitrary code execution by a specially crafted Microsoft Office document or rich text format file. 

Although there is no patch or effective mitigation available for this vulnerability, the playbook does provide several workarounds suggested by Microsoft.

Researchers have validated this attack triggered in Windows Explorer with “Preview Mode” enabled, even in just a rich-text format RTF file (not an Office file and without ActiveX). This indicates it can be exploited even without opening the file and this invalidates Microsoft’s workaround mitigation mentioned above.

This playbook should be trigger manually and includes the following tasks: 

* Collect related known indicators from several sources.
* Indicators, Files and Process creation patterns hunting using PAN-OS, Cortex XDR and SIEM products.
* Block indicators automatically or manually.
* Provide workarounds and detection capabilities.

More information:
[Microsoft MSHTML Remote Code Execution Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444)

Note: This is a beta pack, which lets you implement and test pre-release software. Since the playbook is beta, it might contain bugs. Updates to the pack during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the pack to help us identify issues, fix them, and continually improve.

![CVE-2021-40444 - MSHTML RCE](doc_files/CVE-2021-40444_-_MSHTML_RCE.png)