The **SlashNext Phishing Incident Response** integration app enables **Cortex XSOAR** users to fully automate the analysis of suspicious URLs in phishing emails, network logs, and more. Playbooks that require URL or Domain analysis can automatically analyze them with the SlashNext SEER threat detection cloud to get definitive, binary verdicts (malicious or benign) along with IOCs, screenshots, and more.

SlashNext threat detection uses browsers in a purpose-built cloud to dynamically inspect page contents and site behavior in real-time. This method enables SlashNext to follow URL re-directs and multi-stage attacks to more thoroughly analyze the final page(s) and made a much more accurate, binary determination with near-zero false positives. It also detects all six major categories of phishing and social engineering sites. These include credential stealing, rogue software / malware sites, scareware, phishing exploits (sites hosting weaponized documents, etc.), and social engineering scams (fake deals, giveaways, etc.).

Use cases include abuse inbox management where SOC teams can automate URL analysis in phishing emails to save hundreds of hours versus more manual methods. Playbooks that mine and analyze network logs can also leverage SlashNext URL analysis on demand.

SlashNext not only provides accurate, binary verdicts (rather than threat scores), it provides IOC metadata and screen shots of detected phishing pages. These enables easier classification and reporting. Screen shots can be used as an aid in on-going employee phishing awareness training and testing.

The SlashNext Phishing Incident Response integration app uses an API key to authenticate with SlashNext cloud. If you don't have a valid API key, contact the SlashNext team: support@slashnext.com 

Notice: Submitting indicators using the following commands of this integration might make the indicator data publicly available.
- ***url***
- ***domain***
- ***slashnext-url-reputation***
- ***slashnext-host-reputation***
See the vendor’s documentation for more details.