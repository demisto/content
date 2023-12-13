RESPONSE_DATA = {
    "data":
    [
        {
            "id": "16d2470f-dcbf-4728-902f-5b1b39926e1a",
            "created_at": "2023-11-18T02:07:23.236896Z",
            "updated_at": "2023-11-22T02:20:19.669382Z",
            "deleted_at": None,
            "sha1_hash": "366fd71c47469498d1a037693c879f632752b5b4",
            "title": "Scattered Spider",
            "authors": "",
            "file_creation_date": "2023-11-15T13:33:34Z",
            "file_modification_date": "2023-11-15T13:40:12Z",
            "file_size": 529435,
            "plain_text": "Co-Authored by:\n\nTLP:CLEAR\n\nProduct ID: AA23-320A\nNovember 16, 2023\n\nScattered Spider\nSUMMARY\nThe Federal Bureau of Investigation (FBI) and Cybersecurity\nand Infrastructure Security Agency (CISA) are releasing this\njoint Cybersecurity Advisory (CSA) in response to recent\nactivity by Scattered Spider threat actors against the\ncommercial facilities sectors and subsectors. This advisory\nprovides tactics, techniques, and procedures (TTPs)\nobtained through FBI investigations as recently as November\n2023.\n\nActions to take today to mitigate\nmalicious cyber activity:\n•\n•\n\n•\n\nMaintain offline backups of data.\nEnable and enforce phishingresistant multifactor\nauthentication (MFA).\nImplementing application\ncontrols to manage and control\nsoftware execution.\n\nScattered Spider is a cybercriminal group that targets large\ncompanies and their contracted information technology (IT)\nhelp desks. Scattered Spider threat actors, per trusted third parties, have typically engaged in data theft\nfor extortion and have also been known to utilize BlackCat/ALPHV ransomware alongside their usual\nTTPs.\nFBI and CISA encourage critical infrastructure organizations to implement the recommendations in\nthe Mitigations section of this CSA to reduce the likelihood and impact of a cyberattack by Scattered\nSpider actors.\n\nTECHNICAL DETAILS\nNote: This advisory uses the MITRE ATT&CK for Enterprise framework, version 14. See the MITRE\nATT&CK® Tactics and Techniques section for a table of the threat actors’ activity mapped to MITRE\nATT&CK tactics and techniques. For assistance with mapping malicious cyber activity to the MITRE\nATT&CK framework, see CISA and MITRE ATT&CK’s Best Practices for MITRE ATT&CK Mapping\nand CISA’s Decider Tool.\n\nTo report suspicious or criminal activity related to information found in this joint Cybersecurity Advisory, contact\nyour local FBI field office or CISA’s 24/7 Operations Center at Report@cisa.gov or (888) 282-0870. When\navailable, please include the following information regarding the incident: date, time, and location of the incident;\ntype of activity; number of people affected; type of equipment used for the activity; the name of the submitting\ncompany or organization; and a designated point of contact.\nThis document is distributed as TLP:CLEAR. Sources may use TLP:CLEAR when information carries minimal or\nno foreseeable risk of misuse, in accordance with applicable rules and procedures for public release. Subject to\nstandard copyright rules. TLP:CLEAR information may be distributed without restrictions. For more information\non the Traffic Light Protocol, see cisa.gov/tlp.\n\nTLP:CLEAR\n\nTLP:CLEAR\n\nFBI  CISA\n\nOverview\nScattered Spider (also known as Starfraud, UNC3944, Scatter Swine, and Muddled Libra) engages in\ndata extortion and several other criminal activities.[1] Scattered Spider threat actors are considered\nexperts in social engineering and use multiple social engineering techniques, especially phishing,\npush bombing, and subscriber identity module (SIM) swap attacks, to obtain credentials, install\nremote access tools, and/or bypass multi-factor authentication (MFA). According to public reporting,\nScattered Spider threat actors have [2],[3],[4]:\n•\n•\n•\n•\n•\n•\n\nPosed as company IT and/or helpdesk staff using phone calls or SMS messages to obtain\ncredentials from employees and gain access to the network [T1598],[T1656].\nPosed as company IT and/or helpdesk staff to direct employees to run commercial remote\naccess tools enabling initial access [T1204],[T1219],[T1566].\nPosed as IT staff to convince employees to share their one-time password (OTP), an MFA\nauthentication code.\nSent repeated MFA notification prompts leading to employees pressing the “Accept” button\n(also known as MFA fatigue) [T1621].[5]\nConvinced cellular carriers to transfer control of a targeted user’s phone number to a SIM card\nthey controlled, gaining control over the phone and access to MFA prompts.\nMonetized access to victim networks in numerous ways including extortion enabled by\nransomware and data theft [T1657].\n\nAfter gaining access to networks, FBI observed Scattered Spider threat actors using publicly\navailable, legitimate remote access tunneling tools. Table 1 details a list of legitimate tools Scattered\nSpider, repurposed and used for their criminal activity. Note: The use of these legitimate tools alone\nis not indicative of criminal activity. Users should review the Scattered Spider indicators of\ncompromise (IOCs) and TTPs discussed in this CSA to determine whether they have been\ncompromised.\nTable 1: Legitimate Tools Used by Scattered Spider\n\nTool\n\nIntended Use\n\nFleetdeck.io\n\nEnables remote monitoring and management of systems.\n\nLevel.io\n\nEnables remote monitoring and management of systems.\n\nMimikatz [S0002]\n\nExtracts credentials from a system.\n\nNgrok [S0508]\n\nEnables remote access to a local web server by tunneling over the internet.\n\nPulseway\n\nEnables remote monitoring and management of systems.\n\nScreenconnect\n\nEnables remote connections to network devices for management.\n\nPage 2 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\n\nFBI  CISA\n\nTool\n\nIntended Use\n\nSplashtop\n\nEnables remote connections to network devices for management.\n\nTactical.RMM\n\nEnables remote monitoring and management of systems.\n\nTailscale\n\nProvides virtual private networks (VPNs) to secure network communications.\n\nTeamviewer\n\nEnables remote connections to network devices for management.\n\nIn addition to using legitimate tools, Scattered Spider also uses malware as part of its TTPs. See\nTable 2 for some of the malware used by Scattered Spider.\nTable 2: Malware Used by Scattered Spider\n\nMalware\n\nUse\n\nAveMaria (also known as\nWarZone [S0670])\n\nEnables remote access to a victim’s systems.\n\nRaccoon Stealer\n\nSteals information including login credentials [TA0006],\nbrowser history [T1217], cookies [T1539], and other data.\n\nVIDAR Stealer\n\nSteals information including login credentials, browser history,\ncookies, and other data.\n\nScattered Spider threat actors have historically evaded detection on target networks by using living off\nthe land techniques and allowlisted applications to navigate victim networks, as well as frequently\nmodifying their TTPs.\nObservably, Scattered Spider threat actors have exfiltrated data [TA0010] after gaining access and\nthreatened to release it without deploying ransomware; this includes exfiltration to multiple sites\nincluding U.S.-based data centers and MEGA[.]NZ [T1567.002].\n\nRecent Scattered Spider TTPs\nNew TTP - File Encryption\nMore recently, FBI has identified Scattered Spider threat actors now encrypting victim files after\nexfiltration [T1486]. After exfiltrating and/or encrypting data, Scattered Spider threat actors\ncommunicate with victims via TOR, Tox, email, or encrypted applications.\n\nPage 3 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\n\nFBI  CISA\n\nReconnaissance, Resource Development, and Initial Access\nScattered Spider intrusions often begin with broad phishing [T1566] and smishing [T1660] attempts\nagainst a target using victim-specific crafted domains, such as the domains listed in Table 3\n[T1583.001].\nTable 3: Domains Used by Scattered Spider Threat Actors\n\nDomains\nvictimname-sso[.]com\nvictimname-servicedesk[.]com\nvictimname-okta[.]com\nIn most instances, Scattered Spider threat actors conduct SIM swapping attacks against users that\nrespond to the phishing/smishing attempt. The threat actors then work to identify the personally\nidentifiable information (PII) of the most valuable users that succumbed to the phishing/smishing,\nobtaining answers for those users’ security questions. After identifying usernames, passwords, PII\n[T1589], and conducting SIM swaps, the threat actors then use social engineering techniques [T1656]\nto convince IT help desk personnel to reset passwords and/or MFA tokens\n[T1078.002],[T1199],[T1566.004] to perform account takeovers against the users in single sign-on\n(SSO) environments.\n\nExecution, Persistence, and Privilege Escalation\nScattered Spider threat actors then register their own MFA tokens [T1556.006],[T1606] after\ncompromising a user’s account to establish persistence [TA0003]. Further, the threat actors add a\nfederated identity provider to the victim’s SSO tenant and activate automatic account linking\n[T1484.002]. The threat actors are then able to sign into any account by using a matching SSO\naccount attribute. At this stage, the Scattered Spider threat actors already control the identity provider\nand then can choose an arbitrary value for this account attribute. As a result, this activity allows the\nthreat actors to perform privileged escalation [TA0004] and continue logging in even when passwords\nare changed [T1078]. Additionally, they leverage common endpoint detection and response (EDR)\ntools installed on the victim networks to take advantage of the tools’ remote-shell capabilities and\nexecuting of commands which elevates their access. They also deploy remote monitoring and\nmanagement (RMM) tools [T1219] to then maintain persistence.\n\nDiscovery, Lateral Movement, and Exfiltration\nOnce persistence is established on a target network, Scattered Spider threat actors often perform\ndiscovery, specifically searching for SharePoint sites [T1213.002], credential storage documentation\n[T1552.001], VMware vCenter infrastructure [T1018], backups, and instructions for setting up/logging\ninto Virtual Private Networks (VPN) [TA0007]. The threat actors enumerate the victim’s Active\n\nPage 4 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\n\nFBI  CISA\n\nDirectory (AD), perform discovery and exfiltration of victim’s code repositories [T1213.003], codesigning certificates [T1552.004], and source code [T1083],[TA0010]. Threat actors activate Amazon\nWeb Services (AWS) Systems Manager Inventory [T1538] to discover targets for lateral movement\n[TA0007],[TA0008], then move to both preexisting [T1021.007] and actor-created [T1578.002]\nAmazon Elastic Compute Cloud (EC2) instances. In instances where the ultimate goal is data\nexfiltration, Scattered Spider threat actors use actor-installed extract, transform, and load (ETL) tools\n[T1648] to bring data from multiple data sources into a centralized database [T1074],[T1530].\nAccording to trusted third parties, where more recent incidents are concerned, Scattered Spider threat\nactors may have deployed BlackCat/ALPHV ransomware onto victim networks—thereby encrypting\nVMware Elastic Sky X integrated (ESXi) servers [T1486].\nTo determine if their activities have been uncovered and maintain persistence, Scattered Spider\nthreat actors often search the victim’s Slack, Microsoft Teams, and Microsoft Exchange online for\nemails [T1114] or conversations regarding the threat actor’s intrusion and any security response. The\nthreat actors frequently join incident remediation and response calls and teleconferences, likely to\nidentify how security teams are hunting them and proactively develop new avenues of intrusion in\nresponse to victim defenses. This is sometimes achieved by creating new identities in the\nenvironment [T1136] and is often upheld with fake social media profiles [T1585.001] to backstop\nnewly created identities.\n\nMITRE ATT&CK TACTICS AND TECHNIQUES\nSee Tables 4 through 17 for all referenced threat actor tactics and techniques in this advisory.\nTable 4: Reconnaissance\n\nTechnique Title\n\nID\n\nUse\n\nGather Victim Identity\nInformation\n\nT1589\n\nScattered Spider threat actors gather usernames,\npasswords, and PII for targeted organizations.\n\nPhishing for Information\n\nT1598\n\nScattered Spider threat actors use phishing to\nobtain login credentials, gaining access to a\nvictim’s network.\n\nTable 5: Resource Development\n\nTechnique Title\nAcquire Infrastructure:\nDomains\n\nID\n\nUse\n\nT1583.001\n\nScattered Spider threat actors create domains for\nuse in phishing and smishing attempts against\ntargeted organizations.\n\nPage 5 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\nTechnique Title\nEstablish Accounts: Social\nMedia Accounts\n\nFBI  CISA\n\nID\n\nUse\n\nT1585.001\n\nScattered Spider threat actors create fake social\nmedia profiles to backstop newly created user\naccounts in a targeted organization.\n\nTable 6: Initial Access\n\nTechnique Title\n\nPhishing\n\nPhishing (Mobile)\n\nPhishing: Spearphishing Voice\n\nTrusted Relationship\n\nValid Accounts: Domain\nAccounts\n\nID\n\nUse\n\nT1566\n\nScattered Spider threat actors use broad phishing\nattempts against a target to obtain information\nused to gain initial access.\nScattered Spider threat actors have posed as\nhelpdesk personnel to direct employees to install\ncommercial remote access tools.\n\nT1660\n\nScattered Spider threat actors send SMS\nmessages, known as smishing, when targeting a\nvictim.\n\nT1566.004\n\nScattered Spider threat actors use voice\ncommunications to convince IT help desk\npersonnel to reset passwords and/or MFA tokens.\n\nT1199\n\nScattered Spider threat actors abuse trusted\nrelationships of contracted IT help desks to gain\naccess to targeted organizations.\n\nT1078.002\n\nScattered Spider threat actors obtain access to\nvalid domain accounts to gain initial access to a\ntargeted organization.\n\nTable 7: Execution\n\nTechnique Title\nServerless Execution\n\nUser Execution\n\nID\n\nUse\n\nT1648\n\nScattered Spider threat actors use ETL tools to\ncollect data in cloud environments.\n\nT1204\n\nScattered Spider threat actors impersonating\nhelpdesk personnel direct employees to run\ncommercial remote access tools thereby enabling\naccess to the victim’s network.\n\nPage 6 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\n\nFBI  CISA\nTable 8: Persistence\n\nTechnique Title\n\nID\n\nUse\n\nPersistence\n\nTA0003\n\nScattered Spider threat actors seek to maintain\npersistence on a targeted organization’s network.\n\nCreate Account\n\nT1136\n\nScattered Spider threat actors create new user\nidentities in the targeted organization.\n\nT1556.006\n\nScattered Spider threat actors may modify MFA\ntokens to gain access to a victim’s network.\n\nT1078\n\nScattered Spider threat actors abuse and control\nvalid accounts to maintain network access even\nwhen passwords are changed.\n\nModify Authentication Process:\nMulti-Factor Authentication\nValid Accounts\n\nTable 9: Privilege Escalation\n\nTechnique Title\n\nID\n\nUse\n\nPrivilege Escalation\n\nTA0004\n\nScattered Spider threat actors escalate account\nprivileges when on a targeted organization’s\nnetwork.\n\nDomain Policy Modification:\nDomain Trust Modification\n\nT1484.002\n\nScattered Spider threat actors add a federated\nidentify provider to the victim’s SSO tenant and\nactivate automatic account linking.\n\nTable 10: Defense Evasion\n\nTechnique Title\nModify Cloud Compute\nInfrastructure: Create Cloud\nInstance\n\nImpersonation\n\nID\nT1578.002\n\nTA1656\n\nUse\nScattered Spider threat actors will create cloud\ninstances for use during lateral movement and\ndata collection.\nScattered Spider threat actors pose as company\nIT and/or helpdesk staff to gain access to victim’s\nnetworks.\nScattered Spider threat actors use social\nengineering to convince IT help desk personnel to\nreset passwords and/or MFA tokens.\n\nPage 7 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\n\nFBI  CISA\nTable 11: Credential Access\n\nTechnique Title\n\nID\n\nUse\n\nCredential Access\n\nTA0006\n\nScattered Spider threat actors use tools, such as\nRaccoon Stealer, to obtain login credentials.\n\nForge Web Credentials\n\nT1606\n\nScattered Spider threat actors may forge MFA\ntokens to gain access to a victim’s network.\n\nT1621\n\nScattered Spider sends repeated MFA notification\nprompts to lead employees to accept the prompt\nand gain access to the target network.\n\nUnsecured Credentials:\nCredentials in Files\n\nT1552.001\n\nScattered Spider threat actors search for\ninsecurely stored credentials on victim’s systems.\n\nUnsecured Credentials:\nPrivate Keys\n\nT1552.004\n\nScattered Spider threat actors search for\ninsecurely stored private keys on victim’s systems.\n\nMulti-Factor Authentication\nRequest Generation\n\nTable 12: Discovery\n\nTechnique Title\n\nID\n\nUse\n\nDiscovery\n\nTA0007\n\nUpon gaining access to a targeted network,\nScattered Spider threat actors seek out\nSharePoint sites, credential storage\ndocumentation, VMware vCenter, infrastructure\nbackups and enumerate AD to identify useful\ninformation to support further operations.\n\nBrowser Information Discovery\n\nT1217\n\nScattered Spider threat actors use tools (e.g.,\nRaccoon Stealer) to obtain browser histories.\n\nCloud Service Dashboard\n\nT1538\n\nScattered Spider threat actors leverage AWS\nSystems Manager Inventory to discover targets for\nlateral movement.\n\nFile and Directory Discovery\n\nT1083\n\nScattered Spider threat actors search a\ncompromised network to discover files and\ndirectories for further information or exploitation.\n\nRemote System Discovery\n\nT1018\n\nScattered Spider threat actors search for\ninfrastructure, such as remote systems, to exploit.\n\nPage 8 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\nTechnique Title\nSteal Web Session Cookie\n\nFBI  CISA\n\nID\n\nUse\n\nT1539\n\nScattered Spider threat actors use tools, such as\nRaccoon Stealer, to obtain browser cookies.\n\nTable 13: Lateral Movement\n\nTechnique Title\n\nID\n\nUse\n\nLateral Movement\n\nTA0008\n\nScattered Spider threat actors laterally move\nacross a target network upon gaining access and\nestablishing persistence.\n\nT1021.007\n\nScattered Spider threat actors use pre-existing\ncloud instances for lateral movement and data\ncollection.\n\nRemote Services: Cloud\nServices\n\nTable 14: Collection\n\nTechnique Title\n\nID\n\nUse\n\nData from Information\nRepositories: Code\nRepositories\n\nT1213.003\n\nScattered Spider threat actors search code\nrepositories for data collection and exfiltration.\n\nData from Information\nRepositories: Sharepoint\n\nT1213.002\n\nScattered Spider threat actors search SharePoint\nrepositories for information.\n\nT1074\n\nScattered Spider threat actors stage data from\nmultiple data sources into a centralized database\nbefore exfiltration.\n\nEmail Collection\n\nT1114\n\nScattered Spider threat actors search victim’s\nemails to determine if the victim has detected the\nintrusion and initiated any security response.\n\nData from Cloud Storage\n\nT1530\n\nScattered Spider threat actors search data in\ncloud storage for collection and exfiltration.\n\nData Staged\n\nPage 9 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\n\nFBI  CISA\nTable 15: Command and Control\n\nTechnique Title\n\nRemote Access Software\n\nID\n\nUse\n\nT1219\n\nImpersonating helpdesk personnel, Scattered\nSpider threat actors direct employees to run\ncommercial remote access tools thereby enabling\naccess to and command and control of the victim’s\nnetwork.\nScattered Spider threat actors leverage third-party\nsoftware to facilitate lateral movement and\nmaintain persistence on a target organization’s\nnetwork.\n\nTable 16: Exfiltration\n\nTechnique Title\nExfiltration\n\nID\n\nUse\n\nTA0010\n\nScattered Spider threat actors exfiltrate data from\na target network to for data extortion.\n\nTable 17: Impact\n\nTechnique Title\n\nID\n\nUse\n\nData Encrypted for Impact\n\nT1486\n\nScattered Spider threat actors recently began\nencrypting data on a target network and\ndemanding a ransom for decryption.\nScattered Spider threat actors has been observed\nencrypting VMware ESXi servers.\n\nExfiltration Over Web Service:\nExfiltration to Cloud Storage\n\nT1567.002\n\nScattered Spider threat actors exfiltrate data to\nmultiple sites including U.S.-based data centers\nand MEGA[.]NZ.\n\nT1657\n\nScattered Spider threat actors monetized access\nto victim networks in numerous ways including\nextortion-enabled ransomware and data theft.\n\nFinancial Theft\n\nPage 10 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\n\nFBI  CISA\n\nMITIGATIONS\nFBI and CISA recommend organizations implement\nThese mitigations apply to all critical\nthe mitigations below to improve your organization’s\ninfrastructure organizations and network\ncybersecurity posture based on the threat actor\ndefenders. FBI and CISA recommend that\nactivity and to reduce the risk of compromise by\nsoftware manufactures incorporate secureScattered Spider threat actors. These mitigations align\nby-design and -default principles and tactics\nwith the Cross-Sector Cybersecurity Performance\ninto their software development practices\nGoals (CPGs) developed by CISA and the National\nlimiting the impact of ransomware\nInstitute of Standards and Technology (NIST). The\ntechniques, thus, strengthening the secure\nCPGs provide a minimum set of practices and\nposture for their customers.\nprotections that CISA and NIST recommend all\norganizations implement. CISA and NIST based the For more information on secure by design,\nCPGs on existing cybersecurity frameworks and see CISA’s Secure by Design and Default\nwebpage and joint guide.\nguidance to protect against the most common and\nimpactful threats, tactics, techniques, and procedures.\nVisit CISA’s Cross-Sector Cybersecurity Performance Goals for more information on the CPGs,\nincluding additional recommended baseline protections.\n•\n\n•\n\n•\n\nImplement application controls to manage and control execution of software, including\nallowlisting remote access programs. Application controls should prevent installation and\nexecution of portable versions of unauthorized remote access and other software. A properly\nconfigured application allowlisting solution will block any unlisted application execution.\nAllowlisting is important because antivirus solutions may fail to detect the execution of\nmalicious portable executables when the files use any combination of compression,\nencryption, or obfuscation.\nReduce threat of malicious actors using remote access tools by:\no Auditing remote access tools on your network to identify currently used and/or\nauthorized software.\no Reviewing logs for execution of remote access software to detect abnormal use of\nprograms running as a portable executable [CPG 2.T].\no Using security software to detect instances of remote access software being loaded only\nin memory.\no Requiring authorized remote access solutions to be used only from within your network\nover approved remote access solutions, such as virtual private networks (VPNs) or virtual\ndesktop interfaces (VDIs).\no Blocking both inbound and outbound connections on common remote access\nsoftware ports and protocols at the network perimeter.\no Applying recommendations in the Guide to Securing Remote Access Software.\nImplementing FIDO/WebAuthn authentication or Public Key Infrastructure (PKI)-based\nMFA. These MFA implementations are resistant to phishing and not suspectable to push\nbombing or SIM swap attacks, which are techniques known to be used by Scattered Spider\nactors. See CISA’s fact sheet Implementing Phishing-Resistant MFA for more information.\n\nPage 11 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\n•\n\nFBI  CISA\n\nStrictly limit the use of Remote Desktop Protocol (RDP) and other remote desktop\nservices. If RDP is necessary, rigorously apply best practices, for example [CPG 2.W]:\no Audit the network for systems using RDP.\no Close unused RDP ports.\no Enforce account lockouts after a specified number of attempts.\no Apply phishing-resistant multifactor authentication (MFA).\no Log RDP login attempts.\n\nIn addition, the authoring authorities of this CSA recommend network defenders apply the following\nmitigations to limit potential adversarial use of common system and network discovery techniques,\nand to reduce the impact and risk of compromise by ransomware or data extortion actors:\n•\n\n•\n\n•\n\n•\n\n•\n\n•\n\nImplement a recovery plan to maintain and retain multiple copies of sensitive or proprietary\ndata and servers in a physically separate, segmented, and secure location (i.e., hard drive,\nstorage device, the cloud).\nMaintain offline backups of data and regularly maintain backup and restoration (daily or\nweekly at minimum). By instituting this practice, an organization limits the severity of disruption\nto its business practices [CPG 2.R].\nRequire all accounts with password logins (e.g., service account, admin accounts, and\ndomain admin accounts) to comply with NIST's standards for developing and managing\npassword policies.\no Use longer passwords consisting of at least eight characters and no more than 64\ncharacters in length [CPG 2.B].\no Store passwords in hashed format using industry-recognized password managers.\no Add password user “salts” to shared login credentials.\no Avoid reusing passwords [CPG 2.C].\no Implement multiple failed login attempt account lockouts [CPG 2.G].\no Disable password “hints.”\no Refrain from requiring password changes more frequently than once per year.\nNote: NIST guidance suggests favoring longer passwords instead of requiring regular and\nfrequent password resets. Frequent password resets are more likely to result in users\ndeveloping password “patterns” cyber criminals can easily decipher.\no Require administrator credentials to install software.\nRequire phishing-resistant multifactor authentication (MFA) for all services to the extent\npossible, particularly for webmail, virtual private networks (VPNs), and accounts that access\ncritical systems [CPG 2.H].\nKeep all operating systems, software, and firmware up to date. Timely patching is one of\nthe most efficient and cost-effective steps an organization can take to minimize its exposure to\ncybersecurity threats. Prioritize patching known exploited vulnerabilities in internet-facing\nsystems [CPG 1.E].\nSegment networks to prevent the spread of ransomware. Network segmentation can help\nprevent the spread of ransomware by controlling traffic flows between—and access to—\nvarious subnetworks and by restricting adversary lateral movement [CPG 2.F].\n\nPage 12 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\n•\n\n•\n•\n•\n•\n•\n\nFBI  CISA\n\nIdentify, detect, and investigate abnormal activity and potential traversal of the\nindicated ransomware with a networking monitoring tool. To aid in detecting the\nransomware, implement a tool that logs and reports all network traffic and activity, including\nlateral movement, on a network. Endpoint detection and response (EDR) tools are particularly\nuseful for detecting lateral connections as they have insight into common and uncommon\nnetwork connections for each host [CPG 3.A].\nInstall, regularly update, and enable real time detection for antivirus software on all\nhosts.\nDisable unused ports and protocols [CPG 2.V].\nConsider adding an email banner to emails received from outside your organization [CPG\n2.M].\nDisable hyperlinks in received emails.\nEnsure all backup data is encrypted, immutable (i.e., ensure backup data cannot be\naltered or deleted), and covers the entire organization’s data infrastructure [CPG 2.K, 2.L,\n2.R].\n\nVALIDATE SECURITY CONTROLS\nIn addition to applying mitigations, FBI and CISA recommend exercising, testing, and validating your\norganization's security program against the threat behaviors mapped to the MITRE ATT&CK for\nEnterprise framework in this advisory. FBI and CISA recommend testing your existing security\ncontrols inventory to assess how they perform against the ATT&CK techniques described in this\nadvisory.\nTo get started:\n1.\n2.\n3.\n4.\n5.\n\nSelect an ATT&CK technique described in this advisory (see Tables 4-17).\nAlign your security technologies against the technique.\nTest your technologies against the technique.\nAnalyze your detection and prevention technologies’ performance.\nRepeat the process for all security technologies to obtain a set of comprehensive performance\ndata.\n6. Tune your security program, including people, processes, and technologies, based on the\ndata generated by this process.\nFBI and CISA recommend continually testing your security program, at scale, in a production\nenvironment to ensure optimal performance against the MITRE ATT&CK techniques identified in this\nadvisory.\n\nREPORTING\nFBI and CISA are seeking any information that can be shared, to include a sample ransom note,\ncommunications with Scattered Spider group actors, Bitcoin wallet information, decryptor files, and/or\na benign sample of an encrypted file. FBI and CISA do not encourage paying ransom as payment\ndoes not guarantee victim files will be recovered. Furthermore, payment may also embolden\nadversaries to target additional organizations, encourage other criminal actors to engage in the\n\nPage 13 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR\n\nTLP:CLEAR\n\nFBI  CISA\n\ndistribution of ransomware, and/or fund illicit activities. Regardless of whether you or your\norganization have decided to pay the ransom, FBI and CISA urge you to promptly report ransomware\nincidents to a local FBI Field Office, report the incident to FBI’s Internet Crime Complaint Center (IC3)\nat IC3.gov, or CISA via CISA’s 24/7 Operations Center (report@cisa.gov or 888-282-0870).\n\nREFERENCES\n[1] MITRE ATT&CK – Scattered Spider\n[2] Trellix - Scattered Spider: The Modus Operandi\n[3] Crowdstrike - Not a SIMulation: CrowdStrike Investigations Reveal Intrusion Campaign Targeting\nTelco and BPO Companies\n[4] Crowdstrike - SCATTERED SPIDER Exploits Windows Security Deficiencies with Bring-YourOwn-Vulnerable-Driver Tactic in Attempt to Bypass Endpoint Security\n[5] Malwarebytes - Ransomware group steps up, issues statement over MGM Resorts compromise\n\nDISCLAIMER\nThe information in this report is being provided “as is” for informational purposes only. FBI and CISA\ndo not endorse any commercial entity, product, company, or service, including any entities, products,\nor services linked within this document. Any reference to specific commercial entities, products,\nprocesses, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or\nimply endorsement, recommendation, or favoring by FBI and CISA.\n\nVERSION HISTORY\nNovember 16, 2023: Initial version.\n\nPage 14 of 14 | Product ID: AA23-320A\n\nTLP:CLEAR",
            "language": "EN",
            "sources":
            [
                {
                    "id": "bf5be533-fa31-4590-ae37-5761c97ffa34",
                    "created_at": "2022-10-25T16:13:58.389257Z",
                    "updated_at": "2022-10-25T16:13:58.389257Z",
                    "deleted_at": None,
                    "name": "Malpedia",
                    "url": "https://malpedia.caad.fkie.fraunhofer.de",
                    "description": "Malpedia is a free service offered by Fraunhofer FKIE",
                    "reports": None
                }
            ],
            "references":
            [
                "https://www.cisa.gov/sites/default/files/2023-11/aa23-320a_scattered_spider.pdf"
            ],
            "report_names":
            [
                "aa23-320a_scattered_spider.pdf"
            ],
            "threat_actors":
            [
                {
                    "id": "6e23ce43-e1ab-46e3-9f80-76fccf77682b",
                    "created_at": "2022-10-25T16:07:23.303713Z",
                    "updated_at": "2023-11-22T02:02:28.332741Z",
                    "deleted_at": None,
                    "main_name": "ALPHV",
                    "aliases":
                    [
                        "ALPHV",
                        "ALPHVM",
                        "BlackCat Gang",
                        "UNC4466"
                    ],
                    "source_name": "ETDA:ALPHV",
                    "tools":
                    [
                        "ALPHV",
                        "ALPHVM",
                        "BlackCat",
                        "GO Simple Tunnel",
                        "GOST",
                        "Impacket",
                        "LaZagne",
                        "MEGAsync",
                        "Mimikatz",
                        "Noberus",
                        "PsExec",
                        "Remcom",
                        "RemoteCommandExecution",
                        "WebBrowserPassView"
                    ],
                    "source_id": "ETDA",
                    "reports": None
                },
                {
                    "id": "9ddc7baf-2ea7-4294-af2c-5fce1021e8e8",
                    "created_at": "2023-06-23T02:04:34.386651Z",
                    "updated_at": "2023-11-22T02:02:28.688114Z",
                    "deleted_at": None,
                    "main_name": "Muddled Libra",
                    "aliases":
                    [
                        "0ktapus",
                        "Scatter Swine",
                        "Scattered Spider"
                    ],
                    "source_name": "ETDA:Muddled Libra",
                    "tools":
                    [],
                    "source_id": "ETDA",
                    "reports": None
                },
                {
                    "id": "d90307b6-14a9-4d0b-9156-89e453d6eb13",
                    "created_at": "2022-10-25T16:07:23.773944Z",
                    "updated_at": "2023-11-22T02:02:28.639545Z",
                    "deleted_at": None,
                    "main_name": "Lead",
                    "aliases":
                    [
                        "Casper",
                        "TG-3279"
                    ],
                    "source_name": "ETDA:Lead",
                    "tools":
                    [
                        "Agentemis",
                        "BleDoor",
                        "Cobalt Strike",
                        "CobaltStrike",
                        "RbDoor",
                        "RibDoor",
                        "Winnti",
                        "cobeacon"
                    ],
                    "source_id": "ETDA",
                    "reports": None
                },
                {
                    "id": "7da6012f-680b-48fb-80c4-1b8cf82efb9c",
                    "created_at": "2023-11-01T02:01:06.643737Z",
                    "updated_at": "2023-11-22T02:00:52.815732Z",
                    "deleted_at": None,
                    "main_name": "Scattered Spider",
                    "aliases":
                    [
                        "Scattered Spider",
                        "Roasted 0ktapus"
                    ],
                    "source_name": "MITRE:Scattered Spider",
                    "tools": None,
                    "source_id": "MITRE",
                    "reports": None
                },
                {
                    "id": "c3b908de-3dd1-4e5d-ba24-5af8217371f0",
                    "created_at": "2023-10-03T02:00:08.510742Z",
                    "updated_at": "2023-11-22T02:00:07.090483Z",
                    "deleted_at": None,
                    "main_name": "Scattered Spider",
                    "aliases":
                    [
                        "UNC3944",
                        "Muddled Libra",
                        "Oktapus",
                        "Scattered Swine"
                    ],
                    "source_name": "MISPGALAXY:Scattered Spider",
                    "tools":
                    [],
                    "source_id": "MISPGALAXY",
                    "reports": None
                },
                {
                    "id": "d093e8d9-b093-47b8-a988-2a5cbf3ccec9",
                    "created_at": "2023-10-14T02:03:13.99057Z",
                    "updated_at": "2023-11-22T02:02:28.334199Z",
                    "deleted_at": None,
                    "main_name": "Scattered Spider",
                    "aliases":
                    [
                        "0ktapus",
                        "LUCR-3",
                        "Muddled Libra",
                        "Scatter Swine",
                        "Scattered Spider",
                        "Storm-0875",
                        "UNC3944"
                    ],
                    "source_name": "ETDA:Scattered Spider",
                    "tools":
                    [
                        "DCSync",
                        "Impacket",
                        "Lumma Stealer",
                        "LummaC2",
                        "Mimikatz",
                        "ProcDump",
                        "PsExec",
                        "RedLine Stealer",
                        "SharpHound",
                        "Spidey Bot",
                        "Stealc",
                        "VIDAR",
                        "Vidar Stealer",
                        "WinRAR"
                    ],
                    "source_id": "ETDA",
                    "reports": None
                },
                {
                    "id": "cf4cc019-162d-4c21-bdb0-44bdf5b2a55e",
                    "created_at": "2023-06-30T02:07:28.50971Z",
                    "updated_at": "2023-08-17T02:05:36.877957Z",
                    "deleted_at": None,
                    "main_name": "GOLD HARVEST",
                    "aliases":
                    [
                        "Roasted 0ktapus ",
                        "Scattered Spider ",
                        "UNC3944 "
                    ],
                    "source_name": "Secureworks:GOLD HARVEST",
                    "tools":
                    [
                        "AnyDesk",
                        "ConnectWise Control",
                        "Logmein"
                    ],
                    "source_id": "Secureworks",
                    "reports": None
                }
            ],
            "ts_created_at": 1700273243,
            "ts_updated_at": 1700619619,
            "ts_creation_date": 1700055214,
            "ts_modification_date": 1700055612,
            "files":
            {
                "pdf": "https://pub-7cb8ac806c1b4c4383e585c474a24719.r2.dev/366fd71c47469498d1a037693c879f632752b5b4.pdf",
                "text": "https://pub-7cb8ac806c1b4c4383e585c474a24719.r2.dev/366fd71c47469498d1a037693c879f632752b5b4.txt",
                "img": "https://pub-7cb8ac806c1b4c4383e585c474a24719.r2.dev/366fd71c47469498d1a037693c879f632752b5b4.jpg"
            }
        }
    ],
    "message": "library entries",
    "status": "success"
}
