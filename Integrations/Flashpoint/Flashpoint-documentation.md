Use flashpoint integration for reduce business risk. The integration was
integrated and tested with Demisto 5.0 This integration was integrated
and tested with version xx of Flashpoint

Detailed Description
--------------------

Populate this section with the .md file contents for detailed
description.

Fetch Incidents
---------------

Populate this section with Fetch incidents data

Configure Flashpoint on Demisto
-------------------------------

1.  Navigate to **Settings** \> **Integrations**  \> **Servers &
    Services**.
2.  Search for Flashpoint.
3.  Click **Add instance** to create and configure a new integration
    instance.
    -   **Name**: a textual name for the integration instance.
    -   **API Key**

4.  Click **Test** to validate the new instance.

Commands
--------

You can execute these commands from the Demisto CLI, as part of an
automation, or in a playbook. After you successfully execute a command,
a DBot message appears in the War Room with the command details.

1.  [Lookup the "IP" type indicator details: ip](#ip)
2.  [Lookup the "Domain" type indicator details: domain](#domain)
3.  [Lookup the "Filename" type indicator details: filename](#filename)
4.  [Lookup the "URL" type indicator details: url](#url)
5.  [Lookup the "File" type indicator details: file](#file)
6.  [Lookup the "Email" type indicator details: email](#email)
7.  [Search for the Intelligence Reports using a keyword:
    flashpoint-search-intelligence-reports](#flashpoint-search-intelligence-reports)
8.  [Get a single report by its ID:
    flashpoint-get-single-intelligence-report](#flashpoint-get-single-intelligence-report)
9.  [Get related reports for a given report id:
    flashpoint-get-related-reports](#flashpoint-get-related-reports)
10. [For getting single event:
    flashpoint-get-single-event](#flashpoint-get-single-event)
11. [Get all event details:
    flashpoint-get-events](#flashpoint-get-events)
12. [Lookup any type of indicator:
    flashpoint-common-lookup](#flashpoint-common-lookup)
13. [Get forum details:
    flashpoint-get-forum-details](#flashpoint-get-forum-details)
14. [Get room details:
    flashpoint-get-forum-room-details](#flashpoint-get-forum-room-details)
15. [Get user details:
    flashpoint-get-forum-user-details](#flashpoint-get-forum-user-details)
16. [Get post details:
    flashpoint-get-forum-post-details](#flashpoint-get-forum-post-details)
17. [Search forum sites using a keyword:
    flashpoint-search-forum-sites](#flashpoint-search-forum-sites)
18. [Search forum posts using a keyword:
    flashpoint-search-forum-posts](#flashpoint-search-forum-posts)

### 1. ip

* * * * *

Lookup the "IP" type indicator details

##### Base Command

`ip`

##### Input

  **Argument Name**   **Description**    **Required**
  ------------------- ------------------ --------------
  ip                  Enter ip address   Required

 

##### Context Output

There are no context output for this command.

 

##### Command Example

`!ip ip="210.122.7.129"`

##### Context Example

    {
        "DBotScore": {
            "Indicator": "210.122.7.129",
            "Score": 3,
            "Type": "ip",
            "Vendor": "Flashpoint"
        },
        "IP": {
            "Address": "210.122.7.129",
            "Flashpoint": {
                "href": [
                    "https://fp.tools/api/v4/indicators/attribute/KyhpGHc2XYKp2iUESO7ejA"
                ]
            },
            "Malicious": {
                "Description": "Found in malicious indicators dataset",
                "Vendor": "Flashpoint"
            }
        }
    }

##### Human Readable Output

### Flashpoint IP address reputation for 210.122.7.129

Reputation: Malicious

### Events in which this IOC observed

  **Date Observed (UTC)**   **Name**                                                     **Tags**
  ------------------------- ------------------------------------------------------------ --------------
  Feb 12, 2018 21:46        Lazarus Resurfaces, Targets Global Banks and Bitcoin Users   source:OSINT

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=ip-dst%2Cip-src&ioc\_value=210.122.7.129](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=ip-dst%2Cip-src&ioc\_value=210.122.7.129)

### 2. domain

* * * * *

Lookup the "Domain" type indicator details

##### Base Command

`domain`

##### Input

  **Argument Name**   **Description**     **Required**
  ------------------- ------------------- --------------
  domain              Enter domain name   Required


##### Command Example

`!domain domain="subaat.com"`

##### Context Example

    {
        "DBotScore": {
            "Indicator": "subaat.com",
            "Score": 3,
            "Type": "domain",
            "Vendor": "Flashpoint"
        },
        "Domain": {
            "Flashpoint": {
                "href": [
                    "https://fp.tools/api/v4/indicators/attribute/ua5eL6q5W5CTmYcmAhS0XQ"
                ]
            },
            "Malicious": {
                "Description": "Found in malicious indicators dataset",
                "Vendor": "Flashpoint"
            },
            "Name": "subaat.com"
        }
    }

##### Human Readable Output

### Flashpoint Domain reputation for subaat.com

Reputation: Malicious

### Events in which this IOC observed

  **Date Observed (UTC)**   **Name**                     **Tags**
  ------------------------- ---------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Sep 25, 2019 19:51        Gorgon Group actor profile   misp-galaxy:mitre-enterprise-attack-attack-pattern="Spearphishing Attachment - T1193", misp-galaxy:mitre-enterprise-attack-attack-pattern="Scripting - T1064", misp-galaxy:mitre-enterprise-attack-attack-pattern="Command-Line Interface - T1059", misp-galaxy:mitre-enterprise-attack-attack-pattern="System Information Discovery - T1082", misp-galaxy:mitre-enterprise-attack-attack-pattern="Remote Services - T1021", misp-galaxy:mitre-enterprise-attack-attack-pattern="Exfiltration Over Command and Control Channel - T1041", os:Windows, source:phishing, type:RAT, malware:rat:Quasar, malware:banker:Lokibot, file\_name: njrat.exe, file\_name: excel\_.exe

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=domain&ioc\_value=subaat.com](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=domain&ioc\_value=subaat.com)

### 3. filename

* * * * *

Lookup the "Filename" type indicator details

##### Base Command

`filename`

##### Input

  **Argument Name**   **Description**   **Required**
  ------------------- ----------------- --------------
  filename            Enter file-name   Required

##### Command Example

`!filename filename=".locked"`

##### Context Example

    {
        "DBotScore": {
            "Indicator": ".locked",
            "Score": 3,
            "Type": "filename",
            "Vendor": "Flashpoint"
        }
    }

##### Human Readable Output

### Flashpoint Filename reputation for .locked

Reputation: Malicious

### Events in which this IOC observed

  **Date Observed (UTC)**   **Name**     **Tags**
  ------------------------- ------------ -------------------------------------------------------------------------------------------------------------------------------------------------------------
  Oct 24, 2019 16:30        LockerGoga   malware:ransomware:lockergoga, report:lKyimEX1TWS8x6AtdiJ\_vA, report:jEteM4YxQZCdm4macbE3vQ, report:w0fL5MgoQ\_Wih8XyB6Lowg, report:7t-BsuFKTL-HJWbid8nupg

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=filename&ioc\_value=.locked](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=filename&ioc\_value=.locked)

### 4. url

* * * * *

Lookup the "URL" type indicator details

##### Base Command

`url`

##### Input

  **Argument Name**   **Description**   **Required**
  ------------------- ----------------- --------------
  url                 Enter url         Required


##### Command Example

`!url url="92.63.197.153/krabaldento.exe"`

##### Context Example

    {
        "DBotScore": {
            "Indicator": "92.63.197.153/krabaldento.exe",
            "Score": 3,
            "Type": "url",
            "Vendor": "Flashpoint"
        },
        "URL": {
            "Flashpoint": {
                "href": [
                    "https://fp.tools/api/v4/indicators/attribute/XEAP2wmHVqaHERj7E23gTg"
                ]
            },
            "Malicious": {
                "Description": "Found in malicious indicators dataset",
                "Vendor": "Flashpoint"
            },
            "Name": "92.63.197.153/krabaldento.exe"
        }
    }

##### Human Readable Output

### Flashpoint URL reputation for 92.63.197.153/krabaldento.exe

Reputation: Malicious

### Events in which this IOC observed

  **Date Observed (UTC)**   **Name**        **Tags**
  ------------------------- --------------- --------------------------------------------------------------------------------------------
  Oct 24, 2019 16:30        GandCrab 2019   malware:ransomware:GandCrab, report:lKyimEX1TWS8x6AtdiJ\_vA, report:7t-BsuFKTL-HJWbid8nupg

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=url&ioc\_value=92.63.197.153/krabaldento.exe](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=url&ioc\_value=92.63.197.153/krabaldento.exe)

### 5. file

* * * * *

Lookup the "File" type indicator details

##### Base Command

`file`

##### Input

  **Argument Name**   **Description**                             **Required**
  ------------------- ------------------------------------------- --------------
  file                Enter file. It may sha1, md5, sha256 etc.   Required

##### Command Example

`!file file="ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5"`

##### Context Example

    {
        "DBotScore": {
            "Indicator": "ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5",
            "Score": 3,
            "Type": "sha256",
            "Vendor": "Flashpoint"
        },
        "File": {
            "Flashpoint": {
                "href": [
                    "https://fp.tools/api/v4/indicators/attribute/rqIX70QLVlC3aAydF8uECQ",
                    "https://fp.tools/api/v4/indicators/attribute/9oi7LdmmWGuh1AG4fKv13g"
                ]
            },
            "Malicious": {
                "Description": "Found in malicious indicators dataset",
                "Vendor": "Flashpoint"
            },
            "sha256": "ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5"
        }
    }

##### Human Readable Output

### Flashpoint File reputation for ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5

Reputation: Malicious

### Events in which this IOC observed

  **Date Observed (UTC)**   **Name**                   **Tags**
  ------------------------- -------------------------- ----------------------------------------------------------------------------
  Nov 29, 2019 06:02        Gandcrab                   source:VirusTotal, type:Ransomware, gandcrab, malware:GandCrab, os:Windows
  Jul 17, 2019 18:02        win\_ransomware\_generic   source:VirusTotal, type:Ransomware, win\_ransomware\_generic, os:Windows

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=md5%2Csha1%2Csha256%2Csha512&ioc\_value=ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=md5%2Csha1%2Csha256%2Csha512&ioc\_value=ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5)

### 6. email

* * * * *

Lookup the "Email" type indicator details

##### Base Command

`email`

##### Input

  **Argument Name**   **Description**     **Required**
  ------------------- ------------------- --------------
  email               Enter valid email   Required


##### Command Example

`!email email="qicifomuejijika@o2.pl"`

##### Context Example

    {
        "Account.Email": {
            "Flashpoint": {
                "href": [
                    "https://fp.tools/api/v4/indicators/attribute/TrwIYc5AWP-xtjODCXyp7w"
                ]
            },
            "Malicious": {
                "Description": "Found in malicious indicators dataset",
                "Vendor": "Flashpoint"
            },
            "Name": "qicifomuejijika@o2.pl"
        },
        "DBotScore": {
            "Indicator": "qicifomuejijika@o2.pl",
            "Score": 3,
            "Type": "email",
            "Vendor": "Flashpoint"
        }
    }

##### Human Readable Output

### Flashpoint Email reputation for qicifomuejijika@o2.pl

Reputation: Malicious

### Events in which this IOC observed

  **Date Observed (UTC)**   **Name**     **Tags**
  ------------------------- ------------ -------------------------------------------------------------------------------------------------------------------------------------------------------------
  Oct 24, 2019 16:30        LockerGoga   malware:ransomware:lockergoga, report:lKyimEX1TWS8x6AtdiJ\_vA, report:jEteM4YxQZCdm4macbE3vQ, report:w0fL5MgoQ\_Wih8XyB6Lowg, report:7t-BsuFKTL-HJWbid8nupg

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=email-dst%2Cemail-src%2Cemail-src-display-name%2Cemail-subject&ioc\_value=qicifomuejijika%40o2.pl](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=email-dst%2Cemail-src%2Cemail-src-display-name%2Cemail-subject&ioc\_value=qicifomuejijika%40o2.pl)

### 7. flashpoint-search-intelligence-reports

* * * * *

Search for the Intelligence Reports using a keyword

##### Base Command

`flashpoint-search-intelligence-reports`

##### Input

  **Argument Name**   **Description**                       **Required**
  ------------------- ------------------------------------- --------------
  report\_search      Search report using keyword or text   Required


##### Command Example

`!flashpoint-search-intelligence-reports report_search="isis"`

##### Context Example

    {}

##### Human Readable Output

### Flashpoint Intelligence reports related to search: isis

Top 5 reports: 1) [Telegram Targets ISIS Propaganda in Largest Platform
Purge](https://fp.tools/home/intelligence/reports/report/Kd1HMXJQRYmKDmECAmsPMA\#detail)
Summary: Between November 22 and 24, 2019, Telegram removed more than
7,000 jihadist channnels and bots from its platform?in the largest purge
of ISIS propaganda in Telegram?s history. The takedown drastically
impacted ISIS propaganda dissemination, knocking out critical channels
and groups, many of which had operated uninterrupted for years. 2) [Iran
Global Spotlight (Analyst Knowledge
Page)](https://fp.tools/home/intelligence/reports/report/WFhcFuASR3CbxbC6IzuKBA\#detail)
Summary: N/A 3) [Global Spotlight - Iran: Key Developments This
Week](https://fp.tools/home/intelligence/reports/report/mwpd9Dn7SuO\_K7KLPzfJeA\#detail)
Summary: N/A 4) [Dropbox Account Disseminates Far-Right Extremist
Content](https://fp.tools/home/intelligence/reports/report/pRtNw1SETZOD71IRNakVCA\#detail)
Summary: Flashpoint analysts have identified a Dropbox account called
?NS Library? belonging to a far-right extremist containing over 200
white supremacist publications and guides?including neo-Nazi literature
and propaganda, instruction manuals for making homemade weapons,
survival guides, attackers? manifestos, and workout manuals, among other
content. 5) [ISIS Activity Continues Unabated Following al-Baghdadi's
Death](https://fp.tools/home/intelligence/reports/report/hrPmox3jSxyk5zkgTRmLjw\#detail)
Summary: On October 26, 2019, ISIS?s former leader Abu Bakr al-Baghdadi
killed himself in the midst of a US military operation. Less than a week
later, ISIS confirmed al-Baghdadi?s death, and announced that Abu
Ibrahim al-Hashimi al-Qurashi is the group?s new leader. Link to
Report-search on Flashpoint platform:
[https://fp.tools/home/search/reports?query=isis](https://fp.tools/home/search/reports?query=isis)

### 8. flashpoint-get-single-intelligence-report

* * * * *

Get a single report by its ID

##### Base Command

`flashpoint-get-single-intelligence-report`

##### Input

  **Argument Name**   **Description**                **Required**
  ------------------- ------------------------------ --------------
  report\_id          Search report by report fpid   Required


##### Command Example

`!flashpoint-get-single-intelligence-report report_id="e-QdYuuwRwCntzRljzn9-A"`

##### Context Example

    {
        "Flashpoint.Report.notified_at": "2019-09-23T20:27:20.638+00:00",
        "Flashpoint.Report.platform_url": "https://fp.tools/home/intelligence/reports/report/e-QdYuuwRwCntzRljzn9-A#detail",
        "Flashpoint.Report.posted_at": "2019-09-23T20:27:20.638+00:00",
        "Flashpoint.Report.summary": "On September 17, 2019, multiple pro-ISIS Telegram groups disseminated a message warning of the dangers of exposed exif data?a type of metadata showing GPS coordinates, time, and date the image was taken and the make and model of the device used?that is typically captured from images taken by a phone or camera, unless the security settings are properly configured.",
        "Flashpoint.Report.title": "ISIS Supporters Warn of the Risks Associated with Exif Data",
        "Flashpoint.Report.updated_at": "2019-09-23T20:27:20.638+00:00"
    }

##### Human Readable Output

### Flashpoint Intelligence Report details

### Below are the details found:

  **Title**                                                                                                                                         **Date Published (UTC)**   **Summary**                                                                                                                                                                                                                                                                                                                                                                     **Tags**
  ------------------------------------------------------------------------------------------------------------------------------------------------- -------------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ------------------------------------------------------------------------------------------------------------
  [ISIS Supporters Warn of the Risks Associated with Exif Data](https://fp.tools/home/intelligence/reports/report/e-QdYuuwRwCntzRljzn9-A\#detail)   Sep 23, 2019 20:27         On September 17, 2019, multiple pro-ISIS Telegram groups disseminated a message warning of the dangers of exposed exif data?a type of metadata showing GPS coordinates, time, and date the image was taken and the make and model of the device used?that is typically captured from images taken by a phone or camera, unless the security settings are properly configured.   Intelligence Report, Law Enforcement & Military, Physical Threats, Jihadist, Propaganda, Terrorism, Global

### 9. flashpoint-get-related-reports

* * * * *

Get related reports for a given report id

##### Base Command

`flashpoint-get-related-reports`


##### Input

  **Argument Name**   **Description**                         **Required**
  ------------------- --------------------------------------- --------------
  report\_id          Search related report by report fpid.   Required


##### Command Example

`!flashpoint-get-related-reports report_id="tiPqg51OQpOTsoFyTaYa_w"`

##### Context Example

    {}

##### Human Readable Output

### Flashpoint Intelligence related reports:

Top 5 related reports: 1) [Atomwaffen Division Resumes Recruitment
Activity](https://fp.tools/home/intelligence/reports/report/X6YSFdWWQ3yDa9\_0r627sg\#detail)
Summary: On September 30, 2019, the admin of ?The\_Bowlcast? Telegram
channel promoted the launch of the militant, white supremacist group
?Atomwaffen Division?s? (AWD) latest website and new video dubbed
?Nuclear Congress 2019,? which subtlely discusses the need for AWD to
accomplish its goals?alluding to the need for new financing and
recruitment. 2) [iFunny: Arrests Reveal Violent Far-Right
Activity](https://fp.tools/home/intelligence/reports/report/IpIgbStQS8yprb4nqzLW4Q\#detail)
Summary: The August 2019 arrests of two individuals making threatening
posts on the meme-sharing app iFunny reveal an active far-right
extremist presence on the platform. The arrests appear to have prompted
changes to the site?s search functions and the removal of prominent
far-right accounts. 3) [Neo-Nazi Telegram Channel Incites Violence,
Spreads Extremist
Content](https://fp.tools/home/intelligence/reports/report/90paj4gCSBG8FT8R\_SCtgQ\#detail)
Summary: In August 2019, militant white supremacist channel ?Stack the
Bodies to God? appeared on Telegram, inciting violence and providing a
large quantity of informational resources?including extremist
publications, tactical manuals, survival guides, guerrilla warfare
tactics, instructions for making homemade explosives, weapons, and
ricin, and internet security tips. 4) [Far-Right Prepares for "Meme War
2020"](https://fp.tools/home/intelligence/reports/report/pQBUFAlfSce-xQd7Ignmyg\#detail)
Summary: Members of the far-right community are preparing for what they
call ?meme war 2020??content spread via social media focused on
left-leaning targets?in the lead up to the 2020 U.S. presidential
election. 5) ["Boogaloo": Accelerationists' Latest Call to
Action](https://fp.tools/home/intelligence/reports/report/iEOIjuPjREmCIJR7Krbpnw\#detail)
Summary: The term ?boogaloo? (also known as ?the boogaloo? and ?big
igloo?) is the latest term used by accelerationists?advocates of
hastening the collapse of society through violence?to describe an armed
revolution against society to rebuild a white-ethno state. Link to the
given Report on Flashpoint platform:
[https://fp.tools/home/intelligence/reports/report/tiPqg51OQpOTsoFyTaYa\_w\#detail](https://fp.tools/home/intelligence/reports/report/tiPqg51OQpOTsoFyTaYa\_w\#detail)

### 10. flashpoint-get-single-event

* * * * *

For getting single event

##### Base Command

`flashpoint-get-single-event`

##### Input

  **Argument Name**   **Description**                                        **Required**
  ------------------- ------------------------------------------------------ --------------
  event\_id           The UUID or FPID that identifies a particular event.   Required


##### Command Example

`!flashpoint-get-single-event event_id=Hu2SoTWJWteLrH9mR94JbQ`

##### Context Example

    {
        "Flashpoint": {
            "event": {
                "date": "Jun 18, 2019  22:08",
                "event_creator_email": "info@flashpoint-intel.com",
                "href": "https://fp.tools/api/v4/indicators/event/Hu2SoTWJWteLrH9mR94JbQ",
                "tag": "source:CryptingService2"
            }
        }
    }

##### Human Readable Output

### Flashpoint Event details

### Below are the detail found:

  **Observed time (UTC)**   **Name**                                                                                                                                                                       **Tags**
  ------------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -------------------------
  Jun 18, 2019 22:08        [CryptingService\_4c0d570ecdf23529c91b8decf27107db5c5e9430\_2019-06-17T03:01:03.000Z](https://fp.tools/home/technical\_data/iocs/items/5d0960cc-6128-4416-9996-05d20a640c05)   source:CryptingService2

### 11. flashpoint-get-events

* * * * *

Get all event details

##### Base Command

`flashpoint-get-events`

##### Input

  **Argument Name**   **Description**                                                                          **Required**
  ------------------- ---------------------------------------------------------------------------------------- --------------
  time\_period        Specified time period. Search events based on time period.                               Optional
  report\_fpid        Search events by report fpid.                                                            Optional
  limit               Specify limit of the record.                                                             Optional
  attack\_ids         Search events by attack ids. Multiple ids are acceptable using comma separated values.   Optional
 

##### Command Example

`!flashpoint-get-events limit=20`

##### Context Example

    {}

##### Human Readable Output

### Flashpoint Events

### Below are the detail found:

  **Observed time (UTC)**   **Name**                                                                                                                                                                       **Tags**
  ------------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Nov 29, 2019 07:00        [Command\_Line\_Options](https://fp.tools/home/technical\_data/iocs/items/5da01a75-0f20-41da-83e1-56550a640c05)                                                                source:VirusTotal, command\_line\_options
  Nov 29, 2019 06:02        [Gandcrab](https://fp.tools/home/technical\_data/iocs/items/5d07d587-a9ac-4da1-9c72-05cd0a640c05)                                                                              source:VirusTotal, type:Ransomware, gandcrab, malware:GandCrab, os:Windows
  Nov 29, 2019 06:02        [Sodinokibi\_Unreachable\_After\_MZ\_Check](https://fp.tools/home/technical\_data/iocs/items/5da01a74-4b5c-4160-83c6-05d00a640c05)                                             source:VirusTotal, sodinokibi\_unreachable\_after\_mz\_check
  Nov 29, 2019 06:01        [MegaCortex\_Load\_Dinkum\_CLib](https://fp.tools/home/technical\_data/iocs/items/5da01a84-b3fc-4eef-961d-0a340a640c05)                                                        source:VirusTotal, megacortex\_load\_dinkum\_clib, malware:MegaCortex, type:Ransomware, os:Windows
  Nov 29, 2019 05:00        [crime\_win32\_iceid\_injector](https://fp.tools/home/technical\_data/iocs/items/5d07ff63-41c8-480e-975b-05d00a640c05)                                                         source:VirusTotal, malware:IcedID, type:Banker, os:Windows, crime\_win32\_iceid\_injector, target:US, target:Canada, target:UK
  Nov 29, 2019 04:16        [CryptingService\_34ebf3d9ecf8cde4412e83a045f720d6b75c1358\_2019-11-29T02:01:05.000Z](https://fp.tools/home/technical\_data/iocs/items/5de09bb7-3a20-4b39-9e91-01480a2121a2)   source:CryptingService2
  Nov 29, 2019 04:16        [CryptingService\_783eb44ba9a921565a74887291ec148b8e83fb4d\_2019-11-29T03:01:02.000Z](https://fp.tools/home/technical\_data/iocs/items/5de09bad-1468-4ff7-b8da-97af0a2123fc)   source:CryptingService2
  Nov 29, 2019 04:16        [CryptingService\_3b4bcf48739c9ea4fe5e5d029d2c2f83b4536215\_2019-11-29T03:01:02.000Z](https://fp.tools/home/technical\_data/iocs/items/5de09ba3-a938-4eaa-bb02-97f10a2123fc)   source:CryptingService2
  Nov 29, 2019 04:16        [CryptingService\_b3104cb38e21a4f836f0c53299a4f07b964c4d90\_2019-11-29T03:01:02.000Z](https://fp.tools/home/technical\_data/iocs/items/5de09b8f-0424-4e16-a92c-42c30a2121a2)   source:CryptingService2
  Nov 29, 2019 04:16        [CryptingService\_da899c618f181ab0e6e50eaa27e1c90a8ef54f89\_2019-11-29T03:01:02.000Z](https://fp.tools/home/technical\_data/iocs/items/5de09b8c-5880-437e-b017-8dbd0a2123fc)   source:CryptingService2
  Nov 29, 2019 04:16        [CryptingService\_fe1f5cab061ccf51a024e8fff3207d2b78780b3f\_2019-11-29T03:01:02.000Z](https://fp.tools/home/technical\_data/iocs/items/5de09b80-f5e8-4fae-b010-97af0a2123fc)   source:CryptingService2
  Nov 29, 2019 04:01        [Turla\_APT\_Malware\_Gen1](https://fp.tools/home/technical\_data/iocs/items/5dd5c58f-d28c-4b02-bb74-8e5c0a2123fc)                                                             source:VirusTotal, turla\_apt\_malware\_gen1, origin:Russia, actor:Turla, target:EasternEurope
  Nov 29, 2019 04:01        [Turla\_APT\_Malware\_Gen2](https://fp.tools/home/technical\_data/iocs/items/5dd5c58e-c4c0-464d-ad7a-49ad0a2121a2)                                                             source:VirusTotal, turla\_apt\_malware\_gen2, actor:Turla, target:EasternEurope, origin:Russia
  Nov 29, 2019 04:01        [Turla\_APT\_Malware\_Gen3](https://fp.tools/home/technical\_data/iocs/items/5d2ee3cc-739c-4d58-b115-05cd0a640c05)                                                             source:VirusTotal, actor:Turla, origin:Russia, turla\_apt\_malware\_gen3, target:EasternEurope
  Nov 29, 2019 04:01        [Turla\_Mal\_Script\_Jan18\_1](https://fp.tools/home/technical\_data/iocs/items/5dd5c58b-58e8-4ec5-b4b0-43640a2121a2)                                                          source:VirusTotal, origin:Russia, turla\_mal\_script\_jan18\_1, actor:Turla, target:EasternEurope
  Nov 29, 2019 03:00        [Lazarus\_Dec\_17\_5](https://fp.tools/home/technical\_data/iocs/items/5de089e3-16ac-4300-8437-00530a2121a2)                                                                   source:VirusTotal, actor:Lazarus, lazarus\_dec\_17\_5, origin:DPRK
  Nov 29, 2019 03:00        [ROKRAT\_Nov17\_1](https://fp.tools/home/technical\_data/iocs/items/5d5ed847-c018-43f6-baab-0f140a640c05)                                                                      source:VirusTotal, T1057, T1105, T1063, os:Windows, target:SouthKorea, T1003, T1012, T1082, rokrat\_nov17\_1, malware:Rokrat, T1071, exfil:C2, T1102, T1041, T1056, type:RAT, T1497, T1113, misp-galaxy:mitre-enterprise-attack-attack-pattern="Process Discovery - T1057", misp-galaxy:mitre-enterprise-attack-attack-pattern="Remote File Copy - T1105", misp-galaxy:mitre-enterprise-attack-attack-pattern="Security Software Discovery - T1063", misp-galaxy:mitre-enterprise-attack-attack-pattern="Credential Dumping - T1003", misp-galaxy:mitre-enterprise-attack-attack-pattern="Query Registry - T1012", misp-galaxy:mitre-enterprise-attack-attack-pattern="System Information Discovery - T1082", misp-galaxy:mitre-enterprise-attack-attack-pattern="Standard Application Layer Protocol - T1071", misp-galaxy:mitre-enterprise-attack-attack-pattern="Web Service - T1102", misp-galaxy:mitre-enterprise-attack-attack-pattern="Exfiltration Over Command and Control Channel - T1041", misp-galaxy:mitre-enterprise-attack-attack-pattern="Input Capture - T1056", misp-galaxy:mitre-enterprise-attack-attack-pattern="Screen Capture - T1113"
  Nov 29, 2019 03:00        [QRat](https://fp.tools/home/technical\_data/iocs/items/5dd5d393-a8c0-4ba9-a465-98290a2123fc)                                                                                  source:VirusTotal, type:RAT, os:Linux, target:Europe, malware:QRat, target:Asia, qrat
  Nov 29, 2019 03:00        [ZeusPanda](https://fp.tools/home/technical\_data/iocs/items/5d57c2d2-8450-46c1-9675-05d20a640c05)                                                                             source:VirusTotal, T1124, obfuscation:encryption, target:Australia, T1070, zeuspanda, T1012, os:Windows, type:Trojan, T1027, T1056, obfuscation:XOR, T1057, T1060, T1059, T1083, T1112, malware:ZeusPanda, T1107, T1113, T1086, T1140, T1064, T1082, target:Europe, T1105, T1115, T1063, T1179, T1071, T1055, misp-galaxy:mitre-enterprise-attack-attack-pattern="System Time Discovery - T1124", misp-galaxy:mitre-enterprise-attack-attack-pattern="Indicator Removal on Host - T1070", misp-galaxy:mitre-enterprise-attack-attack-pattern="Query Registry - T1012", misp-galaxy:mitre-enterprise-attack-attack-pattern="Obfuscated Files or Information - T1027", misp-galaxy:mitre-enterprise-attack-attack-pattern="Input Capture - T1056", misp-galaxy:mitre-enterprise-attack-attack-pattern="Process Discovery - T1057", misp-galaxy:mitre-enterprise-attack-attack-pattern="Registry Run Keys / Start Folder - T1060", misp-galaxy:mitre-enterprise-attack-attack-pattern="Command-Line Interface - T1059", misp-galaxy:mitre-enterprise-attack-attack-pattern="File and Directory Discovery - T1083", misp-galaxy:mitre-enterprise-attack-attack-pattern="File Deletion - T1107", misp-galaxy:mitre-enterprise-attack-attack-pattern="Screen Capture - T1113", misp-galaxy:mitre-enterprise-attack-attack-pattern="PowerShell - T1086", misp-galaxy:mitre-enterprise-attack-attack-pattern="Deobfuscate/Decode Files or Information - T1140", misp-galaxy:mitre-enterprise-attack-attack-pattern="Scripting - T1064", misp-galaxy:mitre-enterprise-attack-attack-pattern="System Information Discovery - T1082", misp-galaxy:mitre-enterprise-attack-attack-pattern="Remote File Copy - T1105", misp-galaxy:mitre-enterprise-attack-attack-pattern="Clipboard Data - T1115", misp-galaxy:mitre-enterprise-attack-attack-pattern="Security Software Discovery - T1063", misp-galaxy:mitre-enterprise-attack-attack-pattern="Hooking - T1179", misp-galaxy:mitre-enterprise-attack-attack-pattern="Standard Application Layer Protocol - T1071", misp-galaxy:mitre-enterprise-attack-course-of-action="Process Injection Mitigation - T1055", misp-galaxy:mitre-enterprise-attack-attack-pattern="Modify Registry - T1112"
  Nov 29, 2019 02:00        [FIN7\_Backdoor\_Aug17](https://fp.tools/home/technical\_data/iocs/items/5dc148ad-af60-4f14-8e3b-00550a2123fc)                                                                 source:VirusTotal, actor:fin7, type:Backdoor, fin7\_backdoor\_aug17

All events and details (fp-tools):
[https://fp.tools/home/search/iocs](https://fp.tools/home/search/iocs)

### 12. flashpoint-common-lookup

* * * * *

Lookup any type of indicator

##### Base Command

`flashpoint-common-lookup`

##### Input

  **Argument Name**   **Description**                                                **Required**
  ------------------- -------------------------------------------------------------- --------------
  indicator           Specify indicator value like any domain, ip, email, url etc.   Required

##### Command Example

`!flashpoint-common-lookup indicator="mondns.myftp.biz"`

##### Context Example

    {
        "DBotScore": {
            "Indicator": "mondns.myftp.biz",
            "Score": 3,
            "Type": "domain",
            "Vendor": "Flashpoint"
        }
    }

##### Human Readable Output

### Flashpoint reputation for mondns.myftp.biz

Reputation: Malicious

### Events in which this IOC observed

  **Date Observed (UTC)**   **Name**   **Tags**
  ------------------------- ---------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Oct 11, 2019 15:30        ModiRAT    misp-galaxy:mitre-enterprise-attack-attack-pattern="Deobfuscate/Decode Files or Information - T1140", misp-galaxy:mitre-enterprise-attack-attack-pattern="System Owner/User Discovery - T1033", misp-galaxy:mitre-enterprise-attack-attack-pattern="System Information Discovery - T1082", misp-galaxy:mitre-enterprise-attack-attack-pattern="Screen Capture - T1113", misp-galaxy:mitre-enterprise-attack-attack-pattern="Custom Command and Control Protocol - T1094", misp-galaxy:mitre-enterprise-attack-attack-pattern="Data Encoding - T1132", misp-galaxy:mitre-enterprise-attack-attack-pattern="Uncommonly Used Port - T1065", malware:ModiRAT, type:RAT, os:Windows, report:FQmMHh1rR\_WuGd\_PNVv-bQ

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_value=mondns.myftp.biz](https://fp.tools/home/search/iocs?group=indicator&ioc\_value=mondns.myftp.biz)

### 13. flashpoint-get-forum-details

* * * * *

Get forum details

##### Base Command

`flashpoint-get-forum-details`

##### Input

  **Argument Name**   **Description**    **Required**
  ------------------- ------------------ --------------
  forum\_id           Specify forum id   Required

##### Command Example

`!flashpoint-get-forum-details forum_id=ifY5BsXeXQqdTx3fafZbIg`

##### Context Example

    {
        "flashpoint": {
            "forum": {
                "description": "0hack (\u96f6\u9ed1\u8054\u76df) is a Chinese-language hacker training forum. The forum appears to be affiliated with \u975e\u51e1\u5b89\u5168\u7f51, 803389.com.",
                "hostname": "bbs.0hack.com",
                "name": "0hack",
                "stats": {
                    "posts": 1226,
                    "rooms": 11,
                    "threads": 226,
                    "users": 114
                },
                "tags": [
                    {
                        "id": 31,
                        "name": "Chinese",
                        "parent_tag": 28,
                        "uuid": "e725fc5d-71f9-4403-ab00-ae609f2fd3bd"
                    },
                    {
                        "id": 6,
                        "name": "Cyber Threat",
                        "parent_tag": null,
                        "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                    },
                    {
                        "id": 8,
                        "name": "Hacking",
                        "parent_tag": 6,
                        "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
                    },
                    {
                        "id": 28,
                        "name": "Language",
                        "parent_tag": null,
                        "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                    }
                ]
            }
        }
    }

##### Human Readable Output

### Flashpoint Forum details

### Below are the details found:

  **Name**   **Hostname**    **Tags**
  ---------- --------------- ------------------------------------------
  0hack      bbs.0hack.com   Chinese, Cyber Threat, Hacking, Language

### 14. flashpoint-get-forum-room-details

* * * * *

Get room details

##### Base Command

`flashpoint-get-forum-room-details`


##### Input

  **Argument Name**   **Description**   **Required**
  ------------------- ----------------- --------------
  room\_id            Specify room id   Required


##### Command Example

`!flashpoint-get-forum-room-details room_id="dBoQqur5XmGGYLxSrc8C9A"`

##### Context Example

    {
        "flashpoint": {
            "forum": {
                "room": {
                    "forum": {
                        "description": "This is the restored 2013 database of the Carding.pro SQL dump. Crdpro was set up by the threat actor operating under the alias \"Makaka\" to drive traffic to their forum Crdclub.",
                        "hostname": "crdpro.su",
                        "id": "4aFfW6e7VVea1cP7G-Z7mw",
                        "legacy_id": "_OU09w6LVm69kgAyDaTv5A",
                        "name": "Crdpro",
                        "platform_url": "https://fp.tools/home/search/forums?forum_ids=4aFfW6e7VVea1cP7G-Z7mw",
                        "stats": {
                            "posts": 987018,
                            "rooms": 132,
                            "threads": 116115,
                            "users": 50902
                        },
                        "tags": [
                            {
                                "id": 6,
                                "name": "Cyber Threat",
                                "parent_tag": null,
                                "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                            },
                            {
                                "id": 9,
                                "name": "Fraud",
                                "parent_tag": null,
                                "uuid": "fa9a9533-0cf1-42b6-9553-08ebbbaaa60b"
                            },
                            {
                                "id": 28,
                                "name": "Language",
                                "parent_tag": null,
                                "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                            },
                            {
                                "id": 29,
                                "name": "English",
                                "parent_tag": null,
                                "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                            },
                            {
                                "id": 30,
                                "name": "Russian",
                                "parent_tag": null,
                                "uuid": "c3815816-c639-4ea2-9e5c-aec29eee2b1a"
                            }
                        ]
                    },
                    "title": "Bank Carding",
                    "url": "forumdisplay.php?f=70&s=6e25902255e1b57bfe37dd2749dafd66"
                }
            }
        }
    }

##### Human Readable Output

### Flashpoint Room details

### Below are the detail found:

  **Forum Name**   **Title**      **URL**
  ---------------- -------------- ----------------------------------------------------------
  Crdpro           Bank Carding   forumdisplay.php?f=70&s=6e25902255e1b57bfe37dd2749dafd66

### 15. flashpoint-get-forum-user-details

* * * * *

Get user details

##### Base Command

`flashpoint-get-forum-user-details`

##### Input

  **Argument Name**   **Description**   **Required**
  ------------------- ----------------- --------------
  user\_id            Specify room id   Required


##### Command Example

`!flashpoint-get-forum-user-details user_id="P3au_EzEX4-uctmRfdUYeA"`

##### Context Example

    {
        "flashpoint": {
            "forum": {
                "user": {
                    "forum": {
                        "description": "This is the restored 2013 database of the Carding.pro SQL dump. Crdpro was set up by the threat actor operating under the alias \"Makaka\" to drive traffic to their forum Crdclub.",
                        "hostname": "crdpro.su",
                        "id": "4aFfW6e7VVea1cP7G-Z7mw",
                        "legacy_id": "_OU09w6LVm69kgAyDaTv5A",
                        "name": "Crdpro",
                        "platform_url": "https://fp.tools/home/search/forums?forum_ids=4aFfW6e7VVea1cP7G-Z7mw",
                        "stats": {
                            "posts": 987018,
                            "rooms": 132,
                            "threads": 116115,
                            "users": 50902
                        },
                        "tags": [
                            {
                                "id": 6,
                                "name": "Cyber Threat",
                                "parent_tag": null,
                                "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                            },
                            {
                                "id": 9,
                                "name": "Fraud",
                                "parent_tag": null,
                                "uuid": "fa9a9533-0cf1-42b6-9553-08ebbbaaa60b"
                            },
                            {
                                "id": 28,
                                "name": "Language",
                                "parent_tag": null,
                                "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                            },
                            {
                                "id": 29,
                                "name": "English",
                                "parent_tag": null,
                                "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                            },
                            {
                                "id": 30,
                                "name": "Russian",
                                "parent_tag": null,
                                "uuid": "c3815816-c639-4ea2-9e5c-aec29eee2b1a"
                            }
                        ]
                    },
                    "name": "IllWillPub",
                    "platform_url": "https://fp.tools/home/search/forums?author_id=P3au_EzEX4-uctmRfdUYeA",
                    "url": "http://www.crdpro.su/member.php?s=9f099a0eebc5f7c79e36fc688af2f697&u=50678"
                }
            }
        }
    }

##### Human Readable Output

### Flashpoint User details

### Below are the detail found:

  **Forum Name**   **Name**     **URL**
  ---------------- ------------ ----------------------------------------------------------------------------
  Crdpro           IllWillPub   http://www.crdpro.su/member.php?s=9f099a0eebc5f7c79e36fc688af2f697&u=50678

### 16. flashpoint-get-forum-post-details

* * * * *

Get post details

##### Base Command

`flashpoint-get-forum-post-details`

##### Input

  **Argument Name**   **Description**   **Required**
  ------------------- ----------------- --------------
  post\_id            Specify post id   Required


##### Command Example

`!flashpoint-get-forum-post-details post_id=PDo1xGiKXDebHGc8fZme6g`

##### Context Example

    {
        "flashpoint": {
            "forum": {
                "post": {
                    "forum": {
                        "description": "Ukrainian forum with focus on Russian-Ukrainian conflict.",
                        "hostname": "ord-ua.com",
                        "id": "rJnT5ETuWcW9jTCnsobFZQ",
                        "legacy_id": null,
                        "name": "Ord-UA",
                        "platform_url": "https://fp.tools/home/search/forums?forum_ids=rJnT5ETuWcW9jTCnsobFZQ",
                        "stats": {
                            "posts": 163710,
                            "rooms": 1,
                            "threads": 13916,
                            "users": 71614
                        },
                        "tags": [
                            {
                                "id": 55,
                                "name": "Communities in Conflict",
                                "parent_tag": 17,
                                "uuid": "83a2e5d4-e591-42be-943f-4af7d5de30e4"
                            },
                            {
                                "id": 28,
                                "name": "Language",
                                "parent_tag": null,
                                "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                            },
                            {
                                "id": 30,
                                "name": "Russian",
                                "parent_tag": 28,
                                "uuid": "c3815816-c639-4ea2-9e5c-aec29eee2b1a"
                            },
                            {
                                "id": 98,
                                "name": "Ukrainian",
                                "parent_tag": null,
                                "uuid": "9bf8c176-3b2d-4445-a2f5-6fe92843a4a1"
                            }
                        ]
                    },
                    "platform_url": "https://fp.tools/home/ddw/forums/threads/M3NorvmYVoG6rVFHnP3T9w?id=PDo1xGiKXDebHGc8fZme6g",
                    "published_at": "2019-12-10T01:17:00+00:00",
                    "room": {
                        "forum": "/forums/sites/rJnT5ETuWcW9jTCnsobFZQ",
                        "id": "UWUdaSQ7VXCkHq4KDQalpQ",
                        "legacy_id": null,
                        "native_id": "forum",
                        "platform_url": "https://fp.tools/home/search/forums?room_title=\"%D0%A4%D0%BE%D1%80%D1%83%D0%BC\"",
                        "title": "\u0424\u043e\u0440\u0443\u043c",
                        "url": "forum"
                    },
                    "url": "2014/10/22/dsns-na-choli-z-bochkovskim-i-k/?lpage=1&page=580",
                    "user": {
                        "id": "0vK-XB2KWaeYqXjXaO9ruA",
                        "legacy_id": null,
                        "name": "\u0414\u0443\u0431\u043e\u0432\u0438\u043a",
                        "native_id": "\u0414\u0443\u0431\u043e\u0432\u0438\u043a",
                        "platform_url": "https://fp.tools/home/search/forums?author_id=0vK-XB2KWaeYqXjXaO9ruA",
                        "url": null
                    }
                }
            }
        }
    }

##### Human Readable Output

### Flashpoint Post details

### Below are the detail found:

  **Published at**            **Forum Name**   **Room Title**   **Author Name**   **Thread Title**                   **URL**                                                        **Platform url**
  --------------------------- ---------------- ---------------- ----------------- ---------------------------------- -------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  2019-12-10T01:17:00+00:00   Ord-UA           Форум            Дубовик           ДСНС на чолі з Бочковським і К….   2014/10/22/dsns-na-choli-z-bochkovskim-i-k/?lpage=1&page=580   [https://fp.tools/home/ddw/forums/threads/M3NorvmYVoG6rVFHnP3T9w?id=PDo1xGiKXDebHGc8fZme6g](https://fp.tools/home/ddw/forums/threads/M3NorvmYVoG6rVFHnP3T9w?id=PDo1xGiKXDebHGc8fZme6g)

### 17. flashpoint-search-forum-sites

* * * * *

Search forum sites using a keyword

##### Base Command

`flashpoint-search-forum-sites`

##### Input

  **Argument Name**   **Description**                   **Required**
  ------------------- --------------------------------- --------------
  site\_search        Search by site keyword or text.   Required


##### Command Example

`!flashpoint-search-forum-sites site_search="0hack"`

##### Context Example

    {}

##### Human Readable Output

### Flashpoint Forum sites related to search: 0hack

Top 10 sites:

### Below are the detail found:

  **Name**   **Hostname**    **Description**
  ---------- --------------- -------------------------------------------------------------------------------------------------------------------------------
  0hack      bbs.0hack.com   0hack (零黑联盟) is a Chinese-language hacker training forum. The forum appears to be affiliated with 非凡安全网, 803389.com.

### 18. flashpoint-search-forum-posts

* * * * *

Search forum posts using a keyword

##### Base Command

`flashpoint-search-forum-posts`

##### Input

  **Argument Name**   **Description**                   **Required**
  ------------------- --------------------------------- --------------
  post\_search        Search by post keyword or text.   Required

##### Command Example

`!flashpoint-search-forum-posts post_search="The Courtyard Café"`

##### Context Example

    {}

##### Human Readable Output

### Flashpoint Forum posts related to search: The Courtyard Café

Top 10 posts:

### Below are the detail found:

  **Forum Name**       **Thread Title**                     **Room Title**       **Author Name**   **Platform URL**
  -------------------- ------------------------------------ -------------------- ----------------- ----------------------------------------------------------------------------------------------------------------------------------
  The Sammyboy Times   MAS Warns That Property Market....   The Courtyard Café   laksaboy          [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/0w1sUXU3WrqzaXZBIA8x0Q?id=jX785W1uVJWtBPsI\_OAWcw)
  The Sammyboy Times   [SEA Games] - Maria Ozawa decl....   The Courtyard Café   melzp             [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/\_naJUWibUqqAjeJD-KKGig?id=kSTfSKL9WsiYVb4RlM\_F3w)
  The Sammyboy Times   Woman jailed for smashing beer....   The Courtyard Café   whoami            [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/FSnuh6nIWpC5XtUqD2YEeA?id=3WOBHMxTXCC63Pa6y89xTw)
  The Sammyboy Times   Woman jailed for smashing beer....   The Courtyard Café   bobby             [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/FSnuh6nIWpC5XtUqD2YEeA?id=t\_rTSzbzUuaoHJfsJSxemQ)
  The Sammyboy Times   Woman jailed for smashing beer....   The Courtyard Café   Hypocrite-The     [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/FSnuh6nIWpC5XtUqD2YEeA?id=2L2\_lQMGW1ilRDHfseYdkw)
  The Sammyboy Times   Woman jailed for smashing beer....   The Courtyard Café   Hypocrite-The     [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/FSnuh6nIWpC5XtUqD2YEeA?id=sBQtTs0kVp6w4iw3jJTLYw)
  The Sammyboy Times   Jiuhu kia real degrees vs ah n....   The Courtyard Café   mahjongking       [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/lJN5Ya6AWoiFEBYt17db3A?id=Sv9uDzbQUKifmOtTnE1mRw)
  The Sammyboy Times   Woman jailed for smashing beer....   The Courtyard Café   mahjongking       [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/FSnuh6nIWpC5XtUqD2YEeA?id=lGIHud0NXWisSgemOd4jZA)
  The Sammyboy Times   Woman jailed for smashing beer....   The Courtyard Café   Valium            [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/FSnuh6nIWpC5XtUqD2YEeA?id=7cPD72n\_Wy68BqsCSFetDQ)
  The Sammyboy Times   False Arrest by Singapore Poli....   The Courtyard Café   Valium            [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/ngtpLaBuWDy4CwWzJFsNcQ?id=Ldl04RPEWo2Zkg64Vu0I3g)

Link to forum post-search on Flashpoint platform:
[https://fp.tools/home/search/forums?query=The%20Courtyard%20Caf%C3%A9](https://fp.tools/home/search/forums?query=The%20Courtyard%20Caf%C3%A9)

Additional Information
----------------------

Known Limitations
-----------------

Troubleshooting
---------------
