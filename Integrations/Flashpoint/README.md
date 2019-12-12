Use flashpoint integration for reduced business risk.


Configure Flashpoint on Demisto
-------------------------------

1.  Navigate to **Settings** \> **Integrations**  \> **Servers &
    Services**.
2.  Search for Flashpoint.
3.  Click **Add instance** to create and configure a new integration
    instance.
    -   **Name**: a textual name for the integration instance.
    -   **URL**
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

  **Argument Name**  | **Description**   | **Required**
  -------------------| ------------------| --------------
  ip                 | Enter ip address  | Required

 

##### Context Output

  **Path**                  | **Type**  |  **Description**
  --------------------------| ----------|------------------------------------------
  DBotScore.Indicator       | string    | The indicator that was tested.
  DBotScore.Score           | number    | The indicator score.
  DBotScore.Type            | string    | The indicator type.
  DBotScore.Vendor          | string    | The vendor used to calculate the score.
  IP.Address                | string    | IP address
  IP.Flashpoint.href        | unknown   | List of reference link of the indicator.
  IP.Malicious.Description  | string    | Description of malicious ip.
  IP.Malicious.Vendor       | string    | Vandor of malicious ip.

 

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

  **Date Observed (UTC)**  | **Name**                                                   |  **Tags**
  -------------------------| -----------------------------------------------------------| --------------
  Feb 12, 2018 21:46       | Lazarus Resurfaces, Targets Global Banks and Bitcoin Users |  source:OSINT

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=ip-dst%2Cip-src&ioc\_value=210.122.7.129](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=ip-dst%2Cip-src&ioc\_value=210.122.7.129)

### 2. domain

* * * * *

Lookup the "Domain" type indicator details

##### Base Command

`domain`

##### Input

  **Argument Name**  | **Description**    | **Required**
  -------------------| -------------------| --------------
  domain             | Enter domain name  | Required

 

##### Context Output

  **Path**                      | **Type**  | **Description**
  ------------------------------| ----------| -----------------------------------------
  DBotScore.Indicator           | string    | The indicator that was tested.
  DBotScore.Score               | number    | The indicator score.
  DBotScore.Type                | string    | The indicator type.
  DBotScore.Vendor              | string    | The vendor used to calculate the score.
  Domain.Flashpoint.href        | Unknown   | List of reference of indicators.
  Domain.Malicious.Description  | string    | Description of malicious indicator.
  Domain.Malicious.Vendor       | string    | Vendor of malicious indicator.
  Domain.Name                   | string    | Name of domain.

 

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

  **Date Observed (UTC)**  | **Name**                    | **Tags**
  -------------------------| ----------------------------| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Sep 25, 2019 19:51       | Gorgon Group actor profile  | misp-galaxy:mitre-enterprise-attack-attack-pattern="Spearphishing Attachment - T1193", misp-galaxy:mitre-enterprise-attack-attack-pattern="Scripting - T1064", misp-galaxy:mitre-enterprise-attack-attack-pattern="Command-Line Interface - T1059", misp-galaxy:mitre-enterprise-attack-attack-pattern="System Information Discovery - T1082", misp-galaxy:mitre-enterprise-attack-attack-pattern="Remote Services - T1021", misp-galaxy:mitre-enterprise-attack-attack-pattern="Exfiltration Over Command and Control Channel - T1041", os:Windows, source:phishing, type:RAT, malware:rat:Quasar, malware:banker:Lokibot, file\_name: njrat.exe, file\_name: excel\_.exe

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=domain&ioc\_value=subaat.com](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=domain&ioc\_value=subaat.com)

### 3. filename

* * * * *

Lookup the "Filename" type indicator details

##### Base Command

`filename`

##### Input

  **Argument Name**  | **Description**  | **Required**
  -------------------| -----------------| --------------
  filename           | Enter file-name  | Required

 

##### Context Output

  **Path**             | **Type**  | **Description**
  ---------------------| ----------| -----------------------------------------
  DBotScore.Indicator  | string    | The indicator that was tested.
  DBotScore.Score      | number    | The indicator score.
  DBotScore.Type       | string    | The indicator type.
  DBotScore.Vendor     | string    | The vendor used to calculate the score.

 

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

  **Date Observed (UTC)**  | **Name**    | **Tags**
  -------------------------| ------------| -------------------------------------------------------------------------------------------------------------------------------------------------------------
  Oct 24, 2019 16:30       | LockerGoga  | malware:ransomware:lockergoga, report:lKyimEX1TWS8x6AtdiJ\_vA, report:jEteM4YxQZCdm4macbE3vQ, report:w0fL5MgoQ\_Wih8XyB6Lowg, report:7t-BsuFKTL-HJWbid8nupg

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=filename&ioc\_value=.locked](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=filename&ioc\_value=.locked)

### 4. url

* * * * *

Lookup the "URL" type indicator details

##### Base Command

`url`

##### Input

  **Argument Name**  | **Description**  | **Required**
  -------------------| -----------------| --------------
  url                | Enter url        | Required

 

##### Context Output

  **Path**                    | **Type**   | **Description**
  --------------------------- | ---------- | -----------------------------------------
  DBotScore.Indicator         | string     | The indicator that was tested.
  DBotScore.Score             | number     | The indicator score.
  DBotScore.Type              | string     | The indicator type.
  DBotScore.Vendor            | string     | The vendor used to calculate the score.
  URL.Flashpoint.href         | Unknown    | List of reference of url.
  URL.Malicious.Description   | string     | Description of malicious url.
  URL.Malicious.Vendor        | string     | Vendor of malicious url.

 

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

  **Date Observed (UTC)**  | **Name**       | **Tags**
  -------------------------| ---------------| --------------------------------------------------------------------------------------------
  Oct 24, 2019 16:30       | GandCrab 2019  | malware:ransomware:GandCrab, report:lKyimEX1TWS8x6AtdiJ\_vA, report:7t-BsuFKTL-HJWbid8nupg

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=url&ioc\_value=92.63.197.153/krabaldento.exe](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=url&ioc\_value=92.63.197.153/krabaldento.exe)

### 5. file

* * * * *

Lookup the "File" type indicator details

##### Base Command

`file`

##### Input

  **Argument Name**  | **Description**                            | **Required**
  -------------------| -------------------------------------------| --------------
  file               | Enter file. It may sha1, md5, sha256 etc.  | Required

 

##### Context Output

  **Path**                    | **Type**  | **Description**
  ----------------------------| ----------| -----------------------------------------
  DBotScore.Indicator         | string    | The indicator that was tested.
  DBotScore.Score             | number    | The indicator score.
  DBotScore.Type              | string    | The indicator type.
  DBotScore.Vendor            | string    | The vendor used to calculate the score.
  File.Flashpoint.href        | unknown   | List of indicators reference.
  File.Malicious.Description  | string    | Description of malicious file.
  File.Malicious.Vendor       | string    | Vendor of malicious file.
  File.MD5                    | string    | MD5 type file.
  File.SHA1                   | string    | SHA1 type file.
  File.SHA256                 | string    | SHA256 type file.

 

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

  **Date Observed (UTC)**  | **Name**                  | **Tags**
  -------------------------| --------------------------| ----------------------------------------------------------------------------
  Dec 11, 2019 06:03       | Gandcrab                  | source:VirusTotal, type:Ransomware, gandcrab, malware:GandCrab, os:Windows
  Jul 17, 2019 18:02       | win\_ransomware\_generic  | source:VirusTotal, type:Ransomware, win\_ransomware\_generic, os:Windows

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=md5%2Csha1%2Csha256%2Csha512&ioc\_value=ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=md5%2Csha1%2Csha256%2Csha512&ioc\_value=ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5)

### 6. email

* * * * *

Lookup the "Email" type indicator details

##### Base Command

`email`

##### Input

  **Argument Name**  | **Description**   |  **Required**
  -------------------| ------------------| --------------
  email              | Enter valid email |  Required

 

##### Context Output

  **Path**                             |  **Type**  | **Description**
  -------------------------------------|  ----------| -----------------------------------------
  DBotScore.Indicator                  |  string    | The indicator that was tested.
  DBotScore.Score                      |  number    | The indicator score.
  DBotScore.Type                       |  string    | The indicator type.
  DBotScore.Vendor                     |  string    | The vendor used to calculate the score.
  Account.Email.Flashpoint.href        |  Unknown   | List of email references.
  Account.Email.Malicious.Description  |  string    | Description of Malicious email account.
  Account.Email.Malicious.Vendor       |  string    | Vendor of Malicious email.
  Account.Email.Name                   |  string    | Name of indicator.

 

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

  **Date Observed (UTC)**  | **Name**    | **Tags**
  -------------------------| ------------| -------------------------------------------------------------------------------------------------------------------------------------------------------------
  Oct 24, 2019 16:30       | LockerGoga  | malware:ransomware:lockergoga, report:lKyimEX1TWS8x6AtdiJ\_vA, report:jEteM4YxQZCdm4macbE3vQ, report:w0fL5MgoQ\_Wih8XyB6Lowg, report:7t-BsuFKTL-HJWbid8nupg

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_type=email-dst%2Cemail-src%2Cemail-src-display-name%2Cemail-subject&ioc\_value=qicifomuejijika%40o2.pl](https://fp.tools/home/search/iocs?group=indicator&ioc\_type=email-dst%2Cemail-src%2Cemail-src-display-name%2Cemail-subject&ioc\_value=qicifomuejijika%40o2.pl)

### 7. flashpoint-search-intelligence-reports

* * * * *

Search for the Intelligence Reports using a keyword

##### Base Command

`flashpoint-search-intelligence-reports`

##### Input

  **Argument Name**  | **Description**                      | **Required**
  -------------------| -------------------------------------| --------------
  report\_search     | Search report using keyword or text  | Required

 

##### Context Output

There are no context output for this command.

 

##### Command Example

`!flashpoint-search-intelligence-reports report_search="isis"`

##### Context Example

    {}

##### Human Readable Output

### Flashpoint Intelligence reports related to search: isis

Top 5 reports: 
1) [ISIS Media Rebuilds Following Sweeping Suspensions](https://fp.tools/home/intelligence/reports/report/og0aVCYmSeS-mpSXOF21Rg\#detail)  
Summary: Despite Telegram?s aggressive and sustained targeting of
jihadists on its platform, ISIS?s official media and supportive groups
are beginning to rebuild on Telegram.

2) [Telegram Targets ISIS Propaganda in Largest Platform Purge](https://fp.tools/home/intelligence/reports/report/Kd1HMXJQRYmKDmECAmsPMA\#detail)  
Summary: Between November 22 and 24, 2019, Telegram removed more than
7,000 jihadist channnels and bots from its platform?in the largest purge
of ISIS propaganda in Telegram?s history. The takedown drastically
impacted ISIS propaganda dissemination, knocking out critical channels
and groups, many of which had operated uninterrupted for years.

3)[Global Spotlight - Iran: Key Developments ThisWeek](https://fp.tools/home/intelligence/reports/report/mwpd9Dn7SuO\_K7KLPzfJeA\#detail)  
Summary: N/A 

4) [Dropbox Account Disseminates Far-Right Extremist Content](https://fp.tools/home/intelligence/reports/report/pRtNw1SETZOD71IRNakVCA\#detail)  
Summary: Flashpoint analysts have identified a Dropbox account called
?NS Library? belonging to a far-right extremist containing over 200
white supremacist publications and guides?including neo-Nazi literature
and propaganda, instruction manuals for making homemade weapons,
survival guides, attackers? manifestos, and workout manuals, among other
content.

5) [ISIS Activity Continues Unabated Following al-Baghdadi's Death](https://fp.tools/home/intelligence/reports/report/hrPmox3jSxyk5zkgTRmLjw\#detail)  
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

  **Argument Name**  | **Description**               | **Required**
  -------------------| ------------------------------| --------------
  report\_id         | Search report by report fpid  | Required

 

##### Context Output

  **Path**                         | **Type**  | **Description**
  ---------------------------------| ----------| ------------------------------
  Flashpoint.Report.notified\_at   | string    | Notify date of report.
  Flashpoint.Report.platform\_url  | string    | Platform url of report.
  Flashpoint.Report.posted\_at     | number    | posted date of report.
  Flashpoint.Report.summary        | string    | Summary of report.
  Flashpoint.Report.title          | string    | Title of the report.
  Flashpoint.Report.updated\_at    | string    | Last updated date of report.

 

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

  **Title**                                                                                                                                        | **Date Published (UTC)**  | **Summary**                                                                                                                                                                                                                                                                                                                                                                    | **Tags**
  -------------------------------------------------------------------------------------------------------------------------------------------------| --------------------------| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| ------------------------------------------------------------------------------------------------------------
  [ISIS Supporters Warn of the Risks Associated with Exif Data](https://fp.tools/home/intelligence/reports/report/e-QdYuuwRwCntzRljzn9-A\#detail)  | Sep 23, 2019 20:27        | On September 17, 2019, multiple pro-ISIS Telegram groups disseminated a message warning of the dangers of exposed exif data?a type of metadata showing GPS coordinates, time, and date the image was taken and the make and model of the device used?that is typically captured from images taken by a phone or camera, unless the security settings are properly configured.  | Intelligence Report, Law Enforcement & Military, Physical Threats, Jihadist, Propaganda, Terrorism, Global

### 9. flashpoint-get-related-reports

* * * * *

Get related reports for a given report id

##### Base Command

`flashpoint-get-related-reports`

##### Input

  **Argument Name**  | **Description**                        | **Required**
  -------------------| ---------------------------------------| --------------
  report\_id         | Search related report by report fpid.  | Required

 

##### Context Output

There are no context output for this command.

 

##### Command Example

`!flashpoint-get-related-reports report_id="tiPqg51OQpOTsoFyTaYa_w"`

##### Context Example

    {}

##### Human Readable Output

### Flashpoint Intelligence related reports:

Top 5 related reports: 
1) [Neo-Nazi Telegram Channel Incites Violence, Spreads Extremist Content](https://fp.tools/home/intelligence/reports/report/90paj4gCSBG8FT8R\_SCtgQ\#detail)  
Summary: In August 2019, militant white supremacist channel ?Stack the
Bodies to God? appeared on Telegram, inciting violence and providing a
large quantity of informational resources?including extremist
publications, tactical manuals, survival guides, guerrilla warfare
tactics, instructions for making homemade explosives, weapons, and
ricin, and internet security tips.

2) [Atomwaffen Division Resumes Recruitment Activity](https://fp.tools/home/intelligence/reports/report/X6YSFdWWQ3yDa9\_0r627sg\#detail)  
Summary: On September 30, 2019, the admin of ?The\_Bowlcast? Telegram
channel promoted the launch of the militant, white supremacist group
?Atomwaffen Division?s? (AWD) latest website and new video dubbed
?Nuclear Congress 2019,? which subtlely discusses the need for AWD to
accomplish its goals?alluding to the need for new financing and
recruitment. 

3) ["Vorherrschaft Division" (VSD): A Nascent Militant White Supremacy Group](https://fp.tools/home/intelligence/reports/report/iQRHJvzySma6-aHNE973mA\#detail)  
Summary: On June 14, 2019, a militant white supremacy group called
?Vorherrschaft Division? (VSD) announced its creation in its Telegram
channel "Vorherrschaft division propaganda posting." 

4) ["Boogaloo": Accelerationists' Latest Call to Action](https://fp.tools/home/intelligence/reports/report/iEOIjuPjREmCIJR7Krbpnw\#detail)  
Summary: The term ?boogaloo? (also known as ?the boogaloo? and ?big
igloo?) is the latest term used by accelerationists?advocates of
hastening the collapse of society through violence?to describe an armed
revolution against society to rebuild a white-ethno state. 

5) [Far-Right Prepares for "Meme War 2020"](https://fp.tools/home/intelligence/reports/report/pQBUFAlfSce-xQd7Ignmyg\#detail)  
Summary: Members of the far-right community are preparing for what they
call ?meme war 2020??content spread via social media focused on
left-leaning targets?in the lead up to the 2020 U.S. presidential
election. Link to the given Report on Flashpoint platform:
[https://fp.tools/home/intelligence/reports/report/tiPqg51OQpOTsoFyTaYa\_w\#detail](https://fp.tools/home/intelligence/reports/report/tiPqg51OQpOTsoFyTaYa\_w\#detail)

### 10. flashpoint-get-single-event

* * * * *

For getting single event

##### Base Command

`flashpoint-get-single-event`

##### Input

  **Argument Name**  | **Description**                                       | **Required**
  -------------------| ------------------------------------------------------| --------------
  event\_id          | The UUID or FPID that identifies a particular event.  | Required

 

##### Context Output

  **Path**                                | **Type**  | **Description**
  ----------------------------------------| ----------| --------------------------
  Flashpoint.event.date                   | string    | Date of event triggered.
  Flashpoint.event.event\_creator\_email  | string    | Event creator email.
  Flashpoint.event.href                   | Unknown   | Display event reference.
  Flashpoint.event.tag                    | Unknown   | Display event tag.

 

##### Command Example

`!flashpoint-get-single-event event_id=Hu2SoTWJWteLrH9mR94JbQ`

##### Context Example

    {
        "flashpoint": {
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

  **Observed time (UTC)**   |**Name**                                                                                                                                                                      | **Tags**
  ------------------------- |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| -------------------------
  Jun 18, 2019 22:08        |[CryptingService\_4c0d570ecdf23529c91b8decf27107db5c5e9430\_2019-06-17T03:01:03.000Z](https://fp.tools/home/technical\_data/iocs/items/5d0960cc-6128-4416-9996-05d20a640c05)  | source:CryptingService2

### 11. flashpoint-get-events

* * * * *

Get all event details

##### Base Command

`flashpoint-get-events`

##### Input

  **Argument Name**  | **Description**                                                                         | **Required**
  -------------------| ----------------------------------------------------------------------------------------| --------------
  time\_period       | Specified time period. Search events based on time period.                              | Optional
  report\_fpid       | Search events by report fpid.                                                           | Optional
  limit              | Specify limit of the record.                                                            | Optional
  attack\_ids        | Search events by attack ids. Multiple ids are acceptable using comma separated values.  | Optional

##### Context Output

There are no context output for this command.

 

##### Command Example

`!flashpoint-get-events limit=20`

##### Context Example

    {}

##### Human Readable Output

### Flashpoint Events

### Below are the detail found:

  **Observed time (UTC)**  | **Name**                                                                                                                                                                      | **Tags**
  -------------------------| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Dec 11, 2019 10:16       | [CryptingService\_4273f08ae5f229f6301e7e0cc9e9005cebc4da20\_2019-12-11T03:01:01.000Z](https://fp.tools/home/technical\_data/iocs/items/5df0c210-2c54-4003-a1a8-004f0a21253a)  | source:CryptingService2
  Dec 11, 2019 09:00       | [NetWire](https://fp.tools/home/technical\_data/iocs/items/5d58176a-6020-418a-b5aa-05d20a640c05)                                                                              | source:VirusTotal, T1060, netwire, T1056, os:Windows, type:RAT, malware:NetWire, T1082, T1116, T1113, misp-galaxy:mitre-enterprise-attack-attack-pattern="Registry Run Keys / Start Folder - T1060", misp-galaxy:mitre-enterprise-attack-attack-pattern="Input Capture - T1056", misp-galaxy:mitre-enterprise-attack-attack-pattern="System Information Discovery - T1082", misp-galaxy:mitre-enterprise-attack-attack-pattern="Code Signing - T1116", misp-galaxy:mitre-enterprise-attack-attack-pattern="Screen Capture - T1113"
  Dec 11, 2019 08:00       | [CyberGate](https://fp.tools/home/technical\_data/iocs/items/5d07d55f-e9f8-4530-b57c-05cd0a640c05)                                                                            | source:VirusTotal, os:Windows, type:RAT, cybergate, malware:CyberGate
  Dec 11, 2019 07:04       | [ROKRAT\_Nov17\_1](https://fp.tools/home/technical\_data/iocs/items/5d5ed847-c018-43f6-baab-0f140a640c05)                                                                     | source:VirusTotal, T1057, T1105, T1063, os:Windows, target:SouthKorea, T1003, T1012, T1082, rokrat\_nov17\_1, malware:Rokrat, T1071, exfil:C2, T1102, T1041, T1056, type:RAT, T1497, T1113, misp-galaxy:mitre-enterprise-attack-attack-pattern="Process Discovery - T1057", misp-galaxy:mitre-enterprise-attack-attack-pattern="Remote File Copy - T1105", misp-galaxy:mitre-enterprise-attack-attack-pattern="Security Software Discovery - T1063", misp-galaxy:mitre-enterprise-attack-attack-pattern="Credential Dumping - T1003", misp-galaxy:mitre-enterprise-attack-attack-pattern="Query Registry - T1012", misp-galaxy:mitre-enterprise-attack-attack-pattern="System Information Discovery - T1082", misp-galaxy:mitre-enterprise-attack-attack-pattern="Standard Application Layer Protocol - T1071", misp-galaxy:mitre-enterprise-attack-attack-pattern="Web Service - T1102", misp-galaxy:mitre-enterprise-attack-attack-pattern="Exfiltration Over Command and Control Channel - T1041", misp-galaxy:mitre-enterprise-attack-attack-pattern="Input Capture - T1056", misp-galaxy:mitre-enterprise-attack-attack-pattern="Screen Capture - T1113"
  Dec 11, 2019 07:04       | [Sodinokibi\_Unreachable\_After\_MZ\_Check](https://fp.tools/home/technical\_data/iocs/items/5da01a74-4b5c-4160-83c6-05d00a640c05)                                            | source:VirusTotal, sodinokibi\_unreachable\_after\_mz\_check
  Dec 11, 2019 07:04       | [MegaCortex\_Load\_Dinkum\_CLib](https://fp.tools/home/technical\_data/iocs/items/5da01a84-b3fc-4eef-961d-0a340a640c05)                                                       | source:VirusTotal, megacortex\_load\_dinkum\_clib, malware:MegaCortex, type:Ransomware, os:Windows
  Dec 11, 2019 07:04       | [Command\_Line\_Options](https://fp.tools/home/technical\_data/iocs/items/5da01a75-0f20-41da-83e1-56550a640c05)                                                               | source:VirusTotal, command\_line\_options
  Dec 11, 2019 06:17       | [CryptingService\_74dd32ce57900738cba4d945e4619289ff040a9e\_2019-12-11T03:01:01.000Z](https://fp.tools/home/technical\_data/iocs/items/5df089e2-5e0c-4c12-b890-006e0a21270c)  | source:CryptingService2
  Dec 11, 2019 06:03       | [Gandcrab](https://fp.tools/home/technical\_data/iocs/items/5d07d587-a9ac-4da1-9c72-05cd0a640c05)                                                                             | source:VirusTotal, type:Ransomware, gandcrab, malware:GandCrab, os:Windows
  Dec 11, 2019 06:00       | [botox\_lampeduza\_amaterasu\_output5E0600](https://fp.tools/home/technical\_data/iocs/items/5d1504b4-572c-47dd-afb2-05d20a640c05)                                            | source:VirusTotal, botox\_lampeduza\_amaterasu\_output5e0600
  Dec 11, 2019 04:17       | [CryptingService\_e2f163c72837c6b4386ef9158d017418ab149b13\_2019-12-11T03:01:01.000Z](https://fp.tools/home/technical\_data/iocs/items/5df06dbf-7f10-47ff-b7c7-00720a21270c)  | source:CryptingService2
  Dec 11, 2019 04:16       | [CryptingService\_2c13004c346bf79bbec61f6a65fb5b11d5c6f557\_2019-12-11T02:01:02.000Z](https://fp.tools/home/technical\_data/iocs/items/5df06db3-9170-4b8d-b5b8-006e0a21270c)  | source:CryptingService2
  Dec 11, 2019 04:16       | [CryptingService\_5eda60cd7c1d4e5dd4fc5e0d3746bd4879de3959\_2019-12-11T03:01:01.000Z](https://fp.tools/home/technical\_data/iocs/items/5df06da7-45f0-4712-9fb6-00500a21253a)  | source:CryptingService2
  Dec 11, 2019 04:16       | [CryptingService\_981ad08f56f265e9e7209e09e3842d8a6b7f7563\_2019-12-11T03:01:01.000Z](https://fp.tools/home/technical\_data/iocs/items/5df06d94-3c3c-4f94-880e-05040a21270c)  | source:CryptingService2
  Dec 11, 2019 04:16       | [CryptingService\_7dbfe923559cbb91031dbe2b616c16f5aa40233f\_2019-12-11T02:01:02.000Z](https://fp.tools/home/technical\_data/iocs/items/5df06d89-c758-4ba4-ac03-00500a21253a)  | source:CryptingService2
  Dec 11, 2019 04:00       | [cobalt\_beacon](https://fp.tools/home/technical\_data/iocs/items/5d07ff66-2544-4632-b2bc-0f140a640c05)                                                                       | source:VirusTotal, cobalt\_beacon
  Dec 10, 2019 19:00       | [Loki](https://fp.tools/home/technical\_data/iocs/items/5d087e04-1464-4a26-964e-05cd0a640c05)                                                                                 | source:VirusTotal, type:Stealer, malware:Loki, loki, os:Windows
  Dec 10, 2019 19:00       | [crime\_alina\_pos\_3](https://fp.tools/home/technical\_data/iocs/items/5d0d6fb8-9ab4-48e6-b4a5-0a450a640c05)                                                                 | source:VirusTotal, crime\_alina\_pos\_3, type:POS, malware:Alina
  Dec 10, 2019 19:00       | [Kovter](https://fp.tools/home/technical\_data/iocs/items/5d0aa281-9768-4f33-9903-05d20a640c05)                                                                               | source:VirusTotal, actor:KovCoreG, kovter, os:Windows, type:Trojan, malware:Kovter
  Dec 10, 2019 17:24       | [zeroclear Oilrig](https://fp.tools/home/technical\_data/iocs/items/5defd365-659c-46c0-b67b-004c0a21253a)                                                                     | origin:Iran, actor:APT34, malware:ransomware:zeroclear

All events and details (fp-tools):
[https://fp.tools/home/search/iocs](https://fp.tools/home/search/iocs)

### 12. flashpoint-common-lookup

* * * * *

Lookup any type of indicator

##### Base Command

`flashpoint-common-lookup`

##### Input

  **Argument Name**  | **Description**                                               | **Required**
  -------------------| --------------------------------------------------------------| --------------
  indicator          | Specify indicator value like any domain, ip, email, url etc.  | Required

 

##### Context Output

  **Path**             | **Type**  | **Description**
  ---------------------| ----------| -----------------------------------------
  DBotScore.Indicator  | string    | The indicator that was tested.
  DBotScore.Score      | number    | The indicator score.
  DBotScore.Type       | string    | The indicator type.
  DBotScore.Vendor     | string    | The vendor used to calculate the score.

 

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

  **Date Observed (UTC)**  | **Name**  | **Tags**
  -------------------------| ----------| -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Oct 11, 2019 15:30       | ModiRAT   | misp-galaxy:mitre-enterprise-attack-attack-pattern="Deobfuscate/Decode Files or Information - T1140", misp-galaxy:mitre-enterprise-attack-attack-pattern="System Owner/User Discovery - T1033", misp-galaxy:mitre-enterprise-attack-attack-pattern="System Information Discovery - T1082", misp-galaxy:mitre-enterprise-attack-attack-pattern="Screen Capture - T1113", misp-galaxy:mitre-enterprise-attack-attack-pattern="Custom Command and Control Protocol - T1094", misp-galaxy:mitre-enterprise-attack-attack-pattern="Data Encoding - T1132", misp-galaxy:mitre-enterprise-attack-attack-pattern="Uncommonly Used Port - T1065", malware:ModiRAT, type:RAT, os:Windows, report:FQmMHh1rR\_WuGd\_PNVv-bQ

All events and details (fp-tools):
[https://fp.tools/home/search/iocs?group=indicator&ioc\_value=mondns.myftp.biz](https://fp.tools/home/search/iocs?group=indicator&ioc\_value=mondns.myftp.biz)

### 13. flashpoint-get-forum-details

* * * * *

Get forum details

##### Base Command

`flashpoint-get-forum-details`

##### Input

  **Argument Name**   |**Description**   | **Required**
  ------------------- |------------------| --------------
  forum\_id           |Specify forum id  | Required

 

##### Context Output

  **Path**                      | **Type**  | **Description**
  ------------------------------| ----------| ---------------------------------------------------------------------
  Flashpoint.forum.description  | string    | Description of forum.
  Flashpoint.forum.hostname     | string    | Display hostname of forum.
  Flashpoint.forum.name         | string    | Display name of forum.
  Flashpoint.forum.stats        | Unknown   | Display stats like posts, rooms, threads and users details.
  Flashpoint.forum.tags         | Unknown   | Display list of tags which includes id, name, parent\_tag and uuid.

 

##### Command Example

`!flashpoint-get-forum-details forum_id=ifY5BsXeXQqdTx3fafZbIg`

##### Context Example

    {
        "Flashpoint": {
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

  **Name**  | **Hostname**   | **Tags**
  ----------| ---------------| ------------------------------------------
  0hack     | bbs.0hack.com  | Chinese, Cyber Threat, Hacking, Language

### 14. flashpoint-get-forum-room-details

* * * * *

Get room details

##### Base Command

`flashpoint-get-forum-room-details`

##### Input

  **Argument Name**  | **Description**  | **Required**
  -------------------| -----------------| --------------
  room\_id           | Specify room id  | Required

 

##### Context Output

  **Path**                     | **Type**  | **Description**
  -----------------------------| ----------| ----------------------------------------------------------------------------------------
  flashpoint.forum.room.forum  | Unknown   | Display all forum details like forum name, hostname, platform url, stats and tags etc.
  flashpoint.forum.room.title  | string    | Title of the room
  flashpoint.forum.room.url    | string    | url of the room

 

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

  **Forum Name**  | **Title**     | **URL**
  ----------------| --------------| ----------------------------------------------------------
  Crdpro          | Bank Carding  | forumdisplay.php?f=70&s=6e25902255e1b57bfe37dd2749dafd66

### 15. flashpoint-get-forum-user-details

* * * * *

Get user details

##### Base Command

`flashpoint-get-forum-user-details`

##### Input

  **Argument Name**  | **Description**  | **Required**
  -------------------| -----------------| --------------
  user\_id           | Specify user id  | Required

 

##### Context Output

  **Path**                             | **Type**  | **Description**
  -------------------------------------| ----------| ----------------------------------------------------------------------------
  flashpoint.forum.user.forum          | Unknown   | Display all forum details like id, hostname, description, stats, tags etc.
  flashpoint.forum.user.name           | string    | Name of author.
  flashpoint.forum.user.platform\_url  | string    | platform url of user.
  flashpoint.forum.user.url            | string    | URL of user.

 

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

  **Forum Name**  | **Name**    | **URL**
  ----------------| ------------| ----------------------------------------------------------------------------
  Crdpro          | IllWillPub  | http://www.crdpro.su/member.php?s=9f099a0eebc5f7c79e36fc688af2f697&u=50678

### 16. flashpoint-get-forum-post-details

* * * * *

Get post details

##### Base Command

`flashpoint-get-forum-post-details`

##### Input

  **Argument Name**  | **Description**  | **Required**
  -------------------| -----------------| --------------
  post\_id           | Specify post id  | Required

 

##### Context Output

  **Path**                             | **Type**  | **Description**
  -------------------------------------| ----------| ------------------------------------------------------------------------------------
  flashpoint.forum.post.forum          | Unknown   | Display all forum details of post like id, hostname, stats, description, tags etc.
  flashpoint.forum.post.room           | Unknown   | Display room details of post like room title, id, url, platform url etc.
  flashpoint.forum.post.user           | Unknown   | Display user details of post like user id, name, url, platform url etc.
  flashpoint.forum.post.platform\_url  | string    | platform url of post.
  flashpoint.forum.post.published\_at  | Unknown   | published date of post.
  flashpoint.forum.post.url            | Unknown   | Display url of post.

 

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

  **Published at**          |  **Forum Name** |  **Room Title** |  **Author Name**  | **Thread Title**                 |  **URL**                                                      |  **Platform url**
  --------------------------| ----------------| ----------------| ----------------- |----------------------------------| --------------------------------------------------------------| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  2019-12-10T01:17:00+00:00 |  Ord-UA         |  Форум          |  Дубовик          | ДСНС на чолі з Бочковським і К…. |  2014/10/22/dsns-na-choli-z-bochkovskim-i-k/?lpage=1&page=580 |  [https://fp.tools/home/ddw/forums/threads/M3NorvmYVoG6rVFHnP3T9w?id=PDo1xGiKXDebHGc8fZme6g](https://fp.tools/home/ddw/forums/threads/M3NorvmYVoG6rVFHnP3T9w?id=PDo1xGiKXDebHGc8fZme6g)

### 17. flashpoint-search-forum-sites

* * * * *

Search forum sites using a keyword

##### Base Command

`flashpoint-search-forum-sites`

##### Input

  **Argument Name**  | **Description**                  | **Required**
  -------------------| ---------------------------------| --------------
  site\_search       | Search by site keyword or text.  | Required

 

##### Context Output

There are no context output for this command.

 

##### Command Example

`!flashpoint-search-forum-sites site_search="0hack"`

##### Context Example

    {}

##### Human Readable Output

### Flashpoint Forum sites related to search: 0hack

Top 10 sites:

### Below are the detail found:

  **Name**  | **Hostname**    |**Description**
  ----------| --------------- |-------------------------------------------------------------------------------------------------------------------------------
  0hack     | bbs.0hack.com   |0hack (零黑联盟) is a Chinese-language hacker training forum. The forum appears to be affiliated with 非凡安全网, 803389.com.

### 18. flashpoint-search-forum-posts

* * * * *

Search forum posts using a keyword

##### Base Command

`flashpoint-search-forum-posts`

##### Input

  **Argument Name**  | **Description**                  | **Required**
  -------------------| ---------------------------------| --------------
  post\_search       | Search by post keyword or text.  | Required

 

##### Context Output

There are no context output for this command.

 

##### Command Example

`!flashpoint-search-forum-posts post_search="The Courtyard Café"`

##### Context Example

    {}

##### Human Readable Output

### Flashpoint Forum posts related to search: The Courtyard Café

Top 10 posts:

### Below are the detail found:

  **Forum Name**      | **Thread Title**                    | **Room Title**      | **Author Name**  | **Platform URL**
  --------------------| ------------------------------------| --------------------| -----------------| ---------------------------------------------------------------------------------------------------------------------------------
  The Sammyboy Times  | Fleeting Pleasures....              | The Courtyard Café  | glockman         | [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/K6PC6xeVXueMtwa1sXeJ5Q?id=VHhWvcvDWvGwHlM88LVRwQ)
  The Sammyboy Times  | smoke on the water, fire in th....  | The Courtyard Café  | syed putra       | [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/DJz6tF8BUPylN-i0Y0ezWQ?id=5MiNcD0QWcWRpe-PJGrhQg)
  The Sammyboy Times  | [Singapore] - French girl kena....  | The Courtyard Café  | laksaboy         | [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/jAC8PVZ0VwGPeIG-vfsSEQ?id=TYd7LjRdW3CVY7ASn8iv-A)
  The Sammyboy Times  | smoke on the water, fire in th....  | The Courtyard Café  | laksaboy         | [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/DJz6tF8BUPylN-i0Y0ezWQ?id=ja2OHSLZVw6bMM8O30TU1g)
  The Sammyboy Times  | smoke on the water, fire in th....  | The Courtyard Café  | Leongsam         | [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/DJz6tF8BUPylN-i0Y0ezWQ?id=gPnw4iMzWt6Sc898v7--xA)
  The Sammyboy Times  | smoke on the water, fire in th....  | The Courtyard Café  | rambo22          | [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/DJz6tF8BUPylN-i0Y0ezWQ?id=cTsXksypUQSJ2n0hzJ0fkg)
  The Sammyboy Times  | Fleeting Pleasures....              | The Courtyard Café  | nightsafari      | [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/K6PC6xeVXueMtwa1sXeJ5Q?id=A5P4o7sXUVuAqh-mDfeNpg)
  The Sammyboy Times  | [Singapore] - French girl kena....  | The Courtyard Café  | nightsafari      | [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/jAC8PVZ0VwGPeIG-vfsSEQ?id=zaKSjh1tUsGlAtjiHbvWyg)
  The Sammyboy Times  | [Singapore] - French girl kena....  | The Courtyard Café  | nightsafari      | [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/jAC8PVZ0VwGPeIG-vfsSEQ?id=Wkl\_jF-BW8OC7tvGf6ubaA)
  The Sammyboy Times  | HTHT....                            | The Courtyard Café  | Claire           | [https://fp.tools/home/ddw/foru...](https://fp.tools/home/ddw/forums/threads/jDxdVQ8MWlykzOpPsSC6FQ?id=ufiwTsy2VzWaCGW42keoUA)

Link to forum post-search on Flashpoint platform:
[https://fp.tools/home/search/forums?query=The%20Courtyard%20Caf%C3%A9](https://fp.tools/home/search/forums?query=The%20Courtyard%20Caf%C3%A9)

