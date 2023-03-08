# DO NOT USE IN PRODUCTION

## Random Threat Intelligence
This is an example integration that returns fake data against the following indicator types in XSOAR, intended for demos, where you don't want to hit things like VirusTotal etc.  This will generate good, suspicious, or bad indicators for the following:
- IP (ip command)
- File (file command)
- Domain (domain command)
- URL (url command)

### Custom Indicator Types
This integration also demos how you could build a custom reputation command into XSOAR to get indicator data for say an internal host.  In this example you can create the following custom indicator after enabling this integration (Settings -> Advanced -> Indicator Types)

Indicator Type: CXHost
Regex: ```(crossiscoming\d{3,5})```
Reputation Command: cxhost

This will mean whenever a host gets extracted matching that regex, the command will return returning data about that hose.

### Private IP Ranges
This integration also does the same for a custom indicator type of 'Private IP'.   By default, private IPs such as 10.10.10.10 would be extracted an run through VirusTotal.   In this case I'd rather reference an internal system for information about that IP.  This can be done in either an integration, and/or through a user reputation script. 

Indicator Type: Private IP
Regex: ```\b(10((?:\[\.\]|\.)(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|((172(?:\[\.\]|\.)(1[6-9]|2[0-9]|3[01]))|192(?:\[\.\]|\.)168)((?:\[\.\]|\.)(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){2})```
Reputation Command: private-ip

#### Exclusions: For this to work, exclude the following CIDR ranges as type IP so they don't get auto-extracted as such: 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12