
# CyberArk PAM Self-Hosted

<~XSIAM>

This pack includes Cortex XSIAM content.

## Configuration on Server Side

This section describes the steps required to configure Syslog forwarding of vault audit logs, such as user activity and safe activity events, from CyberArk PAM Self-Hosted Vault to Cortex XSIAM.

### General Overview
The CyberArk vault event logs are generated in [XML](https://en.wikipedia.org/wiki/XML) format. 
In order to forward the logs via Syslog to Cortex XSIAM, 
the XML event records must be converted to suitable [CEF](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm) messages. 

### Set up the XSL Translator
This transformation from XML event records to CEF messages is done though a suitable [XSL](https://en.wikipedia.org/wiki/XSL) translator file. 
MAYA TEST An example of an XSL file can be found https://raw.githubusercontent.com/demisto/content/fcf4535d373df78bded4b1bedacdd505d25cc095/Packs/CyberArkEPV/doc_files/XSIAM.xsl. This file can be used directly within the target vault.

#### Set up the Syslog Configuration
1. Navigate to the *Conf* subfolder under the CyberArk Vault server installation folder (*PrivateArk\Server\Conf*).
2. Copy the *\[SYSLOG\]* section from the *DBParm.sample.ini* sample file, and paste it at the bottom of the *DBParm.ini* file. 
3. Set the following parameters under the copied *\[SYSLOG\]* section in the *DBParm.ini* file
   | Parameter                       | Description    
   | :---                            | :---                    
   | `SyslogServerIP`                | IP address of the Cortex XSIAM Broker VM Syslog Server.  
   | `SyslogServerPort`              | Target port that the Cortex XSIAM Broker VM Syslog Server is listening on for receiving Syslog messages from CyberArk.  
   | `SyslogServerProtocol`          | The protocol that will be used to forward the Syslog messages to Cortex XSIAM: *UDP* (the default setting), *TCP* or *TLS* (Note: for *TLS*, additional settings are required for configuring certificates, see [*Configure encrypted and non-encrypted protocols*](https://docs.cyberark.com/PAS/Latest/en/Content/PASIMP/Integrating-with-SIEM-Applications.htm#Configureencryptedandnonencryptedprotocols)).
   | `SyslogMessageCodeFilter`       | Range or list of requested message codes that should be sent to  Cortex XSIAM through the syslog protocol. See [*Vault Audit Action Codes*](https://docs.cyberark.com/PAS/Latest/en/Content/PASREF/Vault%20Audit%20Action%20Codes.htm) for the complete list of vault events message codes. By default, all message codes are sent for user and safe activities. For including all Vault events, define the following range: *0-999*. 
   | `SyslogTranslatorFile`   | Specify the relative path in the CyberArk Vault server installation folder (*PrivateArk\Server*) to the relevant XLS translator file  (see [*Set up the XSL Translator*](#Set-up-the-XSL-Translator) section above). For example: *Syslog\XSIAM.xsl*.
   | `UseLegacySyslogFormat`   | Controls whether the syslog messages should be sent in the old legacy syslog format (*Yes*), or in the newer modern [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424) format (*No*). For Cortex XSIAM set this parameter with the default value of *No*. 
   |`SendMonitoringMessage`| Controls whether the Syslog messages that are sent to Cortex XSIAM should include periodic server* system monitoring* events as well (in addition to *audit events*). For Cortex XSIAM set this parameter with the default value of *no*.

 See [*DBPARM.ini file parameters*](https://docs.cyberark.com/PAS/Latest/en/Content/PASIMP/Integrating-with-SIEM-Applications.htm#DBPARMinifileparameters) for a complete list of the possible *DBPARM.ini* file syslog parameters.

 Below is a sample *\[SYSLOG\]* configuration section for the *DBParm.ini* file: 
 
  ```BASH        
            [SYSLOG]
            SyslogServerIP=192.168.1.123
            SyslogServerPort=514
            SyslogServerProtocol=UDP
            SyslogMessageCodeFilter=0-999
            SyslogTranslatorFile=Syslog\XSIAM.xsl
            UseLegacySyslogFormat=No
            SendMonitoringMessage=no
``` 
4. Restart the Vault server to apply the configuration changes. 

### Remarks
CyberArk Vault supports additional syslog configuration settings such as forwarding audit events to *multiple* syslog servers, each server with it's own unique set of syslog parameters. For additional details, refer to the [CyberArk Vault documentation](https://docs.cyberark.com/PAS/Latest/en/Content/PASIMP/Integrating-with-SIEM-Applications.htm?tocpath=End%20user%7CReports%20and%20Audits%7C_____6).


## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. Set the following parameters for the Syslog configuration:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | Should be aligned with the protocol defined in the *SyslogServerProtocol* parameter in the `[SYSLOG]` section of the *DBParm.ini* configuration file on the CyberArk Vault server (see [Set up the Syslog Configuration](#set-up-the-syslog-configuration)).   
   | `Port`        | Should be aligned with the protocol defined in the *SyslogServerPort* parameter in the `[SYSLOG]` section of the *DBParm.ini* configuration file on the CyberArk Vault server (see [Set up the Syslog Configuration](#set-up-the-syslog-configuration)).   
   | `Format`      | Select **CEF**. 
   | `Vendor`      | Select **Auto-Detect** (Would be determined automatically from the CEF header *Vendor* field). 
   | `Product`     | Select **Auto-Detect** (Would be determined automatically from the CEF header *Product* field). 

</~XSIAM>
