
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
The following is an example for an XSL file. This file can be used directly within the target vault;
``` xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:import href='./Syslog/RFC5424Changes.xsl'/>
    <xsl:output method='text' version='1.0' encoding='UTF-8'/>

    <xsl:template match="/">
   <xsl:apply-imports />
        <xsl:for-each select="syslog/audit_record">CEF:0|<xsl:value-of select="Vendor"/>|<xsl:value-of select="Product"/>|<xsl:value-of select="Version"/>|<xsl:value-of select="MessageID"/>|<xsl:choose><xsl:when test="Severity='Critical' or Severity='Error'">Failure: </xsl:when></xsl:choose><xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="Desc"/>
        </xsl:call-template>|<xsl:choose><xsl:when test="Severity='Critical'">10</xsl:when><xsl:when test="Severity='Error'">7</xsl:when><xsl:when test="Severity='Info'">5</xsl:when><xsl:otherwise>0</xsl:otherwise></xsl:choose><!--xsl:value-of select="Severity"/-->|act=<xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="Action"/>
        </xsl:call-template> suser=<xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="Issuer"/>
        </xsl:call-template> fname=<xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="File"/>
        </xsl:call-template> dvc=<xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="GatewayStation"/>
        </xsl:call-template> shost=<xsl:choose>
            <!--xsl:If its PSM Connect and Disconnect event we will show SrcHost value 
                otherwise we will show station value"/-->
            <xsl:when test="MessageID=300 or MessageID=301 or MessageID=302 or MessageID=303"><xsl:call-template name="string-GetValue">
                <xsl:with-param name="from" select="'SrcHost='"/>
                <xsl:with-param name="to" select="';'"/> 
                <xsl:with-param name="string" select="ExtraDetails"/>
            </xsl:call-template></xsl:when>
            <xsl:otherwise><xsl:call-template name="string-replace">
                <xsl:with-param name="from" select="'='"/>
                <xsl:with-param name="to" select="'\='"/> 
                <xsl:with-param name="string" select="Station"/>
            </xsl:call-template></xsl:otherwise>
        </xsl:choose> dhost=<xsl:choose>
            <!--xsl:If its PSM Connect and Disconnect event we will show DstHost value/-->
            <xsl:when test="MessageID=300 or MessageID=301 or MessageID=302 or MessageID=303"><xsl:call-template name="string-GetValue">
                <xsl:with-param name="from" select="'DstHost='"/>
                <xsl:with-param name="to" select="';'"/> 
                <xsl:with-param name="string" select="ExtraDetails"/>
            </xsl:call-template></xsl:when>
            <!--xsl:For transparent connection event we will show RemotheMachine value
                from the PVWA XML/-->
            <xsl:when test="MessageID=295 and PvwaDetails/RequestReason/ConnectionDetails/RemoteMachine!=''"><xsl:call-template name="string-replace">
                <xsl:with-param name="from" select="'='"/>
                <xsl:with-param name="to" select="'\='"/> 
                <xsl:with-param name="string" select="PvwaDetails/RequestReason/ConnectionDetails/RemoteMachine"/>
            </xsl:call-template></xsl:when>
            <!--xsl:Check izf extra details is not empty is so extract the dsthost value from it/-->
                <xsl:when test="ExtraDetails!=''"><xsl:call-template name="string-GetValue">
                <xsl:with-param name="from" select="'DstHost='"/>
                <xsl:with-param name="to" select="';'"/> 
                <xsl:with-param name="string" select="ExtraDetails"/>
                </xsl:call-template></xsl:when>
            <!--xsl:Otherwise we will show Address value from the file categories/-->
            <xsl:otherwise><xsl:for-each select="CAProperties/CAProperty"><xsl:if test="@Name='Address'"><xsl:call-template name="string-replace">
                    <xsl:with-param name="from" select="'='"/>
                    <xsl:with-param name="to" select="'/='"/> 
                    <xsl:with-param name="string" select="@Value"/></xsl:call-template></xsl:if></xsl:for-each>
            </xsl:otherwise>
        </xsl:choose> duser=<xsl:choose>
            <!--xsl:If its PSM Connect and Disconnect event we will show User value/-->
            <xsl:when test="MessageID=300 or MessageID=301 or MessageID=302 or MessageID=303"><xsl:call-template name="string-GetValue">
                <xsl:with-param name="from" select="'User='"/>
                <xsl:with-param name="to" select="';'"/> 
                <xsl:with-param name="string" select="ExtraDetails"/>
                <!--xsl:If it not PSM we check if the Target user field is not empty if so we show his value/-->
            </xsl:call-template></xsl:when><xsl:when test="TargetUser != ''">
                <xsl:call-template name="string-replace">
                    <xsl:with-param name="from" select="'='"/>
                    <xsl:with-param name="to" select="'\='"/> 
                    <xsl:with-param name="string" select="TargetUser"/></xsl:call-template></xsl:when>
            <!--xsl:Otherwise we show  the username value from the file categories/-->
            <xsl:otherwise><xsl:for-each select="CAProperties/CAProperty"><xsl:if test="@Name='UserName'"><xsl:call-template name="string-replace">
                <xsl:with-param name="from" select="'='"/>
                <xsl:with-param name="to" select="'/='"/> 
                <xsl:with-param name="string" select="@Value"/></xsl:call-template></xsl:if></xsl:for-each>
            </xsl:otherwise></xsl:choose> externalId=<xsl:call-template name="string-GetValue">
                <xsl:with-param name="from" select="'SessionID='"/>
                <xsl:with-param name="to" select="';'"/> 
                <xsl:with-param name="string" select="ExtraDetails"/>
            </xsl:call-template> app=<xsl:call-template name="string-GetValue">
                <xsl:with-param name="from" select="'Protocol='"/>
                <xsl:with-param name="to" select="';'"/> 
                <xsl:with-param name="string" select="ExtraDetails"/>
            </xsl:call-template> reason=<xsl:call-template name="string-GetValue">
                <xsl:with-param name="from" select="'Command='"/>
                <xsl:with-param name="to" select="';'"/> 
                <xsl:with-param name="string" select="ExtraDetails"/>
            </xsl:call-template> cs1Label=Affected User Name cs1=<xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="SourceUser"/>
        </xsl:call-template> cs2Label=Safe Name cs2=<xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="Safe"/>
        </xsl:call-template> cs3Label=Device Type cs3=<xsl:for-each select="CAProperties/CAProperty"><xsl:if test="@Name='DeviceType'"><xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'/='"/> 
            <xsl:with-param name="string" select="@Value"/>
        </xsl:call-template></xsl:if></xsl:for-each> cs4Label=Database cs4=<xsl:call-template name="string-GetValue">
            <xsl:with-param name="from" select="'DataBase='"/>
            <xsl:with-param name="to" select="';'"/> 
            <xsl:with-param name="string" select="ExtraDetails"/>
        </xsl:call-template> cs5Label=Other info cs5=<xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="Location"/>   
        </xsl:call-template> <xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="Category"/>   
        </xsl:call-template> <xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="GatewayStation"/>   
			  </xsl:call-template> cs6Label=IsoTimestamp cs6=<xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="IsoTimestamp"/>
        </xsl:call-template> cn1Label=RequestId cn1=<xsl:value-of select="RequestId"/> cn2Label=TicketId cn2=<xsl:value-of select="Reason"/>  msg=<xsl:call-template name="string-replace">
            <xsl:with-param name="from" select="'='"/>
            <xsl:with-param name="to" select="'\='"/> 
            <xsl:with-param name="string" select="Reason"/>
        </xsl:call-template> <xsl:choose><xsl:when test="Severity='Critical' or Severity='Error'">Failure: </xsl:when></xsl:choose>
      </xsl:for-each>
	  <xsl:text>&#xa;</xsl:text>
    </xsl:template>

    <!-- Gets the Value of a member from a long string 
           from - the name of the member(pre)
           to - this represents the end of the value(post)
           its also calls the string-replace and replace the = with /=
           Parsing needed for Arcsight.-->
    <xsl:template name="string-GetValue" >
        <xsl:param name="string"/>
        <xsl:param name="from"/>
        <xsl:param name="to"/>
        <xsl:choose>
            <xsl:when test="contains($string,$from)">
                <xsl:call-template name="string-replace">
                    <xsl:with-param name="string" select="substring-before(substring-after($string,$from),$to)"/>
                    <xsl:with-param name="from" select="'='"/>
                    <xsl:with-param name="to" select="'/='"/>
                </xsl:call-template>
            </xsl:when>
        </xsl:choose>
    </xsl:template>

    <!-- replace all occurences of the character(s) `from'
     by the string `to' in the string `string'.-->
    <xsl:template name="string-replace" >
        <xsl:param name="string"/>
        <xsl:param name="from"/>
        <xsl:param name="to"/>
        <xsl:choose>
            <xsl:when test="contains($string,$from)">
                <xsl:value-of select="substring-before($string,$from)"/>
                <xsl:value-of select="$to"/>
                <xsl:call-template name="string-replace">
                    <xsl:with-param name="string" select="substring-after($string,$from)"/>
                    <xsl:with-param name="from" select="$from"/>
                    <xsl:with-param name="to" select="$to"/>
                </xsl:call-template>
            </xsl:when>
            <xsl:otherwise>
                <xsl:value-of select="$string"/>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>

</xsl:stylesheet>
```


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
