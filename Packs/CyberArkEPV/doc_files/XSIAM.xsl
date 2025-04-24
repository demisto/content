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
