. $PSScriptRoot\CommonServerPowerShell.ps1
#Blank Variable

$xpath_template_mobile = @()
$xpath_template_mobile_auth_profile = @()
$xpath_template_mobile_gp_portal = @()
$xpath_template_mobile_gp_gateway = @()
$xpath_plugin_mobile_zone = @()
$xpath_template_mobile = @()
$xpath_template_stack_mobile = @()
$xpath_device_group_mobile = @()
$xpath_pre_rule_mobile = @()
$xpath_template_mobile_plugin = @()
$xpath_tunnel_interface = @()
$mobile_ip_pool = @()
$mobile_url = @()
$url = @()
$rkey = @()
$localdb_name = @()

#Script Value
$Headers = "$rKey application"
$type = "config"
$mobile_ip_pool = $demisto.args().mobile_ip_pool
$mobile_url = $demisto.args().mobile_url
$localdb_name = "Localdb2"
$xpath_template_mobile = "/config/devices/entry[@name='localhost.localdomain']/template"
$xpath_template_mobile_auth_profile = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Mobile_User_Template']/config/shared/authentication-profile/entry[@name='$localdb_name']"
$xpath_template_mobile_gp_portal = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Mobile_User_Template']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect/global-protect-portal/entry[@name='GlobalProtect_Portal']"
$xpath_template_mobile_gp_gateway = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Mobile_User_Template']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect/global-protect-gateway/entry[@name='GlobalProtect_External_Gateway']"
$xpath_plugin_mobile_zone = "/config/devices/entry[@name='localhost.localdomain']/plugins/cloud_services"
$xpath_template_mobile = "/config/devices/entry[@name='localhost.localdomain']/template"
$xpath_template_stack_mobile = "/config/devices/entry[@name='localhost.localdomain']/template-stack"
$xpath_device_group_mobile = "/config/devices/entry[@name='localhost.localdomain']/device-group"
$xpath_pre_rule_mobile = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='Mobile_User_Device_Group']"
$xpath_template_mobile_plugin = "/config/devices/entry[@name='localhost.localdomain']/plugins/cloud_services/mobile-users/onboarding/entry[@name='$mobile_url.gpcloudservice.com']"
$xpath_tunnel_interface = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Mobile_User_Template']/config/devices/entry[@name='localhost.localdomain']/network/tunnel/global-protect-gateway/entry[@name='GlobalProtect_External_Gateway-N']"

#Set Command for Prisma Access Mobile Template
$strUri_set_template_mobile = "<entry name='Mobile_User_Template'>
    <settings>
     <default-vsys>vsys1</default-vsys>
   </settings>
   <description> Template (Use the Cloud Services plugin to edit)</description>
   <config>
     <devices>
       <entry name='localhost.localdomain'>
         <vsys>
           <entry name='vsys1'>
             <zone>
               <entry name='Mobile-trust'>
                 <network>
                   <tap/>
                 </network>
               </entry>
               <entry name='Mobile-untrust'>
                 <network>
                   <tap/>
                 </network>
               </entry>
             </zone>
           </entry>
         </vsys>
       </entry>
     </devices>
     <shared>
       <log-settings>
         <system>
           <match-list>
             <entry name='system-gpcs-default'>
               <filter>All Logs</filter>
               <send-to-panorama>yes</send-to-panorama>
             </entry>
           </match-list>
         </system>
         <userid>
           <match-list>
             <entry name='userid-gpcs-default'>
               <filter>All Logs</filter>
               <send-to-panorama>yes</send-to-panorama>
             </entry>
           </match-list>
         </userid>
       </log-settings>
     </shared>
   </config>
 </entry>"

 #Set Command for template stack creation
 $strUri_set_template_stack_mobile = "<entry name='Mobile_User_Template_Stack'>
  <templates>
      <member>Mobile_User_Template</member>
    </templates>
    <description> Template Stack (Use the Cloud Services plugin to edit)</description>
    <settings>
      <default-vsys>vsys1</default-vsys>
    </settings>
</entry>"

#Set Command for Device Group Profile
$strUri_set_device_group_mobile = "<entry name='Mobile_User_Device_Group'>
  <description> Device Group (Use the Cloud Services plugin to edit)</description>
  <devices/>
  <log-settings>
    <profiles>
      <entry name='Mobile-User-Log-Profile'>
        <match-list>
          <entry name='traffic-enhanced-app-logging'>
            <log-type>traffic</log-type>
            <filter>All Logs</filter>
            <send-to-panorama>yes</send-to-panorama>
          </entry>
          <entry name='threat-enhanced-app-logging'>
            <log-type>threat</log-type>
            <filter>All Logs</filter>
            <send-to-panorama>yes</send-to-panorama>
          </entry>
          <entry name='wildfire-enhanced-app-logging'>
            <log-type>wildfire</log-type>
            <filter>All Logs</filter>
            <send-to-panorama>yes</send-to-panorama>
          </entry>
          <entry name='url-enhanced-app-logging'>
            <log-type>url</log-type>
            <filter>All Logs</filter>
            <send-to-panorama>yes</send-to-panorama>
          </entry>
          <entry name='data-enhanced-app-logging'>
            <log-type>data</log-type>
            <filter>All Logs</filter>
            <send-to-panorama>yes</send-to-panorama>
          </entry>
          <entry name='tunnel-enhanced-app-logging'>
            <log-type>tunnel</log-type>
            <filter>All Logs</filter>
            <send-to-panorama>yes</send-to-panorama>
          </entry>
          <entry name='auth-enhanced-app-logging'>
            <log-type>auth</log-type>
            <filter>All Logs</filter>
            <send-to-panorama>yes</send-to-panorama>
          </entry>
        </match-list>
        <enhanced-application-logging>yes</enhanced-application-logging>
      </entry>
    </profiles>
  </log-settings>
  <reference-templates>
    <member>Mobile_User_Template</member>
  </reference-templates>
</entry>"

#Create Local DB Auth Profile
$strUri_set_template_mobile_auth_profile = "<multi-factor-auth>
    <mfa-enable>no</mfa-enable>
  </multi-factor-auth>
  <method>
    <local-database/>
  </method>
  <allow-list>
    <member>all</member>
  </allow-list>"

#Create Prisma Access Mobile Portal Configuration
$strUri_set_template_mobile_gp_portal = "<portal-config>
    <local-address>
      <interface>-</interface>
      <ip/>
    </local-address>
    <ssl-tls-service-profile>-</ssl-tls-service-profile>
    <client-auth>
      <entry name='DEFAULT'>
        <os>Any</os>
        <authentication-profile>$localdb_name</authentication-profile>
        <authentication-message>Enter login credentials</authentication-message>
      </entry>
    </client-auth>
    <custom-login-page>factory-default</custom-login-page>
    <custom-home-page>factory-default</custom-home-page>
  </portal-config>
  <client-config>
    <configs>
      <entry name='DEFAULT'>
        <gateways>
          <external>
            <list>
              <entry name='Prisma Access'>
                <fqdn>gpcloudservice.com</fqdn>
                <priority-rule>
                  <entry name='Any'>
                    <priority>1</priority>
                  </entry>
                </priority-rule>
                <manual>yes</manual>
              </entry>
            </list>
            <cutoff-time>5</cutoff-time>
          </external>
        </gateways>
        <authentication-override>
          <accept-cookie>
            <cookie-lifetime>
              <lifetime-in-hours>24</lifetime-in-hours>
            </cookie-lifetime>
          </accept-cookie>
          <cookie-encrypt-decrypt-cert>Authentication Cookie Cert</cookie-encrypt-decrypt-cert>
          <generate-cookie>yes</generate-cookie>
        </authentication-override>
        <source-user>
          <member>any</member>
        </source-user>
        <os>
          <member>any</member>
        </os>
      </entry>
    </configs>
  </client-config>
  <clientless-vpn>
    <hostname>$mobile_url.gpcloudservice.com</hostname>
    <dns-proxy>CloudDefault</dns-proxy>
  </clientless-vpn>"

#Set Tunnel Interface
$strUri_set_template_tunnel_interface =
"<local-address>
    <interface>-</interface>
    <ip/>
  </local-address>
  <tunnel-interface>-</tunnel-interface>"


#Create Prisma Access Mobile Gateway Configuration
$strUri_set_template_mobile_gp_gateway =
"<client-auth>
      <entry name='DEFAULT'>
        <authentication-profile>$localdb_name</authentication-profile>
        <os>Any</os>
      </entry>
    </client-auth>
    <remote-user-tunnel-configs>
      <entry name='DEFAULT'>
        <authentication-override>
          <accept-cookie>
            <cookie-lifetime>
              <lifetime-in-hours>24</lifetime-in-hours>
            </cookie-lifetime>
          </accept-cookie>
          <cookie-encrypt-decrypt-cert>Authentication Cookie Cert</cookie-encrypt-decrypt-cert>
          <generate-cookie>yes</generate-cookie>
        </authentication-override>
        <source-user>
          <member>any</member>
        </source-user>
        <os>
          <member>any</member>
        </os>
      </entry>
    </remote-user-tunnel-configs>
    <ssl-tls-service-profile>-</ssl-tls-service-profile>
    <tunnel-mode>yes</tunnel-mode>
  <remote-user-tunnel>-</remote-user-tunnel>"

#Create Prisma Access Mobile Plugin Configuration with Canada East and Canada Central selected
$strUri_set_prisma_access_mobile_plugin =
"<portal-hostname>
    <default-domain>
      <hostname>$mobile_url</hostname>
    </default-domain>
  </portal-hostname>
  <ip-pools>
    <entry name='worldwide'>
      <ip-pool>
        <member>$mobile_ip_pool</member>
      </ip-pool>
    </entry>
  </ip-pools>
  <dns-servers>
    <entry name='worldwide'/>
  </dns-servers>
  <authentication-profile>$localdb_name</authentication-profile>
  <authentication-override-certificate>Authentication Cookie Cert</authentication-override-certificate>
  <global-protect-portal>GlobalProtect_Portal</global-protect-portal>
  <global-protect-gateway>GlobalProtect_External_Gateway</global-protect-gateway>
  <deployment>
    <region>
      <entry name='americas'>
        <locations>
          <member>ca-central-1</member>
          <member>canada-central</member>
        </locations>
      </entry>
    </region>
  </deployment>
  <manual-gateway>
    <region>
      <entry name='americas'>
        <locations>
          <member>canada-central</member>
          <member>ca-central-1</member>
        </locations>
      </entry>
    </region>
  </manual-gateway>"

#Set Command for Pre-Rule Creation
$strUri_set_pre_rule_mobile =
"<pre-rulebase>
  <security>
    <rules>
      <entry name='Trust-to-Untrust' uuid='a4fa0418-92f6-4213-b98e-cf62caa3937d'>
        <profile-setting>
          <profiles>
            <url-filtering>
              <member>default</member>
            </url-filtering>
            <file-blocking>
              <member>basic file blocking</member>
            </file-blocking>
            <virus>
              <member>default</member>
            </virus>
            <spyware>
              <member>default</member>
            </spyware>
            <vulnerability>
              <member>default</member>
            </vulnerability>
            <wildfire-analysis>
              <member>default</member>
            </wildfire-analysis>
          </profiles>
        </profile-setting>
        <target>
          <negate>no</negate>
        </target>
        <to>
          <member>Mobile-untrust</member>
        </to>
        <from>
          <member>Mobile-trust</member>
        </from>
        <source>
          <member>any</member>
        </source>
        <destination>
          <member>any</member>
        </destination>
        <source-user>
          <member>any</member>
        </source-user>
        <category>
          <member>any</member>
        </category>
        <application>
          <member>any</member>
        </application>
        <service>
          <member>application-default</member>
        </service>
        <hip-profiles>
          <member>any</member>
        </hip-profiles>
        <action>allow</action>
        <log-setting>Mobile-User-Log-Profile</log-setting>
      </entry>
      <entry name='Trust-to-Trust' uuid='78025c03-76a3-402c-ab36-a0537ece276d'>
        <profile-setting>
          <profiles>
            <url-filtering>
              <member>default</member>
            </url-filtering>
            <file-blocking>
              <member>basic file blocking</member>
            </file-blocking>
            <virus>
              <member>default</member>
            </virus>
            <spyware>
              <member>default</member>
            </spyware>
            <vulnerability>
              <member>default</member>
            </vulnerability>
            <wildfire-analysis>
              <member>default</member>
            </wildfire-analysis>
          </profiles>
        </profile-setting>
        <target>
          <negate>no</negate>
        </target>
        <to>
          <member>Mobile-trust</member>
        </to>
        <from>
          <member>Mobile-trust</member>
        </from>
        <source>
          <member>any</member>
        </source>
        <destination>
          <member>any</member>
        </destination>
        <source-user>
          <member>any</member>
        </source-user>
        <category>
          <member>any</member>
        </category>
        <application>
          <member>any</member>
        </application>
        <service>
          <member>application-default</member>
        </service>
        <hip-profiles>
          <member>any</member>
        </hip-profiles>
        <action>allow</action>
        <log-setting>Mobile-User-Log-Profile</log-setting>
      </entry>
    </rules>
  </security>
</pre-rulebase>"


#Set Command for Zone Association

$strUri_set_plugin_mobile_zone =
"<mobile-users>
   <template-stack>Mobile_User_Template_Stack</template-stack>
  <device-group>Mobile_User_Device_Group</device-group>
  <trusted-zones>
    <member>Mobile-trust</member>
  </trusted-zones>
</mobile-users>"

#Run Command
$create_template_mobile = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_mobile
    "httptype" = "POST"
    "element" = $strUri_set_template_mobile
})
$create_template_mobile_message = $create_template_mobile[0]['Contents'] | Out-String
Write-Host "Mobile User Template creation successfully Output:$create_template_mobile_message"
Write-Host "Mobile User Zone Mobile-Untrust and Mobile-Trust creation Output:$create_template_mobile_message"

$create_template_stack_mobile = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_stack_mobile
    "httptype" = "POST"
    "element" = $strUri_set_template_stack_mobile
})
$create_template_stack_mobile_message = $create_template_stack_mobile[0]['Contents'] | Out-String
Write-Host "Mobile User Template Stack Creation Output : $create_template_stack_mobile_message"

$create_device_group_mobile = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_device_group_mobile
    "httptype" = "POST"
    "element" = $strUri_set_device_group_mobile
})
$create_device_group_mobile_message = $create_device_group_mobile[0]['Contents'] | Out-String
Write-Host "Mobile User Device Group Creation Ouput:$create_device_group_mobile_message"

$create_template_mobile_auth_profile = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_mobile_auth_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_mobile_auth_profile
})
$create_template_mobile_auth_profile_message = $create_template_mobile_auth_profile[0]['Contents'] | Out-String
Write-Host "Mobile User Local DB Auth Profile creation Ouput:$create_template_mobile_auth_profile_message"

$create_template_mobile_gp_portal = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_mobile_gp_portal
    "httptype" = "POST"
    "element" = $strUri_set_template_mobile_gp_portal
})
$create_template_mobile_gp_portal_message = $create_template_mobile_gp_portal[0]['Contents'] | Out-String
Write-Host "Prisma Access Mobile Portal creation Ouput:$create_template_mobile_gp_portal_message"

$create_tunnel_interface = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_tunnel_interface
    "httptype" = "POST"
    "element" = $strUri_set_template_tunnel_interface
})
$create_tunnel_interface_message = $create_tunnel_interface[0]['Contents'] | Out-String
Write-Host "Prisma Access Tunnel Interface creation Ouput:$create_tunnel_interface_message"

$create_template_mobile_gp_gateway = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_mobile_gp_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_mobile_gp_gateway
})
$create_template_mobile_gp_gateway_message = $create_template_mobile_gp_gateway[0]['Contents'] | Out-String
Write-Host "Prisma Access Mobile Gateway creation Ouput:$create_template_mobile_gp_portal_message"

$create_template_prisma_access_mobile_plugin = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_mobile_plugin
    "httptype" = "POST"
    "element" = $strUri_set_prisma_access_mobile_plugin
})
$create_template_prisma_access_mobile_plugin_message = $create_template_prisma_access_mobile_plugin[0]['Contents'] | Out-String
Write-Host "Prisma Access Mobile Plugin configuration Output:$create_template_prisma_access_mobile_plugin_message"

$create_pre_rule_mobile = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_pre_rule_mobile
    "httptype" = "POST"
    "element" = $strUri_set_pre_rule_mobile
})
$create_pre_rule_mobile_message = $create_pre_rule_mobile[0]['Contents'] | Out-String
Write-Host "Prisma Access Mobile Pre Rule creation Ouput:$create_pre_rule_mobile_message"

$create_prisma_access_mobile_plugin_zone = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_plugin_mobile_zone
    "httptype" = "POST"
    "element" = $strUri_set_prisma_access_mobile_plugin
})
$create_prisma_access_mobile_plugin_zone_message = $create_prisma_access_mobile_plugin_zone[0]['Contents'] | Out-String
Write-Host "Mobile User Zone Mobile-Trust has been move to Prisma Access Trusted Zone Output: $create_prisma_access_mobile_plugin_zone_message"
