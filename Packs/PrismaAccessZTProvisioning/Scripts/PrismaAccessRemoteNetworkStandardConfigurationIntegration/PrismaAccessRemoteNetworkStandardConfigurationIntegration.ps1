. $PSScriptRoot\CommonServerPowerShell.ps1
 #Blank Variable

$xpath_template_rn = @()
$xpath_template_stack_rn = @()
$xpath_device_group_rn = @()
$xpath_pre_rule_rn = @()
$xpath_plugin_rn = @()
$create_template_rn = @()
$strUri_set_template_rn = @()
$create_template_stack_rn = @()
$strUri_set_template_stack_rn= @()
$create_device_group_rn = @()
$strUri_set_device_group_rn = @()
$create_pre_rule_rn = @()
$strUri_set_pre_rule_rn = @()
$create_plugin_rn = @()
$strUri_set_plugin_rn = @()
$rKey = @()
$url = @()

#Script Value
$Headers = "$rKey application"
$type = "config"
$xpath_template_rn = "/config/devices/entry[@name='localhost.localdomain']/template"
$xpath_template_ipsec_rn = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Remote_Network_Template']/config/devices/entry[@name='localhost.localdomain']"
$xpath_template_stack_rn = " /config/devices/entry[@name='localhost.localdomain']/template-stack"
$xpath_device_group_rn = "/config/devices/entry[@name='localhost.localdomain']/device-group"
$xpath_pre_rule_rn = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='Remote_Network_Device_Group']"
$xpath_plugin_rn = "/config/devices/entry[@name='localhost.localdomain']/plugins/cloud_services"

#Ipsec XPATH
$xpath_ike_crypto_profile = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Remote_Network_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles"
$xpath_ipsec_crypto_profile = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Remote_Network_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles"
$xpath_ike_gateway = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Remote_Network_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway"
$xpath_ipsec_tunnel = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Remote_Network_Template']/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec"

#Set Command for template creation

$strUri_set_template_rn =
"<entry name='Remote_Network_Template'>
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
               <entry name='RN-trust'>
                 <network>
                   <tap/>
                 </network>
               </entry>
               <entry name='RN-untrust'>
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

#Create Ike Crypto Default Template

$strUri_set_template_ike_crypto_CloudGenix_rn =
"<network>
           <ike>
             <crypto-profiles>
               <ike-crypto-profiles>
                 <entry name='CloudGenix-IKE-Crypto-Default'>
                   <hash>
                     <member>sha512</member>
                   </hash>
                   <dh-group>
                     <member>group5</member>
                   </dh-group>
                   <encryption>
                     <member>aes-256-cbc</member>
                   </encryption>
                   <lifetime>
                     <hours>8</hours>
                   </lifetime>
                 </entry>
                </ike-crypto-profiles>
             </crypto-profiles>
       </ike>
</network>"

$strUri_set_template_ike_crypto_Citrix_rn =
"<network>
           <ike>
             <crypto-profiles>
               <ike-crypto-profiles>
                 <entry name='Citrix-IKE-Crypto-Default'>
                   <hash>
                     <member>sha256</member>
                   </hash>
                   <dh-group>
                     <member>group20</member>
                   </dh-group>
                   <encryption>
                     <member>aes-256-cbc</member>
                   </encryption>
                   <lifetime>
                     <hours>8</hours>
                   </lifetime>
                 </entry>
                    </ike-crypto-profiles>
             </crypto-profiles>
       </ike>
</network>"

$strUri_set_template_ike_crypto_Riverbed_rn =
"<network>
           <ike>
             <crypto-profiles>
               <ike-crypto-profiles>
                 <entry name='Riverbed-IKE-Crypto-Default'>
                   <hash>
                     <member>sha512</member>
                   </hash>
                   <dh-group>
                     <member>group2</member>
                   </dh-group>
                   <encryption>
                     <member>aes-256-cbc</member>
                   </encryption>
                   <lifetime>
                     <hours>8</hours>
                   </lifetime>
                 </entry>
                      </ike-crypto-profiles>
             </crypto-profiles>
       </ike>
</network>"

$strUri_set_template_ike_crypto_SilverPeak_rn =
"<network>
           <ike>
             <crypto-profiles>
               <ike-crypto-profiles>
                <entry name='SilverPeak-IKE-Crypto-Default'>
                   <hash>
                     <member>sha512</member>
                   </hash>
                   <dh-group>
                     <member>group14</member>
                   </dh-group>
                   <encryption>
                     <member>aes-256-cbc</member>
                   </encryption>
                   <lifetime>
                     <hours>8</hours>
                   </lifetime>
                 </entry>
                      </ike-crypto-profiles>
             </crypto-profiles>
       </ike>
</network>"
$strUri_set_template_ike_crypto_CiscoISR_rn =
"<network>
           <ike>
             <crypto-profiles>
               <ike-crypto-profiles>
                <entry name='CiscoISR-IKE-Crypto-Default'>
                   <hash>
                     <member>sha512</member>
                     <member>sha384</member>
                     <member>sha256</member>
                     <member>sha1</member>
                   </hash>
                   <dh-group>
                     <member>group5</member>
                     <member>group2</member>
                   </dh-group>
                   <encryption>
                     <member>aes-256-cbc</member>
                     <member>aes-192-cbc</member>
                     <member>aes-128-cbc</member>
                   </encryption>
                   <lifetime>
                     <hours>8</hours>
                   </lifetime>
                 </entry>
                 </ike-crypto-profiles>
             </crypto-profiles>
       </ike>
</network>"
$strUri_set_template_ike_crypto_CiscoASA_rn =
"<network>
           <ike>
             <crypto-profiles>
               <ike-crypto-profiles>
                <entry name='CiscoASA-IKE-Crypto-Default'>
                   <hash>
                     <member>sha512</member>
                     <member>sha384</member>
                     <member>sha256</member>
                     <member>sha1</member>
                     <member>md5</member>
                   </hash>
                   <dh-group>
                     <member>group5</member>
                     <member>group2</member>
                     <member>group1</member>
                   </dh-group>
                   <encryption>
                     <member>aes-256-cbc</member>
                     <member>3des</member>
                     <member>des</member>
                   </encryption>
                   <lifetime>
                     <hours>8</hours>
                   </lifetime>
                 </entry>
                 </ike-crypto-profiles>
             </crypto-profiles>
       </ike>
</network>"
$strUri_set_template_ike_crypto_Generic_rn =
"<network>
           <ike>
             <crypto-profiles>
               <ike-crypto-profiles>
                 <entry name='Generic-IKE-Crypto-Default'>
                   <hash>
                     <member>sha512</member>
                     <member>sha384</member>
                     <member>sha256</member>
                     <member>sha1</member>
                     <member>md5</member>
                   </hash>
                   <dh-group>
                     <member>group20</member>
                     <member>group19</member>
                     <member>group14</member>
                     <member>group5</member>
                     <member>group2</member>
                     <member>group1</member>
                   </dh-group>
                   <encryption>
                     <member>aes-256-cbc</member>
                     <member>aes-192-cbc</member>
                     <member>aes-128-cbc</member>
                     <member>3des</member>
                     <member>des</member>
                   </encryption>
                   <lifetime>
                     <hours>8</hours>
                   </lifetime>
                 </entry>
               </ike-crypto-profiles>
             </crypto-profiles>
           </ike>
         </network>"

#Set Command for Ipsec Crypto
$strUri_set_template_ipsec_crypto_CloudGenix_rn =
"<entry name='CloudGenix-IPSec-Crypto-Default'>
                   <esp>
                     <authentication>
                       <member>sha512</member>
                     </authentication>
                     <encryption>
                       <member>aes-256-cbc</member>
                     </encryption>
                   </esp>
                   <lifetime>
                     <hours>1</hours>
                   </lifetime>
                   <dh-group>group20</dh-group>
                 </entry>"
$strUri_set_template_ipsec_crypto_Citrix_rn =
"<entry name='Citrix-IPSec-Crypto-Default'>
                   <esp>
                     <authentication>
                       <member>sha256</member>
                     </authentication>
                     <encryption>
                       <member>aes-256-cbc</member>
                     </encryption>
                   </esp>
                   <lifetime>
                     <hours>1</hours>
                   </lifetime>
                   <dh-group>group2</dh-group>
                 </entry>"

$strUri_set_template_ipsec_crypto_Riverbed_rn =
"<entry name='Riverbed-IPSec-Crypto-Default'>
                   <esp>
                     <authentication>
                       <member>sha512</member>
                     </authentication>
                     <encryption>
                       <member>aes-256-cbc</member>
                     </encryption>
                   </esp>
                   <lifetime>
                     <hours>1</hours>
                   </lifetime>
                   <dh-group>group2</dh-group>
                 </entry>"
$strUri_set_template_ipsec_crypto_SilverPeak_rn =
"<entry name='SilverPeak-IPSec-Crypto-Default'>
                   <esp>
                     <authentication>
                       <member>sha512</member>
                     </authentication>
                     <encryption>
                       <member>aes-256-cbc</member>
                     </encryption>
                   </esp>
                   <lifetime>
                     <hours>1</hours>
                   </lifetime>
                   <dh-group>group14</dh-group>
                 </entry>"
$strUri_set_template_ipsec_crypto_CiscoISR_rn =
"<entry name='CiscoISR-IPSec-Crypto-Default'>
                   <esp>
                     <authentication>
                       <member>sha1</member>
                     </authentication>
                     <encryption>
                       <member>aes-128-cbc</member>
                     </encryption>
                   </esp>
                   <lifetime>
                     <hours>1</hours>
                   </lifetime>
                   <dh-group>group5</dh-group>
                 </entry>"
$strUri_set_template_ipsec_crypto_CiscoASA_rn =
"<entry name='CiscoASA-IPSec-Crypto-Default'>
                   <esp>
                     <authentication>
                       <member>sha512</member>
                       <member>sha384</member>
                       <member>sha256</member>
                       <member>sha1</member>
                       <member>md5</member>
                     </authentication>
                     <encryption>
                       <member>aes-256-gcm</member>
                       <member>aes-128-gcm</member>
                       <member>aes-256-cbc</member>
                       <member>aes-192-cbc</member>
                       <member>3des</member>
                       <member>des</member>
                     </encryption>
                   </esp>
                   <lifetime>
                     <hours>1</hours>
                   </lifetime>
                   <dh-group>group2</dh-group>
                 </entry>"
$strUri_set_template_ipsec_crypto_Generic_rn =
"<entry name='Generic-IPSec-Crypto-Default'>
                   <esp>
                     <authentication>
                       <member>sha512</member>
                       <member>sha384</member>
                       <member>sha256</member>
                       <member>sha1</member>
                       <member>md5</member>
                     </authentication>
                     <encryption>
                       <member>aes-256-gcm</member>
                       <member>aes-128-gcm</member>
                       <member>aes-256-cbc</member>
                       <member>aes-192-cbc</member>
                       <member>aes-128-cbc</member>
                       <member>3des</member>
                       <member>des</member>
                     </encryption>
                   </esp>
                   <lifetime>
                     <hours>1</hours>
                   </lifetime>
                   <dh-group>group2</dh-group>
                 </entry>"

#Set Command for Ike Gateway
$strUri_set_template_ike_gateway_CloudGenix_rn =
"<entry name='CloudGenix-IKE-Gateway-Default'>
                 <authentication>
                   <pre-shared-key>
                     <key>-AQ==vhFqkPiEJgbUtLco1BqESFMKU+M=vVDXkqplwjVl4eDbW0eGYQ==</key>
                   </pre-shared-key>
                 </authentication>
                 <protocol>
                   <ikev1>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                     <ike-crypto-profile>CloudGenix-IKE-Crypto-Default</ike-crypto-profile>
                     <exchange-mode>aggressive</exchange-mode>
                   </ikev1>
                   <ikev2>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                   </ikev2>
                 </protocol>
                 <protocol-common>
                   <nat-traversal>
                     <enable>yes</enable>
                   </nat-traversal>
                   <fragmentation>
                     <enable>no</enable>
                   </fragmentation>
                   <passive-mode>yes</passive-mode>
                 </protocol-common>
                 <local-address>
                   <interface>vlan</interface>
                 </local-address>
                 <peer-address>
                   <dynamic/>
                 </peer-address>
               </entry>"

$strUri_set_template_ike_gateway_Citrix_rn =
"<entry name='Citrix-IKE-Gateway-Default'>
                 <authentication>
                   <pre-shared-key>
                     <key>-AQ==vhFqkPiEJgbUtLco1BqESFMKU+M=vVDXkqplwjVl4eDbW0eGYQ==</key>
                   </pre-shared-key>
                 </authentication>
                 <protocol>
                   <ikev1>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                     <ike-crypto-profile>Citrix-IKE-Crypto-Default</ike-crypto-profile>
                     <exchange-mode>aggressive</exchange-mode>
                   </ikev1>
                   <ikev2>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                   </ikev2>
                 </protocol>
                 <protocol-common>
                   <nat-traversal>
                     <enable>yes</enable>
                   </nat-traversal>
                   <fragmentation>
                     <enable>no</enable>
                   </fragmentation>
                   <passive-mode>yes</passive-mode>
                 </protocol-common>
                 <local-address>
                   <interface>vlan</interface>
                 </local-address>
                 <peer-address>
                   <dynamic/>
                 </peer-address>
               </entry>"
$strUri_set_template_ike_gateway_Riverbed_rn =
"<entry name='Riverbed-IKE-Gateway-Default'>
                 <authentication>
                   <pre-shared-key>
                     <key>-AQ==vhFqkPiEJgbUtLco1BqESFMKU+M=vVDXkqplwjVl4eDbW0eGYQ==</key>
                   </pre-shared-key>
                 </authentication>
                 <protocol>
                   <ikev1>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                     <ike-crypto-profile>Riverbed-IKE-Crypto-Default</ike-crypto-profile>
                     <exchange-mode>aggressive</exchange-mode>
                   </ikev1>
                   <ikev2>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                   </ikev2>
                 </protocol>
                 <protocol-common>
                   <nat-traversal>
                     <enable>yes</enable>
                   </nat-traversal>
                   <fragmentation>
                     <enable>no</enable>
                   </fragmentation>
                   <passive-mode>yes</passive-mode>
                 </protocol-common>
                 <local-address>
                   <interface>vlan</interface>
                 </local-address>
                 <peer-address>
                   <dynamic/>
                 </peer-address>
               </entry>"

$strUri_set_template_ike_gateway_SilverPeak_rn =
"<entry name='SilverPeak-IKE-Gateway-Default'>
                 <authentication>
                   <pre-shared-key>
                     <key>-AQ==vhFqkPiEJgbUtLco1BqESFMKU+M=vVDXkqplwjVl4eDbW0eGYQ==</key>
                   </pre-shared-key>
                 </authentication>
                 <protocol>
                   <ikev1>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                     <ike-crypto-profile>SilverPeak-IKE-Crypto-Default</ike-crypto-profile>
                     <exchange-mode>aggressive</exchange-mode>
                   </ikev1>
                   <ikev2>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                   </ikev2>
                 </protocol>
                 <protocol-common>
                   <nat-traversal>
                     <enable>yes</enable>
                   </nat-traversal>
                   <fragmentation>
                     <enable>no</enable>
                   </fragmentation>
                   <passive-mode>yes</passive-mode>
                 </protocol-common>
                 <local-address>
                   <interface>vlan</interface>
                 </local-address>
                 <peer-address>
                   <dynamic/>
                 </peer-address>
               </entry>"

$strUri_set_template_ike_gateway_CiscoISR_rn =
"<entry name='CiscoISR-IKE-Gateway-Default'>
                 <authentication>
                   <pre-shared-key>
                     <key>-AQ==vhFqkPiEJgbUtLco1BqESFMKU+M=vVDXkqplwjVl4eDbW0eGYQ==</key>
                   </pre-shared-key>
                 </authentication>
                 <protocol>
                   <ikev1>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                     <ike-crypto-profile>CiscoISR-IKE-Crypto-Default</ike-crypto-profile>
                   </ikev1>
                   <ikev2>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                     <ike-crypto-profile>CiscoISR-IKE-Crypto-Default</ike-crypto-profile>
                   </ikev2>
                   <version>ikev2</version>
                 </protocol>
                 <protocol-common>
                   <nat-traversal>
                     <enable>yes</enable>
                   </nat-traversal>
                   <fragmentation>
                     <enable>no</enable>
                   </fragmentation>
                   <passive-mode>no</passive-mode>
                 </protocol-common>
                 <local-address>
                   <interface>vlan</interface>
                 </local-address>
                 <peer-address>
                   <dynamic/>
                 </peer-address>
               </entry>"

$strUri_set_template_ike_gateway_CiscoASA_rn =
"<entry name='CiscoASA-IKE-Gateway-Default'>
                 <authentication>
                   <pre-shared-key>
                     <key>-AQ==vhFqkPiEJgbUtLco1BqESFMKU+M=vVDXkqplwjVl4eDbW0eGYQ==</key>
                   </pre-shared-key>
                 </authentication>
                 <protocol>
                   <ikev1>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                     <ike-crypto-profile>CiscoASA-IKE-Crypto-Default</ike-crypto-profile>
                   </ikev1>
                   <ikev2>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                     <ike-crypto-profile>CiscoASA-IKE-Crypto-Default</ike-crypto-profile>
                   </ikev2>
                   <version>ikev1</version>
                 </protocol>
                 <protocol-common>
                   <nat-traversal>
                     <enable>yes</enable>
                   </nat-traversal>
                   <fragmentation>
                     <enable>no</enable>
                   </fragmentation>
                   <passive-mode>yes</passive-mode>
                 </protocol-common>
                 <local-address>
                   <interface>vlan</interface>
                 </local-address>
                 <peer-address>
                   <dynamic/>
                 </peer-address>
               </entry>"

$strUri_set_template_ike_gateway_Generic_rn =
"<entry name='Generic-IKE-Gateway-Default'>
                 <authentication>
                   <pre-shared-key>
                     <key>-AQ==vhFqkPiEJgbUtLco1BqESFMKU+M=vVDXkqplwjVl4eDbW0eGYQ==</key>
                   </pre-shared-key>
                 </authentication>
                 <protocol>
                   <ikev1>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                     <ike-crypto-profile>Generic-IKE-Crypto-Default</ike-crypto-profile>
                     <exchange-mode>aggressive</exchange-mode>
                   </ikev1>
                   <ikev2>
                     <dpd>
                       <enable>yes</enable>
                     </dpd>
                     <ike-crypto-profile>Generic-IKE-Crypto-Default</ike-crypto-profile>
                   </ikev2>
                   <version>ikev1</version>
                 </protocol>
                 <protocol-common>
                   <nat-traversal>
                     <enable>yes</enable>
                   </nat-traversal>
                   <fragmentation>
                     <enable>no</enable>
                   </fragmentation>
                   <passive-mode>yes</passive-mode>
                 </protocol-common>
                 <local-address>
                   <interface>vlan</interface>
                 </local-address>
                 <peer-address>
                   <dynamic/>
                 </peer-address>
               </entry>"

#Set Command for Ipsec Tunnel Template
$strUri_set_template_ipsec_tunnel_CloudGenix_rn =
"<entry name='CloudGenix-IPSec-Tunnel-Default'>
                 <auto-key>
                   <ike-gateway>
                     <entry name='CloudGenix-IKE-Gateway-Default'/>
                   </ike-gateway>
                   <ipsec-crypto-profile>CloudGenix-IPSec-Crypto-Default</ipsec-crypto-profile>
                 </auto-key>
                 <tunnel-monitor>
                   <enable>no</enable>
                 </tunnel-monitor>
                 <tunnel-interface>tunnel</tunnel-interface>
               </entry>"

$strUri_set_template_ipsec_tunnel_Citrix_rn =
"<entry name='Citrix-IPSec-Tunnel-Default'>
                 <auto-key>
                   <ike-gateway>
                     <entry name='Citrix-IKE-Gateway-Default'/>
                   </ike-gateway>
                   <ipsec-crypto-profile>Citrix-IPSec-Crypto-Default</ipsec-crypto-profile>
                 </auto-key>
                 <tunnel-monitor>
                   <enable>no</enable>
                 </tunnel-monitor>
                 <tunnel-interface>tunnel</tunnel-interface>
               </entry>"

$strUri_set_template_ipsec_tunnel_Riverbed_rn =
"<entry name='Riverbed-IPSec-Tunnel-Default'>
                 <auto-key>
                   <ike-gateway>
                     <entry name='Riverbed-IKE-Gateway-Default'/>
                   </ike-gateway>
                   <ipsec-crypto-profile>Riverbed-IPSec-Crypto-Default</ipsec-crypto-profile>
                 </auto-key>
                 <tunnel-monitor>
                   <enable>no</enable>
                 </tunnel-monitor>
                 <tunnel-interface>tunnel</tunnel-interface>
               </entry>"

$strUri_set_template_ipsec_tunnel_SilverPeak_rn =
"<entry name='SilverPeak-IPSec-Tunnel-Default'>
                 <auto-key>
                   <ike-gateway>
                     <entry name='SilverPeak-IKE-Gateway-Default'/>
                   </ike-gateway>
                   <ipsec-crypto-profile>SilverPeak-IPSec-Crypto-Default</ipsec-crypto-profile>
                 </auto-key>
                 <tunnel-monitor>
                   <enable>no</enable>
                 </tunnel-monitor>
                 <tunnel-interface>tunnel</tunnel-interface>
               </entry>"

$strUri_set_template_ipsec_tunnel_CiscoISR_rn =
"<entry name='CiscoISR-IPSec-Tunnel-Default'>
                 <auto-key>
                   <ike-gateway>
                     <entry name='CiscoISR-IKE-Gateway-Default'/>
                   </ike-gateway>
                   <ipsec-crypto-profile>CiscoISR-IPSec-Crypto-Default</ipsec-crypto-profile>
                   <proxy-id>
                     <entry name='ProxyID'>
                       <protocol>
                         <any/>
                       </protocol>
                     </entry>
                   </proxy-id>
                 </auto-key>
                 <tunnel-monitor>
                   <enable>no</enable>
                 </tunnel-monitor>
                 <tunnel-interface>tunnel</tunnel-interface>
               </entry>"
$strUri_set_template_ipsec_tunnel_CiscoASA_rn =
"<entry name='CiscoASA-IPSec-Tunnel-Default'>
                 <auto-key>
                   <ike-gateway>
                     <entry name='CiscoASA-IKE-Gateway-Default'/>
                   </ike-gateway>
                   <ipsec-crypto-profile>CiscoASA-IPSec-Crypto-Default</ipsec-crypto-profile>
                 </auto-key>
                 <tunnel-monitor>
                   <enable>no</enable>
                 </tunnel-monitor>
                 <tunnel-interface>tunnel</tunnel-interface>
               </entry>"

$strUri_set_template_ipsec_tunnel_Generic_rn =
"<entry name='Generic-IPSec-Tunnel-Default'>
                 <auto-key>
                   <ike-gateway>
                     <entry name='Generic-IKE-Gateway-Default'/>
                   </ike-gateway>
                   <ipsec-crypto-profile>Generic-IPSec-Crypto-Default</ipsec-crypto-profile>
                 </auto-key>
                 <tunnel-monitor>
                   <enable>no</enable>
                 </tunnel-monitor>
                 <tunnel-interface>tunnel</tunnel-interface>
               </entry>"

#Set Command for template stack creation
$strUri_set_template_stack_rn = "<entry name='Remote_Network_Template_Stack'>
 <templates>
     <member>Remote_Network_Template</member>
   </templates>
   <description> Template Stack (Use the Cloud Services plugin to edit)</description>
   <settings>
     <default-vsys>vsys1</default-vsys>
   </settings>
</entry>"

#Set Command for Device Group Profile

$strUri_set_device_group_rn = "<entry name='Remote_Network_Device_Group'>
  <description> Device Group (Use the Cloud Services plugin to edit)</description>
  <devices/>
  <log-settings>
    <profiles>
      <entry name='Remote-Network-Log-Profile'>
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
    <member>Remote_Network_Template</member>
  </reference-templates>
</entry>"


#Set Command for Pre-Rule Creation
$strUri_set_pre_rule_rn =
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
          <member>RN-untrust</member>
        </to>
        <from>
          <member>RN-trust</member>
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
        <log-setting>Remote-Network-Log-Profile</log-setting>
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
          <member>RN-trust</member>
        </to>
        <from>
          <member>RN-trust</member>
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
        <log-setting>Remote-Network-Log-Profile</log-setting>
      </entry>
    </rules>
  </security>
</pre-rulebase>"


#Set Command for Plugin Creation

$strUri_set_plugin_rn =
"<remote-networks>
  <overlapped-subnets>no</overlapped-subnets>
  <template-stack>Remote_Network_Template_Stack</template-stack>
  <device-group>Remote_Network_Device_Group</device-group>
  <trusted-zones>
    <member>RN-trust</member>
  </trusted-zones>
</remote-networks>"


#Run Command
$create_template_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_rn
    "httptype" = "POST"
    "element" = $strUri_set_template_rn
})
$create_template_rn_message = $create_template_rn[0]['Contents'] | Out-String
Write-Host "Remote Network Template has been created successfully Output : $create_template_rn_message"
Write-Host "Remote Network Zone RN-Untrust and RN-Trust has been created Output : $create_template_rn_message"
Write-Host "Remote Network Zone RN-Trust has been move to Prisma Access Trusted Zone Output : $create_template_rn_message"

#CloudGenix Template Creation
$create_template_ike_crypto_CloudGenix_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_rn
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_CloudGenix_rn
})

$create_template_ipsec_crypto_CloudGenix_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_CloudGenix_rn
})

$create_template_ike_gateway_CloudGenix_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_CloudGenix_rn
})

$create_template_ipsec_tunnel_CloudGenix_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_CloudGenix_rn
})
$create_template_ike_crypto_CloudGenix_rn_message = $create_template_ike_crypto_CloudGenix_rn[0]['Contents'] | Out-String
$create_template_ipsec_crypto_CloudGenix_rn_message = $create_template_ipsec_crypto_CloudGenix_rn[0]['Contents'] | Out-String
$create_template_ike_gateway_CloudGenix_rn_message = $create_template_ike_gateway_CloudGenix_rn[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_CloudGenix_rn_message = $create_template_ipsec_tunnel_CloudGenix_rn[0]['Contents'] | Out-String
Write-Host "Remote Network CloudGenix Ike Crypto  Template has been created Output:$create_template_ike_crypto_CloudGenix_rn_message"
Write-Host "Remote Network CloudGenix Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_CloudGenix_rn_message"
Write-Host "Remote Network CloudGenix Ike Gateway  Template has been created Output:$create_template_ike_gateway_CloudGenix_rn_message"
Write-Host "Remote Network CloudGenix IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_CloudGenix_rn_message"

#Citrix Template Creation
$create_template_ike_crypto_Citrix_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_rn
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_Citrix_rn
})

$create_template_ipsec_crypto_Citrix_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_Citrix_rn
})

$create_template_ike_gateway_Citrix_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_Citrix_rn
})

$create_template_ipsec_tunnel_Citrix_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_Citrix_rn
})
$create_template_ike_crypto_Citrix_rn_message = $create_template_ike_crypto_Citrix_rn[0]['Contents'] | Out-String
$create_template_ipsec_crypto_Citrix_rn_message = $create_template_ipsec_crypto_Citrix_rn[0]['Contents'] | Out-String
$create_template_ike_gateway_Citrix_rn_message = $create_template_ike_gateway_Citrix_rn[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_Citrix_rn_message = $create_template_ipsec_tunnel_Citrix_rn[0]['Contents'] | Out-String
Write-Host "Remote Network Citrix Ike Crypto  Template has been created Output:$create_template_ike_crypto_Citrix_rn_message"
Write-Host "Remote Network Citrix Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_Citrix_rn_message"
Write-Host "Remote Network Citrix Ike Gateway  Template has been created Output:$create_template_ike_gateway_Citrix_rn_message"
Write-Host "Remote Network Citrix IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_Citrix_rn_message"

#Riverbed Template Creation
$create_template_ike_crypto_Riverbed_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_rn
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_Riverbed_rn
})

$create_template_ipsec_crypto_Riverbed_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_Riverbed_rn
})

$create_template_ike_gateway_Riverbed_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_Riverbed_rn
})

$create_template_ipsec_tunnel_Riverbed_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_Riverbed_rn
})
$create_template_ike_crypto_Riverbed_rn_message = $create_template_ike_crypto_Riverbed_rn[0]['Contents'] | Out-String
$create_template_ipsec_crypto_Riverbed_rn_message = $create_template_ipsec_crypto_Riverbed_rn[0]['Contents'] | Out-String
$create_template_ike_gateway_Riverbed_rn_message = $create_template_ike_gateway_Riverbed_rn[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_Riverbed_rn_message = $create_template_ipsec_tunnel_Riverbed_rn[0]['Contents'] | Out-String
Write-Host "Remote Network Riverbed Ike Crypto  Template has been created Output:$create_template_ike_crypto_Riverbed_rn_message"
Write-Host "Remote Network Riverbed Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_Riverbed_rn_message"
Write-Host "Remote Network Riverbed Ike Gateway  Template has been created Output:$create_template_ike_gateway_Riverbed_rn_message"
Write-Host "Remote Network Riverbed IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_Riverbed_rn_message"

#SilverPeak Template Creation
$create_template_ike_crypto_SilverPeak_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_rn
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_SilverPeak_rn
})

$create_template_ipsec_crypto_SilverPeak_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_SilverPeak_rn
})

$create_template_ike_gateway_SilverPeak_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_SilverPeak_rn
})

$create_template_ipsec_tunnel_SilverPeak_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_SilverPeak_rn
})
$create_template_ike_crypto_SilverPeak_rn_message = $create_template_ike_crypto_SilverPeak_rn[0]['Contents'] | Out-String
$create_template_ipsec_crypto_SilverPeak_rn_message = $create_template_ipsec_crypto_SilverPeak_rn[0]['Contents'] | Out-String
$create_template_ike_gateway_SilverPeak_rn_message = $create_template_ike_gateway_SilverPeak_rn[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_SilverPeak_rn_message = $create_template_ipsec_tunnel_SilverPeak_rn[0]['Contents'] | Out-String
Write-Host "Remote Network SilverPeak Ike Crypto  Template has been created Output:$create_template_ike_crypto_SilverPeak_rn_message"
Write-Host "Remote Network SilverPeak Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_SilverPeak_rn_message"
Write-Host "Remote Network SilverPeak Ike Gateway  Template has been created Output:$create_template_ike_gateway_SilverPeak_rn_message"
Write-Host "Remote Network SilverPeak IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_SilverPeak_rn_message"

#CiscoISR Template Creation
$create_template_ike_crypto_CiscoISR_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_rn
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_CiscoISR_rn
})

$create_template_ipsec_crypto_CiscoISR_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_CiscoISR_rn
})

$create_template_ike_gateway_CiscoISR_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_CiscoISR_rn
})

$create_template_ipsec_tunnel_CiscoISR_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_CiscoISR_rn
})
$create_template_ike_crypto_CiscoISR_rn_message = $create_template_ike_crypto_CiscoISR_rn[0]['Contents'] | Out-String
$create_template_ipsec_crypto_CiscoISR_rn_message = $create_template_ipsec_crypto_CiscoISR_rn[0]['Contents'] | Out-String
$create_template_ike_gateway_CiscoISR_rn_message = $create_template_ike_gateway_CiscoISR_rn[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_CiscoISR_rn_message = $create_template_ipsec_tunnel_CiscoISR_rn[0]['Contents'] | Out-String
Write-Host "Remote Network CiscoISR Ike Crypto  Template has been created Output:$create_template_ike_crypto_CiscoISR_rn_message"
Write-Host "Remote Network CiscoISR Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_CiscoISR_rn_message"
Write-Host "Remote Network CiscoISR Ike Gateway  Template has been created Output:$create_template_ike_gateway_CiscoISR_rn_message"
Write-Host "Remote Network CiscoISR IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_CiscoISR_rn_message"

#CiscoASA Template Creation
$create_template_ike_crypto_CiscoASA_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_rn
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_CiscoASA_rn
})

$create_template_ipsec_crypto_CiscoASA_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_CiscoASA_rn
})

$create_template_ike_gateway_CiscoASA_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_CiscoASA_rn
})

$create_template_ipsec_tunnel_CiscoASA_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_CiscoASA_rn
})
$create_template_ike_crypto_CiscoASA_rn_message = $create_template_ike_crypto_CiscoASA_rn[0]['Contents'] | Out-String
$create_template_ipsec_crypto_CiscoASA_rn_message = $create_template_ipsec_crypto_CiscoASA_rn[0]['Contents'] | Out-String
$create_template_ike_gateway_CiscoASA_rn_message = $create_template_ike_gateway_CiscoASA_rn[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_CiscoASA_rn_message = $create_template_ipsec_tunnel_CiscoASA_rn[0]['Contents'] | Out-String
Write-Host "Remote Network CiscoASA Ike Crypto  Template has been created Output:$create_template_ike_crypto_CiscoASA_rn_message"
Write-Host "Remote Network CiscoASA Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_CiscoASA_rn_message"
Write-Host "Remote Network CiscoASA Ike Gateway  Template has been created Output:$create_template_ike_gateway_CiscoASA_rn_message"
Write-Host "Remote Network CiscoASA IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_CiscoASA_rn_message"

#Generic Template Creation
$create_template_ike_crypto_Generic_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_rn
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_Generic_rn
})

$create_template_ipsec_crypto_Generic_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_Generic_rn
})

$create_template_ike_gateway_Generic_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_Generic_rn
})

$create_template_ipsec_tunnel_Generic_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_Generic_rn
})
$create_template_ike_crypto_Generic_rn_message = $create_template_ike_crypto_Generic_rn[0]['Contents'] | Out-String
$create_template_ipsec_crypto_Generic_rn_message = $create_template_ipsec_crypto_Generic_rn[0]['Contents'] | Out-String
$create_template_ike_gateway_Generic_rn_message = $create_template_ike_gateway_Generic_rn[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_Generic_rn_message = $create_template_ipsec_tunnel_Generic_rn[0]['Contents'] | Out-String
Write-Host "Remote Network Generic Ike Crypto  Template has been created Output:$create_template_ike_crypto_Generic_rn_message"
Write-Host "Remote Network Generic Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_Generic_rn_message"
Write-Host "Remote Network Generic Ike Gateway  Template has been created Output:$create_template_ike_gateway_Generic_rn_message"
Write-Host "Remote Network Generic IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_Generic_rn_message"

$create_template_stack_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_stack_rn
    "httptype" = "POST"
    "element" = $strUri_set_template_stack_rn
})
$create_template_stack_rn_message = $create_template_stack_rn[0]['Contents'] | Out-String
Write-Host "Remote Network Template Stack has been created successfully Output:$create_template_stack_rn_message"

$create_device_group_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_device_group_rn
    "httptype" = "POST"
    "element" = $strUri_set_device_group_rn
})
$create_device_group_rn_message = $create_device_group_rn[0]['Contents'] | Out-String
Write-Host "Remote Network Device Group has been create successfully Ouput:$create_device_group_rn_message"
Write-Host "Remote Network Default Security Profile has been created successfully Output:$create_device_group_rn_message"
Write-Host "Remote Network Default Cortex Data Lake Log Forwarding Profile has been created successfully Output:$create_device_group_rn_message"

$create_pre_rule_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_pre_rule_rn
    "httptype" = "POST"
    "element" = $strUri_set_pre_rule_rn
})
$create_pre_rule_rn_message = $create_pre_rule_rn[0]['Contents'] | Out-String
Write-Host "Remote Network Pre-Rule has been created successfully Ouput:$create_pre_rule_rn_message"

$create_plugin_rn = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_plugin_rn
    "httptype" = "POST"
    "element" = $strUri_set_plugin_rn
})
$create_plugin_rn_message = $create_plugin_rn[0]['Contents'] | Out-String
Write-Host "Remote Network in Prisma Access has been configured successfully Output:$create_plugin_rn_message"

