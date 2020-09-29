. $PSScriptRoot\CommonServerPowerShell.ps1
#Blank Variable

$xpath_template_sc = @()
$xpath_template_ipsec_sc = @()
$xpath_template_stack_sc = @()
$xpath_device_group_sc = @()
$xpath_plugin_sc = @()
$xpath_ike_crypto_profile = @()
$xpath_ipsec_crypto_profile = @()
$xpath_ike_gateway = @()
$xpath_ipsec_tunnel = @()
$rKey = @()
$url = @()
$sc_infra_subnet = @()

#Script Value
$Headers = "$rKey application"
$type = "config"
$sc_infra_subnet = $demisto.args().mobile_infra_ip_subnet
$xpath_template_sc = "/config/devices/entry[@name='localhost.localdomain']/template"
$xpath_template_ipsec_sc = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Service_Conn_Template']/config/devices/entry[@name='localhost.localdomain']"
$xpath_template_stack_sc = "/config/devices/entry[@name='localhost.localdomain']/template-stack"
$xpath_device_group_sc = "/config/devices/entry[@name='localhost.localdomain']/device-group"
$xpath_plugin_sc = "/config/devices/entry[@name='localhost.localdomain']/plugins/cloud_services"

#Ipsec XPATH
$xpath_ike_crypto_profile = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Service_Conn_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles"
$xpath_ipsec_crypto_profile = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Service_Conn_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles"
$xpath_ike_gateway = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Service_Conn_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway"
$xpath_ipsec_tunnel = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Service_Conn_Template']/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec"

#Set Command for Service Connection template creation

$strUri_set_template_sc = "<entry name='Service_Conn_Template'>
   <settings>
    <default-vsys>vsys1</default-vsys>
  </settings>
  <description>Service Connection Template (Use the Cloud Services plugin to edit)</description>
  <config>
    <devices>
      <entry name='localhost.localdomain'>
        <vsys>
          <entry name='vsys1'/>
        </vsys>
        <deviceconfig>
          <setting>
            <logging>
              <logging-service-forwarding>
                <logging-service-regions>americas</logging-service-regions>
                <enable>yes</enable>
              </logging-service-forwarding>
            </logging>
          </setting>
        </deviceconfig>
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
      </log-settings>
    </shared>
  </config>
</entry>"

#Create Ike Crypto Default Template

$strUri_set_template_ike_crypto_CloudGenix_sc =
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

$strUri_set_template_ike_crypto_Citrix_sc =
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

$strUri_set_template_ike_crypto_Riverbed_sc =
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

$strUri_set_template_ike_crypto_SilverPeak_sc =
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
$strUri_set_template_ike_crypto_CiscoISR_sc =
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
$strUri_set_template_ike_crypto_CiscoASA_sc =
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
$strUri_set_template_ike_crypto_Generic_sc =
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
$strUri_set_template_ipsec_crypto_CloudGenix_sc =
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
$strUri_set_template_ipsec_crypto_Citrix_sc =
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

$strUri_set_template_ipsec_crypto_Riverbed_sc =
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
$strUri_set_template_ipsec_crypto_SilverPeak_sc =
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
$strUri_set_template_ipsec_crypto_CiscoISR_sc =
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
$strUri_set_template_ipsec_crypto_CiscoASA_sc =
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
$strUri_set_template_ipsec_crypto_Generic_sc =
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
$strUri_set_template_ike_gateway_CloudGenix_sc =
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

$strUri_set_template_ike_gateway_Citrix_sc =
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
$strUri_set_template_ike_gateway_Riverbed_sc =
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

$strUri_set_template_ike_gateway_SilverPeak_sc =
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

$strUri_set_template_ike_gateway_CiscoISR_sc =
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

$strUri_set_template_ike_gateway_CiscoASA_sc =
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

$strUri_set_template_ike_gateway_Generic_sc =
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
$strUri_set_template_ipsec_tunnel_CloudGenix_sc =
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

$strUri_set_template_ipsec_tunnel_Citrix_sc =
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

$strUri_set_template_ipsec_tunnel_Riverbed_sc =
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

$strUri_set_template_ipsec_tunnel_SilverPeak_sc =
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

$strUri_set_template_ipsec_tunnel_CiscoISR_sc =
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
$strUri_set_template_ipsec_tunnel_CiscoASA_sc =
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

$strUri_set_template_ipsec_tunnel_Generic_sc =
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

 #Set Command for Service Connection template stack creation
$strUri_set_template_stack_sc =
"<entry name='Service_Conn_Template_Stack'>
 <templates>
    <member>Service_Conn_Template</member>
  </templates>
  <description>Service Connection Template Stack (Use the Cloud Services plugin to edit)</description>
  <settings>
    <default-vsys>vsys1</default-vsys>
  </settings>
</entry>"

#Set Command for Device Group Profile

$strUri_set_device_group_sc =
"<entry name='Service_Conn_Device_Group'>
 <description>Service Connection Device Group (Use the Cloud Services plugin to edit)</description>
  <devices/>
  <reference-templates>
    <member>Service_Conn_Template</member>
  </reference-templates>
</entry>"

#Set Command for Plugin Creation

$strUri_set_plugin_sc =
"<service-connection>
  <service-subnet>$sc_infra_subnet</service-subnet>
  <infra-bgp-as>65534</infra-bgp-as>
  <internal-dns-list/>
  <template-stack>Service_Conn_Template_Stack</template-stack>
  <device-group>Service_Conn_Device_Group</device-group>
</service-connection>
<routing-preference>
  <default/>
</routing-preference>
<pbf>
  <rules/>
</pbf>"


#Run Command

$create_template_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_sc
    "httptype" = "POST"
    "element" = $strUri_set_template_sc
})
$create_template_sc_message = $create_template_sc[0]['Contents'] | Out-String
Write-Host "Service Connection Template has been created successfully Output:$create_template_sc_message"

#CloudGenix Template Creation
$create_template_ike_crypto_CloudGenix_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_sc
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_CloudGenix_sc
})

$create_template_ipsec_crypto_CloudGenix_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_CloudGenix_sc
})

$create_template_ike_gateway_CloudGenix_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_CloudGenix_sc
})

$create_template_ipsec_tunnel_CloudGenix_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_CloudGenix_sc
})
$create_template_ike_crypto_CloudGenix_sc_message = $create_template_ike_crypto_CloudGenix_sc[0]['Contents'] | Out-String
$create_template_ipsec_crypto_CloudGenix_sc_message = $create_template_ipsec_crypto_CloudGenix_sc[0]['Contents'] | Out-String
$create_template_ike_gateway_CloudGenix_sc_message = $create_template_ike_gateway_CloudGenix_sc[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_CloudGenix_sc_message = $create_template_ipsec_tunnel_CloudGenix_sc[0]['Contents'] | Out-String
Write-Host "Remote Network CloudGenix Ike Crypto  Template has been created Output:$create_template_ike_crypto_CloudGenix_sc_message"
Write-Host "Remote Network CloudGenix Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_CloudGenix_sc_message"
Write-Host "Remote Network CloudGenix Ike Gateway  Template has been created Output:$create_template_ike_gateway_CloudGenix_sc_message"
Write-Host "Remote Network CloudGenix IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_CloudGenix_sc_message"

#Citrix Template Creation
$create_template_ike_crypto_Citrix_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_sc
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_Citrix_sc
})

$create_template_ipsec_crypto_Citrix_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_Citrix_sc
})

$create_template_ike_gateway_Citrix_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_Citrix_sc
})

$create_template_ipsec_tunnel_Citrix_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_Citrix_sc
})
$create_template_ike_crypto_Citrix_sc_message = $create_template_ike_crypto_Citrix_sc[0]['Contents'] | Out-String
$create_template_ipsec_crypto_Citrix_sc_message = $create_template_ipsec_crypto_Citrix_sc[0]['Contents'] | Out-String
$create_template_ike_gateway_Citrix_sc_message = $create_template_ike_gateway_Citrix_sc[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_Citrix_sc_message = $create_template_ipsec_tunnel_Citrix_sc[0]['Contents'] | Out-String
Write-Host "Remote Network Citrix Ike Crypto  Template has been created Output:$create_template_ike_crypto_Citrix_sc_message"
Write-Host "Remote Network Citrix Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_Citrix_sc_message"
Write-Host "Remote Network Citrix Ike Gateway  Template has been created Output:$create_template_ike_gateway_Citrix_sc_message"
Write-Host "Remote Network Citrix IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_Citrix_sc_message"

#Riverbed Template Creation
$create_template_ike_crypto_Riverbed_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_sc
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_Riverbed_sc
})

$create_template_ipsec_crypto_Riverbed_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_Riverbed_sc
})

$create_template_ike_gateway_Riverbed_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_Riverbed_sc
})

$create_template_ipsec_tunnel_Riverbed_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_Riverbed_sc
})
$create_template_ike_crypto_Riverbed_sc_message = $create_template_ike_crypto_Riverbed_sc[0]['Contents'] | Out-String
$create_template_ipsec_crypto_Riverbed_sc_message = $create_template_ipsec_crypto_Riverbed_sc[0]['Contents'] | Out-String
$create_template_ike_gateway_Riverbed_sc_message = $create_template_ike_gateway_Riverbed_sc[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_Riverbed_sc_message = $create_template_ipsec_tunnel_Riverbed_sc[0]['Contents'] | Out-String
Write-Host "Remote Network Riverbed Ike Crypto  Template has been created Output:$create_template_ike_crypto_Riverbed_sc_message"
Write-Host "Remote Network Riverbed Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_Riverbed_sc_message"
Write-Host "Remote Network Riverbed Ike Gateway  Template has been created Output:$create_template_ike_gateway_Riverbed_sc_message"
Write-Host "Remote Network Riverbed IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_Riverbed_sc_message"

#SilverPeak Template Creation
$create_template_ike_crypto_SilverPeak_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_sc
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_SilverPeak_sc
})

$create_template_ipsec_crypto_SilverPeak_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_SilverPeak_sc
})

$create_template_ike_gateway_SilverPeak_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_SilverPeak_sc
})

$create_template_ipsec_tunnel_SilverPeak_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_SilverPeak_sc
})
$create_template_ike_crypto_SilverPeak_sc_message = $create_template_ike_crypto_SilverPeak_sc[0]['Contents'] | Out-String
$create_template_ipsec_crypto_SilverPeak_sc_message = $create_template_ipsec_crypto_SilverPeak_sc[0]['Contents'] | Out-String
$create_template_ike_gateway_SilverPeak_sc_message = $create_template_ike_gateway_SilverPeak_sc[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_SilverPeak_sc_message = $create_template_ipsec_tunnel_SilverPeak_sc[0]['Contents'] | Out-String
Write-Host "Remote Network SilverPeak Ike Crypto  Template has been created Output:$create_template_ike_crypto_SilverPeak_sc_message"
Write-Host "Remote Network SilverPeak Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_SilverPeak_sc_message"
Write-Host "Remote Network SilverPeak Ike Gateway  Template has been created Output:$create_template_ike_gateway_SilverPeak_sc_message"
Write-Host "Remote Network SilverPeak IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_SilverPeak_sc_message"

#CiscoISR Template Creation
$create_template_ike_crypto_CiscoISR_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_sc
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_CiscoISR_sc
})

$create_template_ipsec_crypto_CiscoISR_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_CiscoISR_sc
})

$create_template_ike_gateway_CiscoISR_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_CiscoISR_sc
})

$create_template_ipsec_tunnel_CiscoISR_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_CiscoISR_sc
})
$create_template_ike_crypto_CiscoISR_sc_message = $create_template_ike_crypto_CiscoISR_sc[0]['Contents'] | Out-String
$create_template_ipsec_crypto_CiscoISR_sc_message = $create_template_ipsec_crypto_CiscoISR_sc[0]['Contents'] | Out-String
$create_template_ike_gateway_CiscoISR_sc_message = $create_template_ike_gateway_CiscoISR_sc[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_CiscoISR_sc_message = $create_template_ipsec_tunnel_CiscoISR_sc[0]['Contents'] | Out-String
Write-Host "Remote Network CiscoISR Ike Crypto  Template has been created Output:$create_template_ike_crypto_CiscoISR_sc_message"
Write-Host "Remote Network CiscoISR Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_CiscoISR_sc_message"
Write-Host "Remote Network CiscoISR Ike Gateway  Template has been created Output:$create_template_ike_gateway_CiscoISR_sc_message"
Write-Host "Remote Network CiscoISR IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_CiscoISR_sc_message"

#CiscoASA Template Creation
$create_template_ike_crypto_CiscoASA_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_sc
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_CiscoASA_sc
})

$create_template_ipsec_crypto_CiscoASA_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_CiscoASA_sc
})

$create_template_ike_gateway_CiscoASA_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_CiscoASA_sc
})

$create_template_ipsec_tunnel_CiscoASA_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_CiscoASA_sc
})
$create_template_ike_crypto_CiscoASA_sc_message = $create_template_ike_crypto_CiscoASA_sc[0]['Contents'] | Out-String
$create_template_ipsec_crypto_CiscoASA_sc_message = $create_template_ipsec_crypto_CiscoASA_sc[0]['Contents'] | Out-String
$create_template_ike_gateway_CiscoASA_sc_message = $create_template_ike_gateway_CiscoASA_sc[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_CiscoASA_sc_message = $create_template_ipsec_tunnel_CiscoASA_sc[0]['Contents'] | Out-String
Write-Host "Remote Network CiscoASA Ike Crypto  Template has been created Output:$create_template_ike_crypto_CiscoASA_sc_message"
Write-Host "Remote Network CiscoASA Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_CiscoASA_sc_message"
Write-Host "Remote Network CiscoASA Ike Gateway  Template has been created Output:$create_template_ike_gateway_CiscoASA_sc_message"
Write-Host "Remote Network CiscoASA IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_CiscoASA_sc_message"

#Generic Template Creation
$create_template_ike_crypto_Generic_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_ipsec_sc
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_crypto_Generic_sc
})

$create_template_ipsec_crypto_Generic_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_crypto_Generic_sc
})

$create_template_ike_gateway_Generic_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_template_ike_gateway_Generic_sc
})

$create_template_ipsec_tunnel_Generic_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_template_ipsec_tunnel_Generic_sc
})
$create_template_ike_crypto_Generic_sc_message = $create_template_ike_crypto_Generic_sc[0]['Contents'] | Out-String
$create_template_ipsec_crypto_Generic_sc_message = $create_template_ipsec_crypto_Generic_sc[0]['Contents'] | Out-String
$create_template_ike_gateway_Generic_sc_message = $create_template_ike_gateway_Generic_sc[0]['Contents'] | Out-String
$create_template_ipsec_tunnel_Generic_sc_message = $create_template_ipsec_tunnel_Generic_sc[0]['Contents'] | Out-String
Write-Host "Remote Network Generic Ike Crypto  Template has been created Output:$create_template_ike_crypto_Generic_sc_message"
Write-Host "Remote Network Generic Ipsec Crypto  Template has been created Output:$create_template_ipsec_crypto_Generic_sc_message"
Write-Host "Remote Network Generic Ike Gateway  Template has been created Output:$create_template_ike_gateway_Generic_sc_message"
Write-Host "Remote Network Generic IPsec Tunnel  Template has been created Output:$create_template_ipsec_tunnel_Generic_sc_message"

$create_template_stack_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_template_stack_sc
    "httptype" = "POST"
    "element" = $strUri_set_template_stack_sc
})
$create_template_stack_sc_message = $create_template_stack_sc[0]['Contents'] | Out-String
Write-Host "Service Connection Template Stack has been created successfully Output:$create_template_stack_sc_message"

$create_device_group_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_device_group_sc
    "httptype" = "POST"
    "element" = $strUri_set_device_group_sc
})
$create_device_group_sc_message = $create_device_group_sc[0]['Contents'] | Out-String
Write-Host "Service Connection Device Group has been create successfully Ouput:$create_device_group_sc_message"

$create_plugin_sc = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_plugin_sc
    "httptype" = "POST"
    "element" = $strUri_set_plugin_sc
})
$create_plugin_sc_message = $create_plugin_sc[0]['Contents'] | Out-String
Write-Host "Service Connection in Prisma Access with Infrastructure Subnet $sc_infra_subnet has been configured successfully Output:$create_plugin_sc_message"
