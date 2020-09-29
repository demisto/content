. $PSScriptRoot\CommonServerPowerShell.ps1
#Blank Variable
$sc_name =@()
$sc_location=@()
$sc_bandwith=@()
$sc_peer_ip=@()
$sc_peer_subnet=@()

#Script Value
$Headers = "$rKey application"
$type = "config"
$encryption ="aes-128-cbc"
$hash="sha1"
$dhgroup="group2"
$lifetime="8"
$xpath_ike_crypto_profile = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Service_Conn_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles"
$xpath_ipsec_crypto_profile = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Service_Conn_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles"
$xpath_ike_gateway = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Service_Conn_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway"
$xpath_ipsec_tunnel = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Service_Conn_Template']/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec"
$xpath_ipsec_tunnel_plugin = "/config/devices/entry[@name='localhost.localdomain']/plugins/cloud_services/service-connection/onboarding"

#File Information
$path = $demisto.args().csv
$entries = $demisto.ExecuteCommand("ParseCSV", @{"entryID" = $path})
$service_connection = $entries[0]['Contents']

#For Each Loop
ForEach ($sc in $service_connection){
$sc_name = $($sc.Connection_Name)
$sc_location = $($sc.Location)
$sc_bandwith = $($sc.Bandwith)
$sc_peer_ip= $($sc.Peer_IP)
$sc_peer_subnet= $($sc.Subnet)

#Set Command
$strUri_set_ike_crypto ="<entry name='$sc_name-SC-IKE-Crypto'><hash><member>$hash</member></hash><dh-group><member>$dhgroup</member></dh-group><encryption><member>$encryption</member></encryption><lifetime><hours>$lifetime</hours></lifetime></entry>"
$strUri_set_ipsec_crypto_profile ="<entry name='$sc_name-SC-IPSEC-Crypto'><esp><authentication><member>sha1</member></authentication><encryption><member>aes-128-cbc</member></encryption></esp><lifetime><hours>1</hours></lifetime><dh-group>group20</dh-group></entry>"
$strUri_set_ike_gateway ="<entry name='$sc_name-SC-IKE-Gateway'><authentication><pre-shared-key><key>-AQ==HJYaKZavRmz7ptzotbyK/2XLY/k=E3JkmPayGoKB3hT1kuavlg==</key></pre-shared-key></authentication><protocol><ikev1><dpd><enable>yes</enable></dpd><ike-crypto-profile>$sc_name-SC-IKE-Crypto</ike-crypto-profile></ikev1><ikev2><dpd><enable>yes</enable></dpd><ike-crypto-profile>$sc_name-SC-IKE-Crypto</ike-crypto-profile></ikev2><version>ikev2-preferred</version></protocol><protocol-common><nat-traversal><enable>no</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation></protocol-common><local-address><interface>vlan</interface></local-address><peer-address><ip>$sc_peer_ip</ip></peer-address><peer-id><id>$sc_peer_ip</id><type>ipaddr</type></peer-id></entry>"
$strUri_set_ipsec_tunnel ="<entry name='$sc_name-SC-IPsec-Tunnel'><auto-key><ike-gateway><entry name='$sc_name-SC-IKE-Gateway'/></ike-gateway><ipsec-crypto-profile>$sc_name-SC-IPSEC-Crypto</ipsec-crypto-profile></auto-key><tunnel-monitor><enable>no</enable></tunnel-monitor><tunnel-interface>tunnel</tunnel-interface></entry>"
$strUri_set_ipsec_tunnel_plugin ="<entry name='$sc_name-SC'><protocol><bgp><enable>no</enable></bgp></protocol><subnets><member>$sc_peer_subnet</member></subnets><region>$sc_location</region><ipsec-tunnel>$sc_name-SC-IPsec-Tunnel</ipsec-tunnel><secondary-wan-enabled>no</secondary-wan-enabled></entry>"

$create_ike_crypto = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_ike_crypto
})
$ike_crypto_message = $create_ike_crypto[0]['Contents'] | Out-String
Write-Host "IKE Crypto for $rn_name $ike_crypto_message"

$create_ipsec_crypto = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_crypto_profile
    "httptype" = "POST"
    "element" = $strUri_set_ipsec_crypto_profile
})
$ipsec_crypto_message = $create_ipsec_crypto[0]['Contents'] | Out-String
Write-Host "IPSec Crypto for for $rn_name $ipsec_crypto_message"

$create_ike_gateway = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ike_gateway
    "httptype" = "POST"
    "element" = $strUri_set_ike_gateway
})
$ike_gateway_message = $create_ike_gateway[0]['Contents'] | Out-String
Write-Host "Ike Gateway for for $rn_name $ike_gateway_message"

$create_ipsec_tunnel = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel
    "httptype" = "POST"
    "element" = $strUri_set_ipsec_tunnel
})
$ipsec_tunnel_message = $create_ipsec_tunnel[0]['Contents'] | Out-String
Write-Host "IPsec Tunnel for for $rn_name $ipsec_tunnel_message"

$create_ipsec_plugin_tunnel = $demisto.ExecuteCommand("panorama-advanced-command", @{
    "action" = "set"
    "type" = $type
    "xpath" = $xpath_ipsec_tunnel_plugin
    "httptype" = "POST"
    "element" = $strUri_set_ipsec_tunnel_plugin
})
$ipsec_plugin_tunnel_message = $create_ipsec_plugin_tunnel[0]['Contents'] | Out-String
Write-Host "IPsec configuration in Prisma Access Plugin for for $rn_name $ipsec_plugin_tunnel_message"
}
