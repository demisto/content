. $PSScriptRoot\CommonServerPowerShell.ps1

#Blank Variable
$rn_name =@()
$rn_location=@()
$rn_bandwith=@()
$rn_peer_ip=@()
$rn_peer_subnet=@()
$csvEntry = @()

#Script Value
$Headers = "$rKey application"
$type = "config"
#$encryption ="aes-128-cbc"
$encryption=$demisto.args().Encryption
#$hash="sha1"
$hash=$demisto.args().Hash
#$dhgroup="group2"
$dhgroup=$demisto.args().DHGroup
#$lifetime="8"
$lifetime=$demisto.args().Lifetime

#Set XPATH and Element Variables
$xpath_ike_crypto_profile = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Remote_Network_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles"
$xpath_ipsec_crypto_profile = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Remote_Network_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles"
$xpath_ike_gateway = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Remote_Network_Template']/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway"
$xpath_ipsec_tunnel = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Remote_Network_Template']/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec"
$xpath_ipsec_tunnel_plugin = "/config/devices/entry[@name='localhost.localdomain']/plugins/cloud_services/remote-networks/onboarding"
#Element Variables Command
$strUri_set_ike_crypto ="<entry name='$rn_name-RN-IKE-Crypto'><hash><member>$hash</member></hash><dh-group><member>$dhgroup</member></dh-group><encryption><member>$encryption</member></encryption><lifetime><hours>$lifetime</hours></lifetime></entry>"
$strUri_set_ipsec_crypto_profile ="<entry name='$rn_name-RN-IPSEC-Crypto'><esp><authentication><member>sha1</member></authentication><encryption><member>aes-128-cbc</member></encryption></esp><lifetime><hours>1</hours></lifetime><dh-group>group20</dh-group></entry>"
$strUri_set_ike_gateway ="<entry name='$rn_name-RN-IKE-Gateway'><authentication><pre-shared-key><key>-AQ==HJYaKZavRmz7ptzotbyK/2XLY/k=E3JkmPayGoKB3hT1kuavlg==</key></pre-shared-key></authentication><protocol><ikev1><dpd><enable>yes</enable></dpd><ike-crypto-profile>$rn_name-RN-IKE-Crypto</ike-crypto-profile></ikev1><ikev2><dpd><enable>yes</enable></dpd><ike-crypto-profile>$rn_name-RN-IKE-Crypto</ike-crypto-profile></ikev2><version>ikev2-preferred</version></protocol><protocol-common><nat-traversal><enable>no</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation></protocol-common><local-address><interface>vlan</interface></local-address><peer-address><ip>$rn_peer_ip</ip></peer-address><peer-id><id>$rn_peer_ip</id><type>ipaddr</type></peer-id></entry>"
$strUri_set_ipsec_tunnel ="<entry name='$rn_name-RN-IPsec-Tunnel'><auto-key><ike-gateway><entry name='$rn_name-RN-IKE-Gateway'/></ike-gateway><ipsec-crypto-profile>$rn_name-RN-IPSEC-Crypto</ipsec-crypto-profile></auto-key><tunnel-monitor><enable>no</enable></tunnel-monitor><tunnel-interface>tunnel</tunnel-interface></entry>"
$strUri_set_ipsec_tunnel_plugin ="<entry name='$rn_name-RN'><protocol><bgp><enable>no</enable></bgp></protocol><subnets><member>$rn_peer_subnet</member></subnets><region>$rn_location</region><license-type>FWAAS-$rn_bandwith`Mbps</license-type><ipsec-tunnel>$rn_name-RN-IPsec-Tunnel</ipsec-tunnel><secondary-wan-enabled>no</secondary-wan-enabled><ecmp-load-balancing>disabled</ecmp-load-balancing></entry>"

#File Information
$path = $demisto.args().csv
$entries = $demisto.ExecuteCommand("ParseCSV", @{"entryID" = $path})
$remote_networks = $entries[0]['Contents']



#For Each Loop
ForEach ($rn in $remote_networks){
    $rn_name = $($rn.Connection_Name)
    $rn_location = $($rn.Location)
    $rn_bandwith = $($rn.Bandwith)
    $rn_peer_ip= $($rn.Peer_IP)
    $rn_peer_subnet= $($rn.Subnet)

    #Set Command
    $strUri_set_ike_crypto ="<entry name='$rn_name-RN-IKE-Crypto'><hash><member>$hash</member></hash><dh-group><member>$dhgroup</member></dh-group><encryption><member>$encryption</member></encryption><lifetime><hours>$lifetime</hours></lifetime></entry>"
    $strUri_set_ipsec_crypto_profile ="<entry name='$rn_name-RN-IPSEC-Crypto'><esp><authentication><member>sha1</member></authentication><encryption><member>aes-128-cbc</member></encryption></esp><lifetime><hours>1</hours></lifetime><dh-group>group20</dh-group></entry>"
    $strUri_set_ike_gateway ="<entry name='$rn_name-RN-IKE-Gateway'><authentication><pre-shared-key><key>-AQ==HJYaKZavRmz7ptzotbyK/2XLY/k=E3JkmPayGoKB3hT1kuavlg==</key></pre-shared-key></authentication><protocol><ikev1><dpd><enable>yes</enable></dpd><ike-crypto-profile>$rn_name-RN-IKE-Crypto</ike-crypto-profile></ikev1><ikev2><dpd><enable>yes</enable></dpd><ike-crypto-profile>$rn_name-RN-IKE-Crypto</ike-crypto-profile></ikev2><version>ikev2-preferred</version></protocol><protocol-common><nat-traversal><enable>no</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation></protocol-common><local-address><interface>vlan</interface></local-address><peer-address><ip>$rn_peer_ip</ip></peer-address><peer-id><id>$rn_peer_ip</id><type>ipaddr</type></peer-id></entry>"
    $strUri_set_ipsec_tunnel ="<entry name='$rn_name-RN-IPsec-Tunnel'><auto-key><ike-gateway><entry name='$rn_name-RN-IKE-Gateway'/></ike-gateway><ipsec-crypto-profile>$rn_name-RN-IPSEC-Crypto</ipsec-crypto-profile></auto-key><tunnel-monitor><enable>no</enable></tunnel-monitor><tunnel-interface>tunnel</tunnel-interface></entry>"
    $strUri_set_ipsec_tunnel_plugin ="<entry name='$rn_name-RN'><protocol><bgp><enable>no</enable></bgp></protocol><subnets><member>$rn_peer_subnet</member></subnets><region>$rn_location</region><license-type>FWAAS-$rn_bandwith`Mbps</license-type><ipsec-tunnel>$rn_name-RN-IPsec-Tunnel</ipsec-tunnel><secondary-wan-enabled>no</secondary-wan-enabled><ecmp-load-balancing>disabled</ecmp-load-balancing></entry>"

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
    Write-Host "IPsec configuration in Prisma Access Plugin for $rn_name $ipsec_plugin_tunnel_message"
}
