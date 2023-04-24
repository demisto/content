Original community integration author: <b>Adam Burt</b><br />
Modified by <b>Josh Levine</b> for the following:
- Added additional comments to parameters for the integration and associated commands
- Updated README.MD documentation for pack and integration
- Developed unit tests for XSOAR-supported content pack validation
- Updated content pack to uplift it to Palo Alto Networks officially supported status

# Netmiko
Multi-vendor library to execute commands over SSH connections for network devices using the Netmiko Python library.

This can help in situations where there is no integration for a particular vendor technology, but a CLI is accessible that can be interacted with over the network.

## Platforms:
The following platforms are supported as the "platform" command

- a10
- accedian
- adtran_os
- adtran_os_telnet
- adva_fsp150f2
- adva_fsp150f3
- alcatel_aos
- alcatel_sros
- allied_telesis_awplus
- apresia_aeos
- apresia_aeos_telnet
- arista_eos
- arista_eos
- arista_eos_telnet
- arris_cer
- aruba_os
- aruba_osswitch
- aruba_procurve
- aruba_procurve_telnet
- avaya_ers
- avaya_vsp
- broadcom_icos
- brocade_fastiron
- brocade_fastiron_telnet
- brocade_fos
- brocade_netiron
- brocade_netiron_telnet
- brocade_nos
- brocade_vdx
- brocade_vyos
- calix_b6
- calix_b6_telnet
- casa_cmts
- cdot_cros
- centec_os
- centec_os_telnet
- checkpoint_gaia
- ciena_saos
- ciena_saos
- ciena_saos_telnet
- cisco_asa
- cisco_asa
- cisco_ftd
- cisco_ios
- cisco_ios
- cisco_ios_telnet
- cisco_nxos
- cisco_nxos
- cisco_s300
- cisco_s300_telnet
- cisco_tp
- cisco_viptela
- cisco_wlc
- cisco_xe
- cisco_xe
- cisco_xr
- cisco_xr
- cisco_xr_telnet
- cloudgenix_ion
- coriant
- dell_dnos6_telnet
- dell_dnos9
- dell_force10
- dell_isilon
- dell_os10
- dell_os10
- dell_os6
- dell_os9
- dell_powerconnect
- dell_powerconnect_telnet
- dell_sonic
- dlink_ds
- dlink_ds_telnet
- eltex
- eltex_esr
- endace
- enterasys
- ericsson_ipos
- extreme
- extreme_ers
- extreme_exos
- extreme_exos
- extreme_exos_telnet
- extreme_netiron
- extreme_netiron_telnet
- extreme_nos
- extreme_slx
- extreme_telnet
- extreme_tierra
- extreme_vdx
- extreme_vsp
- extreme_wing
- f5_linux
- f5_ltm
- f5_tmsh
- flexvnf
- fortinet
- generic
- generic_telnet
- generic_termserver
- generic_termserver_telnet
- hillstone_stoneos
- hp_comware
- hp_comware_telnet
- hp_procurve
- hp_procurve_telnet
- huawei
- huawei_olt
- huawei_olt_telnet
- huawei_smartax
- huawei_telnet
- huawei_vrpv8
- ipinfusion_ocnos
- ipinfusion_ocnos_telnet
- juniper
- juniper_junos
- juniper_junos
- juniper_junos_telnet
- juniper_screenos
- keymile
- keymile_nos
- linux
- linux
- mellanox
- mellanox_mlnxos
- mikrotik_routeros
- mikrotik_switchos
- mrv_lx
- mrv_optiswitch
- netapp_cdot
- netgear_prosafe
- netscaler
- nokia_srl
- nokia_sros
- nokia_sros
- nokia_sros_telnet
- oneaccess_oneos
- oneaccess_oneos_telnet
- ovs_linux
- paloalto_panos
- paloalto_panos_telnet
- pluribus
- quanta_mesh
- rad_etx
- rad_etx_telnet
- raisecom_roap
- raisecom_telnet
- ruckus_fastiron
- ruckus_fastiron_telnet
- ruijie_os
- ruijie_os_telnet
- sixwind_os
- sophos_sfos
- supermicro_smis
- supermicro_smis_telnet
- Supported Secure Copy device_type values
- tplink_jetstream
- tplink_jetstream_telnet
- ubiquiti_edge
- ubiquiti_edgerouter
- ubiquiti_edgeswitch
- ubiquiti_unifiswitch
- vyatta_vyos
- vyos
- watchguard_fireware
- yamaha
- yamaha_telnet
- zte_zxros
- zte_zxros_telnet
- zyxel_os

A complete list of platforms can be found [here](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md)

### SSH Keys

To provide SSH Keys for a login, and for security purposes, this can only be done by using the **credentials** store under *Integrations->Credentials* and placing the private key in the *Certificate* section. This requires from the **-----BEGIN RSA PRIVATE KEY-----** (or equivalent key type) to the **-----END RSA PRIVATE KEY-----** (or equivalent key type).

When you **DO** provide SSH keys in the credentials, the password becomes the password for the SSH key.

### Executing Commands

Executing a command is done by passing the command to be executed by the cmds= parameter of the !ssh command. e.g., !ssh cmds="show run"

To execute commands, a number of methods are available. 

#### Using the "cmds=" field on the CLI for a single command

*!ssh cmds="ifconfig"*

#### Using the "cmds=" field on the CLI for multiple commands

!ssh cmds="\<value\>" - Replace <value> with either a single command in quotes, or a list of commands surrounded by backticks with each command on a new line (SHIFT+ENTER):

    !ssh cmds=`ifconfig
        ip a
        cat /etc/passwd`

#### Using the "cmds=" field on the CLI for multiple commands stored in an array in context
*!ssh cmds=${arrayContextKey}*

#### Using the "cmds=" field in a task entry

Each command is specified on a new line in the cmds field of the task

    ifconfig
    ip a
    cat /etc/passwd` using="Netmiko"


#### Using the "cmds=" field in a task entry with an array in context

Sample array data = ["ifconfig", "ip a", "cat /etc/passwd"]
Array context key is left as the default "array" value

cmds field value in task is set to <b>${array}</b>

