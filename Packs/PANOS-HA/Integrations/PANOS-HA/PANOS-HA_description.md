# PAN-OS High Availability (HA) Integration - Detailed Instructions

This integration provides a robust set of tools to manage and orchestrate High Availability features on Palo Alto Networks (PAN-OS) Firewalls and Panorama appliances directly from your SOAR platform. It is designed to handle the complexities of the PAN-OS API and the nuances of the `pan-os-python` library, providing reliable commands for both observing and changing the HA state.

---

## Configuration Parameters

To set up an instance of this integration, you will need the following information:

* **Hostname or IP Address:** The management IP address or hostname of the Palo Alto Networks device (Firewall or Panorama).
* **API Key:** An API key generated on the PAN-OS device with sufficient permissions to view and modify HA configurations. It's recommended to use a dedicated service account with the `Superuser (read-only)` role for read-only operations and the `Superuser` role for configuration changes.
* **Device Type:** Specify whether the target device is a `Firewall` or a `Panorama`. Most commands are specific to firewalls.
* **VSYS (Optional):** If your firewall uses Virtual Systems (vsys), you can specify a vsys name (e.g., `vsys1`). Note that most HA operational commands are global and will ignore this setting.
* **Trust any certificate (not secure):** Check this box if the device is using a self-signed SSL/TLS certificate. This is common in lab environments but is not recommended for production.

---

## Commands

The commands are divided into three categories: **Operational**, **Configuration**, and **Panorama**.

### Firewall Operational Commands

These commands query or change the live operational state of a firewall's HA status. They do not change the saved configuration and do not require a commit.

#### **1. panos-ha-get-state**

* **Purpose:** Retrieves the current, live HA status of a firewall pair. This is the primary command to check if firewalls are active, passive, synced, and connected.
* **Arguments:** None.
* **Example Command:**
    ```
    !panos-ha-get-state using="firewall-A"
    ```
* **Example Human-Readable Output:**
    ### High Availability State for 10.1.1.1
    | Property          | Value         |
    | ----------------- | ------------- |
    | Enabled           | Yes           |
    | Mode              | active-passive|
    | Local State       | active        |
    | Local Serial      | 0123456789    |
    | Peer State        | passive       |
    | Peer Connection   | up            |
    | Peer Serial       | 9876543210    |

* **Example Context Output:**
    ```json
    {
        "PAN-OS-HA.State": {
            "enabled": "yes",
            "mode": "active-passive",
            "local-info": {
                "state": "active",
                "priority": "100",
                "serial": "0123456789",
                "preemptive": "yes"
            },
            "peer-info": {
                "state": "passive",
                "conn-status": "up",
                "serial": "9876543210"
            }
        }
    }
    ```

#### **2. panos-ha-suspend-peer**

* **Purpose:** Forces the target firewall into a "suspended" state. If the target firewall is currently **active**, this will trigger a planned failover to its peer.
* **Arguments:** None.
* **Example Command:**
    ```
    !panos-ha-suspend-peer using="active-firewall"
    ```

#### **3. panos-ha-make-peer-functional**

* **Purpose:** Brings a suspended or passive firewall back into a functional state, making it ready to take over as the active peer if necessary. This is the command to use for a planned failback after maintenance.
* **Arguments:** None.
* **Example Command:**
    ```
    !panos-ha-make-peer-functional using="suspended-firewall"
    ```

#### **4. panos-ha-sync-config**

* **Purpose:** Manually forces the active firewall to synchronize its current **running configuration** to its passive peer.
* **Arguments:** None.
* **Example Command:**
    ```
    !panos-ha-sync-config using="active-firewall"
    ```

#### **5. panos-ha-sync-state**

* **Purpose:** Manually forces the active firewall to synchronize its **session state** (session table) to its passive peer.
* **Arguments:** None.
* **Example Command:**
    ```
    !panos-ha-sync-state using="active-firewall"
    ```

### Firewall Configuration Commands

These commands modify the candidate configuration of a firewall. They require a **commit** to become active.

> **Important:** When making configuration changes to a firewall managed by Panorama, the changes may be overwritten by the template. While some commands may support a `force` argument to override the template, this should be done with caution.

#### **6. panos-ha-get-config**

* **Purpose:** Retrieves the saved (not live) HA configuration from a firewall, including detailed interface, peer, and monitoring settings.
* **Arguments:** None.
* **Example Command:**
    ```
    !panos-ha-get-config using="firewall-A"
    ```
* **Example Human-Readable Output:**
    ### High Availability Configuration for 10.1.1.1
    **Main Details**
    | Property            | Value         |
    | ------------------- | ------------- |
    | Enabled             | Yes           |
    | Group ID            | 10            |
    | Mode                | Active/Passive|
    | Passive Link State  | auto          |
    | Config Sync Enabled | Yes           |

    **Peer Details**
    | Property       | Value       |
    | -------------- | ----------- |
    | Peer IP        | 192.168.1.2 |
    | Peer IP Backup | N/A         |

#### **7. panos-ha-configure**

* **Purpose:** Configures and enables High Availability on a firewall. This command can create both simple and highly detailed HA configurations.
* **Arguments:**
    * `group_id`: The HA Group ID (1-255). Default: `1`.
    * `peer_ip`: **(Required)** The IP address of the peer firewall's primary HA1 control link.
    * `peer_ip_backup`: (Optional) The IP address of the peer firewall's backup HA1 control link.
    * `passive_link_state`: (Optional) For Active/Passive mode, specifies the link state of the passive device. Can be `auto` or `shutdown`. Default: `auto`.
    * `ha1_port`: (Optional) The primary control link (HA1) interface port (e.g., `ha1-a`, `ethernet1/1`).
    * `ha1_ip_address`: (Optional) The IP address for the primary control link (HA1) interface.
    * `ha1_netmask`: (Optional) The netmask for the primary control link (HA1) interface.
    * `ha1_backup_port`, `ha1_backup_ip_address`, `ha1_backup_netmask`: (Optional) Details for the backup HA1 link.
    * `ha2_port`, `ha2_ip_address`, `ha2_netmask`: (Optional) Details for the HA2 data link.
    * `commit`: (Optional) Set to `true` to commit the changes immediately. Default: `false`.
    * `force_sync`: (Optional) Set to `true` to force a configuration sync to the peer after the commit. `commit` must also be `true`. Default: `false`.
* **Example Command (Simple):**
    ```
    !panos-ha-configure using="firewall-A" peer_ip=10.1.1.2 commit=true
    ```
* **Example Command (Advanced):**
    ```
    !panos-ha-configure using="firewall-A" group_id=10 peer_ip=192.168.26.102 ha1_port=ha1-a ha1_ip_address=192.168.26.101 ha1_netmask=255.255.255.252 commit=true force_sync=true
    ```
* **Example Human-Readable Output:**
    ### 🚀 High Availability Enabled for 10.1.1.1

    ✅ **Configuration successfully applied to candidate config.**

    💾 **Commit successful!** The configuration is now active.

    🔄 **Configuration Sync Initiated:** Successfully initiated configuration synchronization from 10.1.1.1.

#### **8. panos-ha-disable**

* **Purpose:** Disables High Availability on a firewall. This is a configuration change and requires a commit to take effect.
* **Arguments:**
    * `commit`: (Optional) Set to `true` to commit the changes immediately. Default: `false`.
* **Example Command:**
    ```
    !panos-ha-disable using="firewall-A" commit=true
    ```
* **Example Human-Readable Output:**
    ### 🚫 High Availability Disabled for 10.1.1.1

    ✅ **'Disabled' setting successfully applied to candidate config.**

    💾 **Commit successful!** The configuration is now active.

### Panorama Commands

#### **9. panos-panorama-ha-reconfigure**

* **Purpose:** Issues a "revert to running HA state" command to a Panorama peer. This is used to re-integrate a peer after maintenance or failure.
* **Arguments:** None.
* **Example Command:**
    ```
    !panos-panorama-ha-reconfigure using="panorama-B"
    ```