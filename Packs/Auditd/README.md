## Collect Events from Vendor

In order to use the collector, you can use one of the following options to collect events from the vendor:
 - [Broker VM](#broker-vm)

In either option, you will need to configure the vendor and product for this specific collector.
### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as vendor<- Unix
   - product as product<- Auditd

### Install Auditd on Ubuntu Linux
Install Bash if not present, on your Ubuntu system.
```
sudo apt update
sudo apt install bash-completion
```
After these initial steps, now Install Auditd. The following command will install Auditd's latest version on your ubuntu system.
sudo apt-get install auditd
You can start and enable your auditd service so it will run up after system restart or reboot.

```
service status auditd

auditd start

auditd restart
```