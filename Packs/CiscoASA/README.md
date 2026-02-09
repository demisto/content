<~XSIAM>

# Overview

Cisco Adaptive Security Appliances (ASA) is a unified security solution that integrates firewall capabilities, intrusion prevention (IPS), and VPN services. It safeguards network environments by managing traffic flow, blocking threats, and providing secure connectivity for remote users.

# This pack includes

## Data normalization capabilities

Rules that parse and model Cisco ASA logs ingested via the Broker VM in Cortex XSIAM.

* The ingested Cisco ASA logs can be queried in XQL Search using the *`cisco_asa_raw`* dataset.

## Supported event IDs

* 106001, 106002, 106006, 106007, 106010, 106012, 106013, 106014, 106015, 106016, 106017, 106018, 106020, 106021, 106022, 106023, 106025, 106026, 106027, 106100, 106102, 106103, 108003, 108004, 108005, 108006, 108007, 109001, 109002, 109003, 109005, 109006, 109007, 109008, 109010, 109011, 109017, 109023, 109024, 109025, 109027, 109028, 109031, 109033, 109034, 109040, 109103, 109104, 109201, 109203, 109204, 109205, 109207, 109208, 109209, 109210, 109212, 109213, 110002, 110003, 111001, 111002, 111003, 111004, 111005, 111007, 111008, 111009, 111010, 113003, 113004, 113005, 113006, 113007, 113008, 113009, 113010, 113011, 113012, 113013, 113014, 113015, 113016, 113017, 113019, 113021, 113022, 113023, 113029, 113030, 113031, 113032, 113033, 113034, 113035, 113036, 113037, 113038, 113039, 113042

* 201010, 201012, 209003, 209004, 209006, 212001, 212002, 212003, 212004, 212005, 212006, 212009, 212010, 214001

* 302003, 302004, 302012, 302013, 302014, 302015, 302016, 302017, 302018, 302020, 302021, 302022, 302023, 302024, 302025, 302026, 302027, 302033, 302035, 302036, 302303, 302304, 302305, 302306, 303002, 303004, 303005, 304001, 304002, 308001, 312001, 313005, 313009, 314001, 314002, 314003, 314004, 314005, 314006, 315011, 315013, 322001, 322002, 322003, 324000, 324001, 324002, 324003, 324004, 324005, 324007, 324009, 324300, 324302, 338001, 338002, 338003, 338004, 338005, 338006, 338007, 338008, 338101, 338102, 338103, 338104, 338201, 338202, 338203, 338204, 338301

* 402115, 402116, 402117, 402118, 402119, 402120, 402121, 405001, 405002, 405003, 405103, 405104, 405105, 405201, 405300, 406001, 406002, 407002, 410001, 410002, 410003, 410004, 415001, 415002, 415003, 415004, 415005, 415006, 415007, 415008, 415009, 415010, 415011, 415012, 415013, 415014, 415015, 415016, 415017, 415018, 415019, 415020, 416001, 418001, 419001, 419002, 419003, 421001, 421007, 423001, 423002, 423003, 423004, 423005, 429002, 429003, 429007, 431001, 431002, 434001, 434002, 434003, 434004, 434007

* 500001, 500002, 500003, 500004, 500005, 502101, 502102, 502103, 503001, 507001, 507003, 508001, 508002, 509001

* 602101, 602103, 602104, 602303, 602304, 603102, 603103, 603104, 603105, 603106, 603107, 603108, 605004, 605005, 606001, 606002, 606003, 606004, 607001, 607002, 607003, 607004, 608001, 608002, 608003, 608004, 608005, 609002, 610001, 610002, 611101, 611102, 611103, 616001, 617003, 617004, 617100, 618001, 620001, 620002

* 710001, 710002, 710003, 710004, 710005, 710006, 711004, 713052, 713060, 713198, 713255, 716001, 716002, 716003, 716004, 716005, 716006, 716007, 716009, 716010, 716011, 716012, 716013, 716014, 716015, 716016, 716017, 716018, 716019, 716020, 716021, 716023, 716024, 716025, 716026, 716027, 716028, 716029, 716030, 716031, 716032, 716033, 716034, 716035, 716036, 716037, 716038, 716039, 716042, 716043, 716057, 716058, 716059, 717037, 717051, 717052, 717056, 719004, 719015, 719017, 719018, 719019, 719020, 719021, 719022, 719023, 719024, 719025, 719026, 722005, 722006, 722010, 722011, 722012, 722022, 722023, 722028, 722030, 722031, 722032, 722033, 722034, 722035, 722036, 722037, 722038, 722041, 722043, 722044, 722048, 722050, 722051, 722053, 722054, 722055, 723001, 723002, 723009, 723010, 723014, 724001, 724002, 725001, 725002, 725003, 725004, 725005, 725006, 725007, 725016, 734001, 737036, 768004, 772002, 772003, 772004, 772005, 772006, 775001, 775003, 775007

***

## Data collection

### Cisco ASA side

1. Enter the following command to enable transmitting syslog messages to all output locations.  
   `logging enable`

    `logging enable` - Enables the transmission of syslog messages to all output locations.

2. To configure Cisco ASA to send logging information to a Syslog Server, enter the below command:

    `logging host interface_name ip_address [tcp[/port] | udp[/port]] [format emblem]`

For more information about syslog configuration see the official [Cisco ASA docs](https://www.cisco.com/c/en/us/support/docs/security/pix-500-series-security-appliances/63884-config-asa-00.html#toc-hId-68106104).

### Cortex XSIAM side - Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM).

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

    | Parameter    | Value                                                                                                                       |
    |:-------------|:----------------------------------------------------------------------------------------------------------------------------|
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in Cisco ASA). |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Cisco ASA.   |
    | `Vendor`     | Enter Cisco.                                                                                                                 |
    | `Product`    | Enter ASA.|

</~XSIAM>
