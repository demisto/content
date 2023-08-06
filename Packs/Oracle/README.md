This pack includes XSIAM content.

## Collect Events from Vendor

In order to use the collector, you will need to perform the following steps:
 - [Configure the Broker VM](#broker-vm)
 - [Activate the Database Collector](#database-collector) 

### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click the broker VM and select **Database Collector** -> **Activate**.
3. When configuring the Database Collector, set:
   - vendor as oracle
   - product as db

### Database Collector
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/broker-vm/set-up-broker-vm/activate-the-database-collector#id1d9fc182-8324-4299-8cdd-10c0eeaa4afa).\
When configuring the `Database Connection` the `SQL Query` should look as follows:

```
SELECT UNIFIED_AUDIT_TRAIL.*
FROM UNIFIED_AUDIT_TRAIL
WHERE UNIFIED_AUDIT_TRAIL.EVENT_TIMESTAMP > ?
ORDER BY UNIFIED_AUDIT_TRAIL.EVENT_TIMESTAMP DESC;
```

Make sure to use the correct value for "Retrieval Value", to match the Rising Column value type.
