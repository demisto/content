Polar Security, an innovator in technology that helps companies discover, continuously monitor and secure cloud and software-as-a-service (SaaS) application data – and addresses the growing shadow data problem.
## Configure Polar Security in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Polar Security API URL | True |
| Username | False |
| Password | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### polar-list-linked-vendors

***
Get a list of all 3rd party vendors connected to your cloud workloads

#### Base Command

`polar-list-linked-vendors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolarSecurity.Vendors.vendorId | string | The 3rd party vendor unique ID | 
| PolarSecurity.Vendors.vendorName | string | The 3rd party vendor name \(Company name\) | 
| PolarSecurity.Vendors.vendorUrl | string | The 3rd party company website URL | 
| PolarSecurity.Vendors.description | string | Short description of the 3rd party vendor | 
| PolarSecurity.Vendors.accounts.vendorAccountId | string | The Cloud account ID | 
| PolarSecurity.Vendors.accounts.vendorAccountName | string | The Cloud account name \(as was onboarded to Polar\) | 
| PolarSecurity.Vendors.accounts.cloudProvider | string | Cloud service providers identifier \(aws, gcp, azure\) | 
| PolarSecurity.Vendors.certificates.certificateName | string | The vendor certification \("PCI" "HIPAA" "GDPR", etc\) | 

### polar-list-data-stores

***
List observed data stores

#### Base Command

`polar-list-data-stores`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum results to return. Default is 50. | Optional | 
| page_size | Maximum results to return per page. Default is 50. | Optional | 
| next_token | Hash value for the next page. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolarSecurity.DataStores.Stores.dataStoreId | string | Unique ID within PolarSecurity | 
| PolarSecurity.DataStores.Stores.dataStoreType | string | Type of data store | 
| PolarSecurity.DataStores.Stores.dataStoreName | string | Name of data store | 
| PolarSecurity.DataStores.Stores.cloudAccountDetails.cloudAccountId | string | ID of account where store is located | 
| PolarSecurity.DataStores.Stores.cloudAccountDetails.cloudAccountName | string | Name of account where store is located | 
| PolarSecurity.DataStores.Stores.cloudAccountDetails.serviceProvider | string | Cloud service providers identifier \(aws, gcp, azure\) | 
| PolarSecurity.DataStores.Stores.cloudRegion | string | Cloud provider region designation | 
| PolarSecurity.DataStores.Stores.country | string | Country location of data store | 
| PolarSecurity.DataStores.Stores.classificationStatus | string | One of "CLASSIFIED" "UNCLASSIFIED" "IN_PROGRESS" | 
| PolarSecurity.DataStores.Stores.vpcId | string | ID of the VPC | 
| PolarSecurity.DataStores.Stores.isBackedUp | boolean | Backup status | 
| PolarSecurity.DataStores.Stores.stats | unknown | Array of statistics | 

### polar-data-stores-summary

***
Summarize your data stores by storage type, service provider, cloud location, etc.

#### Base Command

`polar-data-stores-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolarSecurity.DataStores.Summary.totalSensitiveStores | number | Count of stores with sensitivities set | 
| PolarSecurity.DataStores.Summary.totalPotentialFlows | number | Total ways data could be accessed | 
| PolarSecurity.DataStores.Summary.totalActualFlows | number | Total ways data has actually been accessed | 
| PolarSecurity.DataStores.Summary.totalStores | number | Count of all stores observed | 
| PolarSecurity.DataStores.Summary.totalSensitivities | number | Total sensitive items observed | 
| PolarSecurity.DataStores.Summary.cloudLocations | unknown | Array of objects | 
| PolarSecurity.DataStores.Summary.serviceProviders | unknown | Array of objects | 
| PolarSecurity.DataStores.Summary.accountsIds | unknown | Array of strings | 
| PolarSecurity.DataStores.Summary.storeTypes | unknown | Array of objects | 

### polar-list-vendors-data-stores

***
Get a list of all data stores a specific 3rd party vendor can access. See whether they have sensitivities and with what role the access is made possible.

#### Base Command

`polar-list-vendors-data-stores`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_id | Specific vendor ID retrieved from polar-list-linked-vendors command. | Required | 
| limit | Maximum results to return. Default is 50. | Optional | 
| page_size | Maximum results to return per page. Default is 50. | Optional | 
| next_token | Hash value for the next page. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolarSecurity.Vendors.vendor.vendorId | string | The 3rd party vendor unique ID | 
| PolarSecurity.Vendors.vendor.dataStores.cloudProvider | string | Cloud service providers identifier \(aws, gcp, azure\) | 
| PolarSecurity.Vendors.vendor.dataStores.cloudRegion | string | Cloud provider region designation | 
| PolarSecurity.Vendors.vendor.dataStores.dataStoreId | string | Unique ID within PolarSecurity | 
| PolarSecurity.Vendors.vendor.dataStores.dataStoreName | string | Name of data store | 
| PolarSecurity.Vendors.vendor.dataStores.dataStoreType | string | Type of data store | 
| PolarSecurity.Vendors.vendor.dataStores.sensitivitiesSummary | unknown | Array of objects \(SensitivitySummary\) | 

### polar-get-data-store

***
Get a specific data store by its ID. Doesn't return anything above and beyond the polar-list-data-stores command, so no need to run it again if you've already run that.

#### Base Command

`polar-get-data-store`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| store_id | ID of data store of interest. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolarSecurity.DataStores.Stores.dataStoreName | string | Name of data store | 
| PolarSecurity.DataStores.Stores.cloudRegion | string | Cloud provider region designation | 
| PolarSecurity.DataStores.Stores.isBackedUp | boolean | Backup status | 
| PolarSecurity.DataStores.Stores.dataStoreType | string | Type of data store | 
| PolarSecurity.DataStores.Stores.dataStoreId | string | Unique ID within PolarSecurity | 
| PolarSecurity.DataStores.Stores.country | string | Country location of data store | 
| PolarSecurity.DataStores.Stores.dataStoreUrl | string | Public URL to access store | 
| PolarSecurity.DataStores.Stores.classificationStatus | string | One of "CLASSIFIED" "UNCLASSIFIED" "IN_PROGRESS" | 
| PolarSecurity.DataStores.Stores.stats | unknown | Array of statistics | 
| PolarSecurity.DataStores.Stores.cloudTags | unknown | Array of tags assigned to store | 
| PolarSecurity.DataStores.Stores.cloudAccountDetails.cloudAccountId | string | ID of account that owns the store | 
| PolarSecurity.DataStores.Stores.cloudAccountDetails.cloudAccountName | string | Name  of account that owns the store | 
| PolarSecurity.DataStores.Stores.cloudAccountDetails.serviceProvider | string | Cloud service providers identifier \(aws, gcp, azure\) | 

### polar-list-vendor-accessible-data-stores

***
List all data stores accessible by 3rd party vendors, along with which vendors have access.

#### Base Command

`polar-list-vendor-accessible-data-stores`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolarSecurity.DataStores.Stores.3rdParties.accounts.cloudProvider | string | Cloud service providers identifier \(aws, gcp, azure\) | 
| PolarSecurity.DataStores.Stores.3rdParties.accounts.vendorAccountId | string | The Cloud account ID | 
| PolarSecurity.DataStores.Stores.3rdParties.accounts.vendorAccountName | string | The Cloud account name \(as was onboarded to Polar\) | 
| PolarSecurity.DataStores.Stores.3rdParties.certificates.certificateName | string | The vendor certification \("PCI" "HIPAA" "GDPR", etc\) | 
| PolarSecurity.DataStores.Stores.3rdParties.description | string | Short description of the 3rd party vendor | 
| PolarSecurity.DataStores.Stores.3rdParties.vendorId | string | The 3rd party vendor unique ID | 
| PolarSecurity.DataStores.Stores.3rdParties.vendorName | string | The 3rd party vendor name \(Company name\) | 
| PolarSecurity.DataStores.Stores.3rdParties.vendorUrl | string | The 3rd party company website URL | 
| PolarSecurity.DataStores.Stores.cloudProvider | string | Cloud service providers identifier \(aws, gcp, azure\) | 
| PolarSecurity.DataStores.Stores.cloudRegion | string | Cloud provider region designation | 
| PolarSecurity.DataStores.Stores.dataStoreId | string | Unique ID within PolarSecurity | 
| PolarSecurity.DataStores.Stores.dataStoreName | string | Name of data store | 
| PolarSecurity.DataStores.Stores.dataStoreType | string | Type of data store | 
| PolarSecurity.DataStores.Stores.sensitivitiesSummary | unknown | Array of objects \(SensitivitySummary\) | 

### polar-apply-label

***
Add or update a custom label to a data store

#### Base Command

`polar-apply-label`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label | 256 character max string. | Required | 
| store_id | Which store to apply label. | Required | 

#### Context Output

There is no context output for this command.