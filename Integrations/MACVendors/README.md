
Macvendors.com API provides vendor information of supplied Mac Addresses, their vendors list is provided directly from the IEEE Standards Association and is updated multiple times each day. The IEEE is the registration authority and provides us data on over 16,500 registered vendors.

## Use Cases:

* Run an API query to get the vendor information of a Mac address .


## Configure MAC Vendors on Demisto

1. Go to __Settings__ > __Integrations__ > __Servers & Services__ 

2. Locate __MAC Vendors__ by searching for it using the search box on the top of the page.

3. Click __Add instance__ to create and configure a new integration. You should configure the following settings:

__URL__:
The Current API URL http://api.macvendors.com

##Commands

You can execute the following command from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### mac
Returns vendor information for the passed Mac address.
####Input
| **Argument**|**Description** |
| :------:|:------:|
| address |	The Mac address for which to return vendor information. For example: 00-11-22-33-44-55, 00:11:22:33:44:55, 00.11.22.33.44.55, 001122334455, 0011.2233.4455 |

#####Context Output
| **Path** |**Type**  | **Description**  |
| :------:|:------:|:------:|
| MACVendors.Vendor | String | The vendor name of the passed Mac address. |
