## Argus Managed Defence by mnemonic
This section gives some details into how to use the integration. 

For detailed description of the API and how to use it, we recommend having a look at https://api.mnemonic.no for a comprehensive guide.

Here you will find information about expected format for all commands and what they return. There is also a link to Swagger where you will be able to interactively test the API. 
We have tried to select the features of the API relevant to XSOAR, but if you do see the need for extended functionality, you may send us a feature request at contact@mnemonic.no. 

### API keys
To use this integration, you will need an API key from Argus.

You generate one by logging into your Argus instance, and selecting "User Preferences" from the menu in the upper right corner. 
At the bottom of this page you may generate API keys. You will need to know the (translated) IP address of your XSOAR instance as you should limit the key as much as possible, for security purposes. 

### Time formats
Argus' API is quite flexible in regards to parsing time. For a comprehensive, up-to-date guide, please have a look here: 
https://docs.mnemonic.no/display/public/API/Using+Argus+Search+APIs+-+Time+fields

#### Sort By
In same cases you may want to sort the results to some sort of criteria. This could be tags such as `sortBy=timestamp` and may be nested. 
For full documentation, have a look here: https://docs.mnemonic.no/display/public/API/General+integration+guide#Generalintegrationguide-Limit,offsetandsorting


### Parsing arguments
#### Lists
Sometimes an argument requires a list of items. 
Most of the time this should be handled by XSOAR (e.g. passing values in playbooks), but if you want to input a list manually, you should do it in a comma-separated format, e.g.:
```
!command-name argument="<list_item1>,<list_item2>,..."
```

#### Tags
When batch-adding tags, the expected format is a comma-separated list of key, value pairs as shown here:
```
!command-name argument="<key1>,<value1>,<key2>,<value2>,..."
```
