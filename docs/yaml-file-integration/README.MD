# Overview

## What is a YAML file?
A YAML file is a form of structured data. It is visually similar to a JSON tree, however is less strict with syntax. Think of it as key, value set for your integration.

When pushing an integration for public release, your YAML file must follow certain structural requirements in order to work properly. In this section we will review the various parts of the Demisto YAML file.

## Common Fields
The Common Fields section contains information that the Demisto server will use to identify your integration. See the example below:

```yml
commonfields:
  id: New Integration
  version: -1
```

This section accepts the following information:

| Name | Description |
| --- | --- |
| **id** | A *unique* identifier for your integration |
| **version** | Setting the value to -1 will lock the integration from being modified |

## Basic Information

Observe the following:

```yml
name: MaxMind GeoIP2
display: MaxMind GeoIP2
category: Data Enrichment & Threat Intelligence
image: data:image/png;base64,**Base64 of Image Here**
description: Enriches IP addresses
detaileddescription: 'The MaxMind GeoIP2 integration allows you to query the MaxMind
  API service and retrieve a JSON of all details. '
```

The following is an explanation of these fields:

| Name | Description |
| --- | --- |
| **name** | The name of your integration. This *may* be different than the display name |
| **display** | This is the display name for your integration |
| **category** | The applicable category |
| **image** | The Icon that will be used for the integration. Please note that this image must be in Base64. Ask the design team to provide you with a compatible image  |
| **description** | A brief description of what your integration will do |
| **detaileddescription** | This description should go into more detail about how your integration works as well as requirements for the integration to work |


## Configuration
In this section, we specify the configuration requirements that are necessary for the integration to operate.

```yml
configuration:
- display: API Key
  name: apikey
  defaultvalue: ""
  type: 0
  required: true
- display: Use system proxy
  name: proxy
  defaultvalue: ""
  type: 8
  required: false
```
An explanation of these fields is as follows:

| Name | Description |
| --- | --- |
| **display** | The display name for the field. |
| **name** | The parameter which is used within the integration |
| **defaultvalue** | If there is a default for the field, it should be located here |
| **type** | An Integer that represents the type for the field. [See Entry Types Here](https://github.com/demisto/etc/wiki/_new#entry-types) |
| **required** | Boolean value to indicate that the parameter is required |

## Script
This section is where your code will reside. Review the example below:

```yml
script:
  script: |
    import requests
    import collections

    def explain_yaml():
        if user.understands is False:
            re_read_documentation()

  type: python
```
Type indicates the language your integration is written in. Demisto currently supports Python and JavaScript.

## Commands
The command section tells Demisto what arguments are required for your command as well as what the outputs are.

```yml
  commands:
  - name: command-name
    arguments:
    - name: command-argument
      required: true
      description: This is a description for the argument
    outputs:
    - contextPath: Example.Sample.Name
      description: The name of the sample
      type: string
    - contextPath: Example.Sample.ID
      description: The ID for the sample
      type: string
    description: Sample description for the command-name function
  runonce: false
```
An explanation of these fields is as follows:

| Name | Description |
| --- | --- |
| **name** | The name of the command |
| **arguments: name** | The name of the argument |
| **arguments: required** | Boolean for if the argument is required |
| **arguments: description** | A description of the argument |
| **outputs: contextPath** | The dot notation representation of the context |
| **outputs: description** | Description of the context item |
| **outputs: type** | The type which the context item will be formatted |
| **description** | A description for the command |
| **runonce** | Boolean to indicate if the function runs repeatedly|

## Version, Notes and Tests
The last section of the YAML file provides Demisto with information regarding what version is supported, release notes, and tests. See the example below:

```yml
fromversion: 4.1.0
releaseNotes: "Changed some outputs"
tests:
  - Sample Integration Test
```

From version indicates the server version that is supported with the integration. If the server version is below the fromversion, the integration will not display in the Settings area.

Release Notes tells the user what has changed in the new version of this integration. If the integration is new, simply write something to describe the integration.

Tests instructs the Demisto CircleCI tool which test to run to verify that the integration is working. 

If you want to run all of the tests you will need to add to the tests section ```Run all tests``` as the test you would like to run.


***

If you want to live a life of shame and disappoint your team, you can opt to not run any tests by adding ```No test - <reason>``` as a test you would like to run. You can attempt to earn back the respect of your team by writing a reason for skipping the test and we *may* consider it.


***

Please take into consideration that both the automatic and the manual mechanisms are working side by side and don't override each other, and don't worry it will not cause the same test to run more than once.


## Entry Types

| ID | Name | Details |
| --- | --- | --- |
| 1 | Note | A note is a text entry in the war room. |
| 2 | Download Agent | Internal use only |
| 3 | File | A file and it's metadata will be displayed |
| 4 | Error | Observed with a red background, this indicates that a command did not run successfully. |
| 5 | Pinned | Internal use only |
| 6 | User Management | Internal use only |
| 7 | Image | An image will be displayed in the war room. |
| 8 | Playground Error | An error has occurred in the playground |
| 9 | Entry Info File | Used in the `FileResult` function in ServerCommon. This is similar to the `file` entry type. |
| 10-14 | Reserved | This is for future entry types |
| 15 | Map | Posts a map location in the war room. **Please note**: This will require an API key from Google maps. |

