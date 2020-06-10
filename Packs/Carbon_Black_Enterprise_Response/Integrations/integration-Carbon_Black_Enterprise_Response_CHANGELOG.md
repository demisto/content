## [Unreleased]
Added new context outputs for the ***cb-get-processes*** command:
    - **File.Name**
    - **File.MD5**
    - **File.Path**
    - **Endpoint.Hostname**


## [20.3.3] - 2020-03-18
Changed search alerts API v1 call to API v2 call.

## [20.1.0] - 2020-01-07
Added the *Maximum number of incidents to fetch* parameter, which specifies the maximum number of incidents to create per fetch.

## [19.11.1] - 2019-11-26
Added the ***cb-binary-download*** command, which replaces the deprecated ***cb-binary-get*** command.

## [19.11.0] - 2019-11-12
Added the *decompress* argument to the ***cb-binary-get*** command.

## [19.9.0] - 2019-09-04
Added *get_related* argument to the ***cb-get-process*** command. If "true", will get process siblings, parent, and children. 
