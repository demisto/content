Atlassian Confluence Server API.
This integration was integrated and tested with version 6.1 of Atlassian Confluence Server.

## Configure Atlassian Confluence Server in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. http://1.2.3.4:8090) | True |
| Username | False |
| Password | False |
| Personal Access Token | False |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### confluence-create-space

***
Creates a new Confluence space.

#### Base Command

`confluence-create-space`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Space name, for example: "Test Space". | Required | 
| description | A description for the space. | Required | 
| key | Space key, which will be used as input when creating or updating child components from a space. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Confluence.Space.ID | String | Space ID. | 
| Confluence.Space.Key | String | Space key. | 
| Confluence.Space.Name | String | Space name. | 

### confluence-create-content

***
Creates Confluence content for a given space.

#### Base Command

`confluence-create-content`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | Confluence page title. | Required | 
| type | Confluence content type. Can be "page" or "blogpost". Possible values are: page, blogpost. Default is page. | Required | 
| space | Space key to add content to a specific space. | Required | 
| body | Confluence page body to add. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Confluence.Content.ID | String | Page content ID. | 
| Confluence.Content.Title | String | Content title. | 
| Confluence.Content.Type | String | Content type. | 
| Confluence.Content.Body | String | Content body. | 

### confluence-list-spaces

***
Returns a list of all Confluence spaces.

#### Base Command

`confluence-list-spaces`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of spaces to return. Default is 25. | Optional | 
| type | Filter the returned list of spaces by type. Can be "global" or "personal". Possible values are: global, personal. | Optional | 
| status | Filter the returned list of spaces by status. Can be "current" or "archived". Possible values are: current, archived. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Confluence.Space.ID | String | Space ID. | 
| Confluence.Space.Key | String | Space key. | 
| Confluence.Space.Name | String | Space name. | 

### confluence-get-content

***
Returns Confluence content by space key and title.

#### Base Command

`confluence-get-content`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | Space key. | Required | 
| title | Content title. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Confluence.Content.ID | String | Content ID. | 
| Confluence.Content.Title | String | Content title. | 
| Confluence.Content.Type | String | Content type. | 
| Confluence.Content.Version | String | Content version. | 
| Confluence.Content.Body | String | Content body. | 

### confluence-get-page-as-pdf

***
Returns Confluence Page as PDF by PageID.

#### Base Command

`confluence-get-page-as-pdf`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pageid | ID of the Page to download as PDF. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Name | string | The sample name. | 
| File.SSDeep | string | SSDeep hash of the file. | 
| File.EntryID | string | War Room entry ID of the file. | 
| File.Info | string | Basic information of the file. | 
| File.Type | string | File type, e.g., "PE". | 
| File.MD5 | string | MD5 hash of the file. | 
| File.Extension | string | File extension. | 

### confluence-delete-content

***
Deletes Confluence content.

#### Base Command

`confluence-delete-content`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Content ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Confluence.Content.Result | String | Content delete result. | 
| Confluence.Content.ID | String | Content ID deleted. | 

### confluence-update-content

***
Update (overwrite) the existing content of a Confluence page with new content.

#### Base Command

`confluence-update-content`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pageid | Page ID used to find and update the page. | Required | 
| currentversion | The version number, extracted from a content search. The integration will increment by 1. | Required | 
| title | Title of the page to update. | Required | 
| type | Content type. Can be "page" or "blogpost". Possible values are: page, blogpost. Default is page. | Required | 
| space | Space key to update. | Required | 
| body | Content body to replace (overwrite) existing content of a Confluence page. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Confluence.Content.ID | String | Content ID. | 
| Confluence.Content.Title | String | Content title. | 
| Confluence.Content.Type | String | Content type. | 
| Confluence.Content.Body | String | Content body. | 

### confluence-search-content

***
Fetches a list of content using the Confluence Query Language (CQL). For more information about CQL syntax, see https://developer.atlassian.com/server/confluence/advanced-searching-using-cql/

#### Base Command

`confluence-search-content`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cql | A CQL query string to use to locate content, for example: "space = DEV order by created". | Required | 
| cqlcontext | The context in which to execute a CQL search. The context is the JSON serialized form of SearchContext. | Optional | 
| expand | A CSV list of properties to expand on the content. Default is version. | Optional | 
| start | The start point of the collection to return. | Optional | 
| limit | Maximum number of items to return. This can be restricted by fixed system limits. Default is 25. Default is 25. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Confluence.Content.ID | String | Content ID. | 
| Confluence.Content.Title | String | Content title. | 
| Confluence.Content.Type | String | Content type. | 
| Confluence.Content.Version | String | Content version. | 
