Use the Atlassian Confluence Server API integration to manage your Confluence spaces and content.

This integration was integrated and tested with version 6.1 of Atlassian Confluence Server.

## Configure Atlassian Confluence Server on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Atlassian Confluence Server.
3. Click **Add instance** to create and configure a new integration instance.
    - **Name**: a textual name for the integration instance.
    - **Server URL (e.g. http://1.2.3.4:8090)**
    - **Username & Password or Personal Access Token**
    - **Use system proxy settings**
    - **Trust any certificate (not secure)**
4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. Create a space: `confluence-create-space`
2. Create content for a space: `confluence-create-content`
3. Get a list of all spaces: `confluence-list-spaces`
4. Get content for a space: `confluence-get-content`
5. Delete content: `confluence-delete-content`
6. Update (overwrite) existing content: `confluence-update-content`
7. Run a CQL query: `confluence-search-content`
8. Download a Page as PDF: `confluence-get-page-as-pdf`

### 1. Create a space

Creates a new Confluence space.

#### Base Command

`confluence-create-space`

#### Input

| Argument Name | Description                                                                                     | Required |
|---------------|-------------------------------------------------------------------------------------------------|----------|
| name          | Space name, for example: “Test Space”.                                                          | Required |
| description   | A description for the space.                                                                    | Required |
| key           | Space key, which will be used as input when creating or updating child components from a space. | Required |

#### Context Output

| Path                  | Type   | Description |
|-----------------------|--------|-------------|
| Confluence.Space.ID   | string | Space ID.   |
| Confluence.Space.Key  | string | Space key.  |
| Confluence.Space.Name | string | Space name. |

#### Command Example

```
!confluence-create-space name=test description="testing space" key=TEST
```

### 2. Create content for a space

Creates Confluence content for a given space.

#### Base Command

`confluence-create-content`

#### Input

| Argument Name | Description                                           | Required |
|---------------|-------------------------------------------------------|----------|
| title         | Confluence page title.                                | Required |
| type          | Confluence content type. Can be “page” or “blogpost”. | Required |
| space         | Space key to add content to a specific space.         | Required |
| body          | Confluence page body to add.                          | Optional |

#### Context Output

| Path                     | Type   | Description      |
|--------------------------|--------|------------------|
| Confluence.Content.ID    | string | Page content ID. |
| Confluence.Content.Title | string | Content title.   |
| Confluence.Content.Type  | string | Content type.    |
| Confluence.Content.Body  | string | Content body.    |

#### Command Example

```
!confluence-create-content space=DemistoContent title="test confluence integration" type=page body=testing
```

### 3. Get a list of all spaces

Returns a list of all Confluence spaces.

#### Base Command

`confluence-list-spaces`

#### Input

| Argument Name | Description                                                                   | Required |
|---------------|-------------------------------------------------------------------------------|----------|
| limit         | Maximum number of spaces to return.                                           | Optional |
| type          | Filter the returned list of spaces by type. Can be “global” or “personal”.    | Optional |
| status        | Filter the returned list of spaces by status. Can be “current” or “archived”. | Optional |

#### Context Output

| Path                  | Type   | Description |
|-----------------------|--------|-------------|
| Confluence.Space.ID   | string | Space ID.   |
| Confluence.Space.Key  | string | Space key.  |
| Confluence.Space.Name | string | Space name. |

#### Command Example

```
!confluence-list-spaces
```

### 4. Get content for a space

Returns Confluence content by space key and title.

#### Base Command

`confluence-get-content`

#### Input

| Argument Name | Description    | Required |
|---------------|----------------|----------|
| key           | Space key.     | Required |
| title         | Content title. | Required |

#### Context Output

| Path                       | Type   | Description      |
|----------------------------|--------|------------------|
| Confluence.Content.ID      | string | Content ID.      |
| Confluence.Content.Title   | string | Content title.   |
| Confluence.Content.Type    | string | Content type.    |
| Confluence.Content.Version | string | Content version. |
| Confluence.Content.Body    | string | Content body.    |

#### Command Example

```
!confluence-get-content key=DemistoContent title="test confluence integration"
```

### 5. Delete content

Deletes Confluence content.

#### Base Command

`confluence-delete-content`

#### Input

| Argument Name | Description | Required |
|---------------|-------------|----------|
| id            | Content ID  | Required |

#### Context Output

| Path                      | Type   | Description            |
|---------------------------|--------|------------------------|
| Confluence.Content.Result | string | Content delete result. |
| Confluence.Content.ID     | string | Content ID deleted.    |

#### Command Example

```
!confluence-delete-content id=172723162
```

### 6. Update (overwrite) existing content

Update (overwrite) the existing content of a Confluence page with new content.

#### Base Command

`confluence-update-content`

#### Input

| Argument Name  | Description                                                                               | Required |
|----------------|-------------------------------------------------------------------------------------------|----------|
| pageid         | Page ID used to find and update the page.                                                 | Required |
| currentversion | The version number, extracted from a content search. The integration will increment by 1. | Required |
| title          | Title of the page to update.                                                              | Required |
| type           | Content type. Can be “page” or “blogpost”.                                                | Required |
| space          | Space key to update.                                                                      | Required |
| body           | Content body to replace (overwrite) existing content of a Confluence page.                | Optional |

#### Context Output

| Path                     | Type   | Description    |
|--------------------------|--------|----------------|
| Confluence.Content.ID    | string | Content ID.    |
| Confluence.Content.Title | string | Content title. |
| Confluence.Content.Type  | string | Content type.  |
| Confluence.Content.Body  | string | Content body.  |

#### Command Example

```
!confluence-update-content type=page pageid=172723162 currentversion=2 space=DemistoContent title="test confluence integration" body="new body"
```

### 7. Run a CQL query

Fetches a list of content using the Confluence Query Language (CQL). For more information about CQL syntax, see the [Atlassian Confluence documentation](https://developer.atlassian.com/server/confluence/advanced-searching-using-cql/).

#### Base Command

`confluence-search-content`

#### Input

| Argument Name | Description                                                                                             | Required |
|---------------|---------------------------------------------------------------------------------------------------------|----------|
| cql           | A CQL query string to use to locate content, for example: “space = DEV order by created”.               | Required |
| cqlcontext    | The context in which to execute a CQL search. The context is the JSON serialized form of SearchContext. | Optional |
| expand        | A CSV list of properties to expand on the content.                                                      | Optional |
| start         | The start point of the collection to return.                                                            | Optional |
| limit         | Maximum number of items to return. This can be restricted by fixed system limits. Default is 25.        | Optional |

#### Context Output

| Path                       | Type   | Description      |
|----------------------------|--------|------------------|
| Confluence.Content.ID      | string | Content ID.      |
| Confluence.Content.Title   | string | Content title.   |
| Confluence.Content.Type    | string | Content type.    |
| Confluence.Content.Version | string | Content version. |

#### Command Example

```
!confluence-search-content cql="title=\"test confluence integration\""
```

### 8. Download a Page as PDF

Downloads a Page as PDF by Page ID

#### Base Command

`confluence-get-page-as-pdf`

#### Input

| Argument Name | Description                                    | Required |
|---------------|------------------------------------------------|----------|
| pageid        | The ID of the page you want to export as a PDF | Required |

#### Context Output

| Path           | Type   | Description                    |
|----------------|--------|--------------------------------|
| File.Size      | number | File size.                     |
| File.SHA1      | string | SHA1 hash of the file.         |
| File.SHA256    | string | SHA256 hash of the file.       |
| File.Name      | string | The sample name.               |
| File.SSDeep    | string | SSDeep hash of the file.       |
| File.EntryID   | string | War Room entry ID of the file. |
| File.Info      | string | Basic information of the file. |
| File.Type      | string | File type, e.g., "PE".         |
| File.MD5       | string | MD5 hash of the file.          |
| File.Extension | string | File extension.                |

#### Command Example

```
!confluence-get-page-as-pdf pageid="123456"
```