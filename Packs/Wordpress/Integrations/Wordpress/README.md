The WordPress REST API provides an interface for applications to interact with your WordPress site by sending and receiving data as JSON (JavaScript Object Notation) objects. It is the foundation of the WordPress Block Editor, and can likewise enable your theme, plugin or custom application to present new, powerful interfaces for managing and publishing your site content.
This integration was integrated and tested with version 5.6 of Wordpress

## Configure Wordpress in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| User | Username | True |
| Application Password | The Application Password to use for connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### wordpress-url-request
***
Get information from a custom URL


#### Base Command

`wordpress-url-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| method | Method. Possible values are: get, post, put, delete, patch. Default is get. | Required | 
| url | URL suffix to append to the base URL. | Required | 
| body | Body data (JSON). | Optional | 
| params | Parameters (JSON). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.URL | Unknown | URL output data | 

### wordpress-list-posts
***
Lists all posts


#### Base Command

`wordpress-list-posts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context | Scope under which the request is made; determines fields present in response (default is view). Possible values are: view, edit, embed. Default is view. | Optional | 
| page | Current page of the collection (defaults is 1). | Optional | 
| per_page | Maximum number of items to be returned in result set (default is 10). | Optional | 
| search | Limit results to those matching a string. | Optional | 
| after | Limit response to posts published after a given ISO8601 compliant date. | Optional | 
| author | Limit result set to posts assigned to specific authors. | Optional | 
| author_exclude | Ensure result set excludes posts assigned to specific authors. | Optional | 
| before | Limit response to posts published before a given ISO8601 compliant date. | Optional | 
| exclude | Ensure result set excludes specific IDs. | Optional | 
| include | Limit result set to specific IDs. | Optional | 
| offset | Offset the result set by a specific number of items. | Optional | 
| order | Order sort attribute ascending or descending (default is desc). Possible values are: desc, asc. Default is desc. | Optional | 
| orderby | Sort collection by object attribute (default is date). Possible values are: author, date, id, include, modified, parent, relevance, slug, include_slugs, title. Default is date. | Optional | 
| slug | Limit result set to posts with one or more specific slugs. | Optional | 
| status | Limit result set to posts assigned one or more statuses (default is publish). Default is publish. | Optional | 
| tax_relation | Limit result set based on relationship between multiple taxonomies. Possible values are: AND, OR. | Optional | 
| categories | Limit result set to all items that have the specified term assigned in the categories taxonomy. | Optional | 
| categories_exclude | Limit result set to all items except those that have the specified term assigned in the categories taxonomy. | Optional | 
| tags | Limit result set to all items that have the specified term assigned in the tags taxonomy. | Optional | 
| tags_exclude | Limit result set to all items except those that have the specified term assigned in the tags taxonomy. | Optional | 
| sticky | Limit result set to items that are sticky. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Posts.excerpt.protected | Boolean | Exerpt protected | 
| Wordpress.Posts.excerpt.rendered | String | Exerpt rendered | 
| Wordpress.Posts.meta | Unknown | Metadata | 
| Wordpress.Posts.sticky | Boolean | Sticky | 
| Wordpress.Posts.guid.rendered | String | GUID rendered | 
| Wordpress.Posts.modified | String | Modified | 
| Wordpress.Posts.author | String | Author | 
| Wordpress.Posts.slug | String | Slug | 
| Wordpress.Posts.date | String | Date | 
| Wordpress.Posts.comment_status | String | Comment status | 
| Wordpress.Posts.status | String | Status | 
| Wordpress.Posts.featured_media | Number | Featured media | 
| Wordpress.Posts.format | String | Format | 
| Wordpress.Posts.modified_gmt | String | Modified GMT | 
| Wordpress.Posts.title.rendered | String | Title rendered | 
| Wordpress.Posts.tags | List | Tags | 
| Wordpress.Posts.content.protected | Boolean | Content protected | 
| Wordpress.Posts.content.rendered | String | Content rendered | 
| Wordpress.Posts.template | String | Template | 
| Wordpress.Posts._links | Unknown | Links | 
| Wordpress.Posts.type | String | Type | 
| Wordpress.Posts.link | String | Link | 
| Wordpress.Posts.id | String | ID | 
| Wordpress.Posts.categories | List | Categories | 
| Wordpress.Posts.date_gmt | String | Date GMT | 
| Wordpress.Posts.ping_status | String | Ping status | 

### wordpress-get-post
***
Retrieve a specific post record.


#### Base Command

`wordpress-get-post`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Unique identifier for the object. | Required | 
| context | Scope under which the request is made; determines fields present in response (default is view). Possible values are: view, edit, embed. Default is view. | Optional | 
| password | The password for the post if it is password protected. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Posts.excerpt.protected | Boolean | Exerpt protected | 
| Wordpress.Posts.excerpt.rendered | String | Exerpt rendered | 
| Wordpress.Posts.meta | Unknown | Metadata | 
| Wordpress.Posts.sticky | Boolean | Sticky | 
| Wordpress.Posts.guid.rendered | String | GUID rendered | 
| Wordpress.Posts.modified | String | Modified | 
| Wordpress.Posts.author | String | Author | 
| Wordpress.Posts.slug | String | Slug | 
| Wordpress.Posts.date | String | Date | 
| Wordpress.Posts.comment_status | String | Comment status | 
| Wordpress.Posts.status | String | Status | 
| Wordpress.Posts.featured_media | Number | Featured media | 
| Wordpress.Posts.format | String | Format | 
| Wordpress.Posts.modified_gmt | String | Modified GMT | 
| Wordpress.Posts.title.rendered | String | Title rendered | 
| Wordpress.Posts.tags | List | Tags | 
| Wordpress.Posts.content.protected | Boolean | Content protected | 
| Wordpress.Posts.content.rendered | String | Content rendered | 
| Wordpress.Posts.template | String | Template | 
| Wordpress.Posts._links | Unknown | Links | 
| Wordpress.Posts.type | String | Type | 
| Wordpress.Posts.link | String | Link | 
| Wordpress.Posts.id | String | ID | 
| Wordpress.Posts.categories | List | Categories | 
| Wordpress.Posts.date_gmt | String | Date GMT | 
| Wordpress.Posts.ping_status | String | Ping status | 

### wordpress-create-post
***
Create a post


#### Base Command

`wordpress-create-post`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | A named status for the object (default is draft). Possible values are: publish, future, draft, pending, private. Default is draft. | Required | 
| slug | An alphanumeric identifier for the object unique to its type. | Optional | 
| password | A password to protect access to the content and excerpt. | Optional | 
| title | The title for the object. | Required | 
| content | The content for the object. | Required | 
| author | The ID for the author of the object. | Required | 
| exerpt | The excerpt for the object. | Optional | 
| featured_media | The ID of the featured media for the object. | Optional | 
| comment_status | Whether or not comments are open on the object. Possible values are: open, closed. | Optional | 
| ping_status | Whether or not the object can be pinged. Possible values are: open, closed. | Optional | 
| format | The format for the object (default is standard). Possible values are: standard, aside, chat, gallery, link, image, quote, status, video, audio. Default is standard. | Required | 
| meta | Meta fields (JSON dict). | Optional | 
| sticky | Whether or not the object should be treated as sticky (default is false). Possible values are: true, false. Default is false. | Optional | 
| template | The theme file to use to display the object. | Optional | 
| categories | The terms assigned to the object in the category taxonomy (CSV of IDs). | Optional | 
| tags | The terms assigned to the object in the post_tag taxonomy (CSV). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Posts.excerpt.protected | Boolean | Exerpt protected | 
| Wordpress.Posts.excerpt.rendered | String | Exerpt rendered | 
| Wordpress.Posts.meta | Unknown | Metadata | 
| Wordpress.Posts.sticky | Boolean | Sticky | 
| Wordpress.Posts.guid.rendered | String | GUID rendered | 
| Wordpress.Posts.modified | String | Modified | 
| Wordpress.Posts.author | String | Author | 
| Wordpress.Posts.slug | String | Slug | 
| Wordpress.Posts.date | String | Date | 
| Wordpress.Posts.comment_status | String | Comment status | 
| Wordpress.Posts.status | String | Status | 
| Wordpress.Posts.featured_media | Number | Featured media | 
| Wordpress.Posts.format | String | Format | 
| Wordpress.Posts.modified_gmt | String | Modified GMT | 
| Wordpress.Posts.title.rendered | String | Title rendered | 
| Wordpress.Posts.tags | List | Tags | 
| Wordpress.Posts.content.protected | Boolean | Content protected | 
| Wordpress.Posts.content.rendered | String | Content rendered | 
| Wordpress.Posts.template | String | Template | 
| Wordpress.Posts._links | Unknown | Links | 
| Wordpress.Posts.type | String | Type | 
| Wordpress.Posts.link | String | Link | 
| Wordpress.Posts.id | String | ID | 
| Wordpress.Posts.categories | List | Categories | 
| Wordpress.Posts.date_gmt | String | Date GMT | 
| Wordpress.Posts.ping_status | String | Ping status | 

### wordpress-update-post
***
Update a post


#### Base Command

`wordpress-update-post`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Post ID. | Required | 
| date | The date the object was published, in the sites timezone. | Optional | 
| date_gmt | The date the object was published, as GMT. | Optional | 
| status | A named status for the object (default is draft). Possible values are: publish, future, draft, pending, private. Default is draft. | Optional | 
| slug | An alphanumeric identifier for the object unique to its type. | Optional | 
| password | A password to protect access to the content and excerpt. | Optional | 
| title | The title for the object. | Optional | 
| content | The content for the object. | Optional | 
| author | The ID for the author of the object. | Optional | 
| exerpt | The excerpt for the object. | Optional | 
| featured_media | The ID of the featured media for the object. | Optional | 
| comment_status | Whether or not comments are open on the object. Possible values are: open, closed. | Optional | 
| ping_status | Whether or not the object can be pinged. Possible values are: open, closed. | Optional | 
| format | The format for the object (default is standard). Possible values are: standard, aside, chat, gallery, link, image, quote, status, video, audio. Default is standard. | Optional | 
| meta | Meta fields (JSON dict). | Optional | 
| sticky | Whether or not the object should be treated as sticky (default is false). Possible values are: true, false. Default is false. | Optional | 
| template | The theme file to use to display the object. | Optional | 
| categories | The terms assigned to the object in the category taxonomy (CSV of IDs). | Optional | 
| tags | The terms assigned to the object in the post_tag taxonomy (CSV of IDs). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Posts.excerpt.protected | Boolean | Exerpt protected | 
| Wordpress.Posts.excerpt.rendered | String | Exerpt rendered | 
| Wordpress.Posts.meta | Unknown | Metadata | 
| Wordpress.Posts.sticky | Boolean | Sticky | 
| Wordpress.Posts.guid.rendered | String | GUID rendered | 
| Wordpress.Posts.modified | String | Modified | 
| Wordpress.Posts.author | String | Author | 
| Wordpress.Posts.slug | String | Slug | 
| Wordpress.Posts.date | String | Date | 
| Wordpress.Posts.comment_status | String | Comment status | 
| Wordpress.Posts.status | String | Status | 
| Wordpress.Posts.featured_media | Number | Featured media | 
| Wordpress.Posts.format | String | Format | 
| Wordpress.Posts.modified_gmt | String | Modified GMT | 
| Wordpress.Posts.title.rendered | String | Title rendered | 
| Wordpress.Posts.tags | List | Tags | 
| Wordpress.Posts.content.protected | Boolean | Content protected | 
| Wordpress.Posts.content.rendered | String | Content rendered | 
| Wordpress.Posts.template | String | Template | 
| Wordpress.Posts._links | Unknown | Links | 
| Wordpress.Posts.type | String | Type | 
| Wordpress.Posts.link | String | Link | 
| Wordpress.Posts.id | String | ID | 
| Wordpress.Posts.categories | List | Categories | 
| Wordpress.Posts.date_gmt | String | Date GMT | 
| Wordpress.Posts.ping_status | String | Ping status | 

### wordpress-delete-post
***
Delete a post


#### Base Command

`wordpress-delete-post`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Post ID. | Required | 
| force | Whether to bypass Trash and force deletion (default is false). Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Posts.excerpt.protected | Boolean | Exerpt protected | 
| Wordpress.Posts.excerpt.rendered | String | Exerpt rendered | 
| Wordpress.Posts.meta | Unknown | Metadata | 
| Wordpress.Posts.sticky | Boolean | Sticky | 
| Wordpress.Posts.guid.rendered | String | GUID rendered | 
| Wordpress.Posts.modified | String | Modified | 
| Wordpress.Posts.author | String | Author | 
| Wordpress.Posts.slug | String | Slug | 
| Wordpress.Posts.date | String | Date | 
| Wordpress.Posts.comment_status | String | Comment status | 
| Wordpress.Posts.status | String | Status | 
| Wordpress.Posts.featured_media | Number | Featured media | 
| Wordpress.Posts.format | String | Format | 
| Wordpress.Posts.modified_gmt | String | Modified GMT | 
| Wordpress.Posts.title.rendered | String | Title rendered | 
| Wordpress.Posts.tags | List | Tags | 
| Wordpress.Posts.content.protected | Boolean | Content protected | 
| Wordpress.Posts.content.rendered | String | Content rendered | 
| Wordpress.Posts.template | String | Template | 
| Wordpress.Posts._links | Unknown | Links | 
| Wordpress.Posts.type | String | Type | 
| Wordpress.Posts.link | String | Link | 
| Wordpress.Posts.id | String | ID | 
| Wordpress.Posts.categories | List | Categories | 
| Wordpress.Posts.date_gmt | String | Date GMT | 
| Wordpress.Posts.ping_status | String | Ping status | 

### wordpress-list-categories
***
List categories


#### Base Command

`wordpress-list-categories`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context | Scope under which the request is made; determines fields present in response (default is view). Possible values are: view, edit, embed. Default is view. | Optional | 
| page | Current page of the collection (defaults is 1). | Optional | 
| per_page | Maximum number of items to be returned in result set (default is 10). | Optional | 
| search | Limit results to those matching a string. | Optional | 
| exclude | Ensure result set excludes specific IDs. | Optional | 
| include | Limit result set to specific IDs. | Optional | 
| order | Order sort attribute ascending or descending (default is desc). Possible values are: desc, asc. Default is desc. | Optional | 
| orderby | Sort collection by object attribute (default is date). Possible values are: author, date, id, include, modified, parent, relevance, slug, include_slugs, title. Default is date. | Optional | 
| slug | Limit result set to posts with one or more specific slugs. | Optional | 
| hide_empty | Whether to hide terms not assigned to any posts. | Optional | 
| post | Limit result set to terms assigned to a specific post. | Optional | 
| parent | Limit result set to terms assigned to a specific parent. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Categories.meta | Unknown | Metadata | 
| Wordpress.Categories.parent | Number | Parent | 
| Wordpress.Categories.name | String | Name | 
| Wordpress.Categories.slug | String | Slug | 
| Wordpress.Categories.count | Number | Count | 
| Wordpress.Categories.taxonomy | String | Taxonomy | 
| Wordpress.Categories._links | List | Links | 
| Wordpress.Categories.link | String | Link | 
| Wordpress.Categories.id | Number | ID | 
| Wordpress.Categories.description | String | Description | 

### wordpress-create-category
***
Create a category


#### Base Command

`wordpress-create-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | HTML description of the term. | Optional | 
| name | HTML title for the term. | Required | 
| slug | An alphanumeric identifier for the term unique to its type. | Optional | 
| parent | The parent term ID. | Optional | 
| meta | Meta fields (JSON dict). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Categories.meta | Unknown | Metadata | 
| Wordpress.Categories.parent | Number | Parent | 
| Wordpress.Categories.name | String | Name | 
| Wordpress.Categories.slug | String | Slug | 
| Wordpress.Categories.count | Number | Count | 
| Wordpress.Categories.taxonomy | String | Taxonomy | 
| Wordpress.Categories._links | List | Links | 
| Wordpress.Categories.link | String | Link | 
| Wordpress.Categories.id | Number | ID | 
| Wordpress.Categories.description | String | Description | 

### wordpress-get-category
***
Retrieve a category


#### Base Command

`wordpress-get-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Unique identifier for the category. | Required | 
| context | Scope under which the request is made; determines fields present in response (default is view). Possible values are: view, edit, embed. Default is view. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Categories.meta | Unknown | Metadata | 
| Wordpress.Categories.parent | Number | Parent | 
| Wordpress.Categories.name | String | Name | 
| Wordpress.Categories.slug | String | Slug | 
| Wordpress.Categories.count | Number | Count | 
| Wordpress.Categories.taxonomy | String | Taxonomy | 
| Wordpress.Categories._links | List | Links | 
| Wordpress.Categories.link | String | Link | 
| Wordpress.Categories.id | Number | ID | 
| Wordpress.Categories.description | String | Description | 

### wordpress-update-category
***
Update a category


#### Base Command

`wordpress-update-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Category ID. | Required | 
| description | HTML description of the term. | Optional | 
| name | HTML title for the term. | Optional | 
| slug | An alphanumeric identifier for the term unique to its type. | Optional | 
| parent | The parent term ID. | Optional | 
| meta | Meta fields (JSON dict). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Categories.meta | Unknown | Metadata | 
| Wordpress.Categories.parent | Number | Parent | 
| Wordpress.Categories.name | String | Name | 
| Wordpress.Categories.slug | String | Slug | 
| Wordpress.Categories.count | Number | Count | 
| Wordpress.Categories.taxonomy | String | Taxonomy | 
| Wordpress.Categories._links | List | Links | 
| Wordpress.Categories.link | String | Link | 
| Wordpress.Categories.id | Number | ID | 
| Wordpress.Categories.description | String | Description | 

### wordpress-delete-category
***
Delete a category


#### Base Command

`wordpress-delete-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Category ID. | Required | 


#### Context Output

There is no context output for this command.
### wordpress-list-tags
***
Lists all tags


#### Base Command

`wordpress-list-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context | Scope under which the request is made; determines fields present in response (default is view). Possible values are: view, edit, embed. Default is view. | Optional | 
| page | Current page of the collection (defaults is 1). | Optional | 
| per_page | Maximum number of items to be returned in result set (default is 10). | Optional | 
| search | Limit results to those matching a string. | Optional | 
| exclude | Ensure result set excludes specific IDs. | Optional | 
| include | Limit result set to specific IDs. | Optional | 
| offset | Offset the result set by a specific number of items. | Optional | 
| order | Order sort attribute ascending or descending (default is desc). Possible values are: desc, asc. Default is desc. | Optional | 
| orderby | Sort collection by object attribute (default is date). Possible values are: author, date, id, include, modified, parent, relevance, slug, include_slugs, title. Default is date. | Optional | 
| slug | Limit result set to posts with one or more specific slugs. | Optional | 
| hide_empty | Whether to hide terms not assigned to any posts. | Optional | 
| post | Limit result set to terms assigned to a specific post. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Tags.meta | Unknown | Metadata | 
| Wordpress.Tags.name | String | Name | 
| Wordpress.Tags.slug | String | Slug | 
| Wordpress.Tags.count | Number | Count | 
| Wordpress.Tags.taxonomy | String | Taxonomy | 
| Wordpress.Tags._links | List | Links | 
| Wordpress.Tags.link | String | Link | 
| Wordpress.Tags.id | Number | ID | 
| Wordpress.Tags.description | String | Description | 

### wordpress-create-tag
***
Create a tag


#### Base Command

`wordpress-create-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | HTML description of the term. | Optional | 
| name | HTML title for the term. | Optional | 
| slug | An alphanumeric identifier for the term unique to its type. | Optional | 
| meta | Meta fields (JSON dict). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Tags.meta | Unknown | Metadata | 
| Wordpress.Tags.name | String | Name | 
| Wordpress.Tags.slug | String | Slug | 
| Wordpress.Tags.count | Number | Count | 
| Wordpress.Tags.taxonomy | String | Taxonomy | 
| Wordpress.Tags._links | List | Links | 
| Wordpress.Tags.link | String | Link | 
| Wordpress.Tags.id | Number | ID | 
| Wordpress.Tags.description | String | Description | 

### wordpress-get-tag
***
Retrieves a tag


#### Base Command

`wordpress-get-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context | Scope under which the request is made; determines fields present in response (default is view). Possible values are: view, edit, embed. Default is view. | Optional | 
| id | Tag ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Tags.meta | Unknown | Metadata | 
| Wordpress.Tags.name | String | Name | 
| Wordpress.Tags.slug | String | Slug | 
| Wordpress.Tags.count | Number | Count | 
| Wordpress.Tags.taxonomy | String | Taxonomy | 
| Wordpress.Tags._links | List | Links | 
| Wordpress.Tags.link | String | Link | 
| Wordpress.Tags.id | Number | ID | 
| Wordpress.Tags.description | String | Description | 

### wordpress-update-tag
***
Update a tag


#### Base Command

`wordpress-update-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Tag ID. | Required | 
| description | HTML description of the term. | Optional | 
| name | HTML title for the term. | Optional | 
| slug | An alphanumeric identifier for the term unique to its type. | Optional | 
| parent | The parent term ID. | Optional | 
| meta | Meta fields (JSON dict). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Tags.meta | Unknown | Metadata | 
| Wordpress.Tags.name | String | Name | 
| Wordpress.Tags.slug | String | Slug | 
| Wordpress.Tags.count | Number | Count | 
| Wordpress.Tags.taxonomy | String | Taxonomy | 
| Wordpress.Tags._links | List | Links | 
| Wordpress.Tags.link | String | Link | 
| Wordpress.Tags.id | Number | ID | 
| Wordpress.Tags.description | String | Description | 

### wordpress-delete-tag
***
Delete a tag


#### Base Command

`wordpress-delete-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Tag ID. | Required | 


#### Context Output

There is no context output for this command.
### wordpress-list-comments
***
Lists all comments


#### Base Command

`wordpress-list-comments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context | Scope under which the request is made; determines fields present in response (default is view). Possible values are: view, edit, embed. Default is view. | Optional | 
| page | Current page of the collection (defaults is 1). | Optional | 
| per_page | Maximum number of items to be returned in result set (default is 10). | Optional | 
| search | Limit results to those matching a string. | Optional | 
| after | Limit response to comments published after a given ISO8601 compliant date. | Optional | 
| author | Limit result set to comments assigned to specific user IDs. | Optional | 
| author_exclude | Ensure result set excludes comments assigned to specific user IDs. | Optional | 
| author_email | Limit result set to that from a specific author email. | Optional | 
| before | Limit response to comments published before a given ISO8601 compliant date. | Optional | 
| exclude | Ensure result set excludes specific IDs. | Optional | 
| include | Limit result set to specific IDs. | Optional | 
| offset | Offset the result set by a specific number of items. | Optional | 
| order | Order sort attribute ascending or descending (default is desc). Possible values are: desc, asc. Default is desc. | Optional | 
| orderby | Sort collection by object attribute (default is date_gmt). Possible values are: date, date_gmt, id, include, post, parent, type. Default is date_gmt. | Optional | 
| parent | Limit result set to terms assigned to a specific parent. | Optional | 
| parent_exclude | Ensure result set excludes specific parent IDs. | Optional | 
| post | Limit result set to terms assigned to a specific post. | Optional | 
| status | Limit result set to comments assigned a specific status (default is approve). Default is approve. | Optional | 
| type | Limit result set to comments assigned a specific type (default is comment). Default is comment. | Optional | 
| password | The password for the post if it is password protected. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Comments.post | String | Post ID | 
| Wordpress.Comments.meta | String | Metadata | 
| Wordpress.Comments.parent | Number | Parent ID | 
| Wordpress.Comments.author | Number | Author ID | 
| Wordpress.Comments.date | String | Date | 
| Wordpress.Comments.status | String | Status | 
| Wordpress.Comments.author_avatar_urls | List | Author svatars | 
| Wordpress.Comments.content.rendered | String | Rendered content | 
| Wordpress.Comments._links | List | Links | 
| Wordpress.Comments.type | String | Type | 
| Wordpress.Comments.link | String | Link | 
| Wordpress.Comments.author_url | String | Author URL | 
| Wordpress.Comments.id | Number | id | 
| Wordpress.Comments.date_gmt | String | Date GMT | 
| Wordpress.Comments.author_name | String | Author name | 

### wordpress-create-comment
***
Create a comment


#### Base Command

`wordpress-create-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| author | The ID of the user object, if author was a user. | Optional | 
| author_email | Email address for the object author. | Optional | 
| author_ip | IP address for the object author. | Optional | 
| author_name | Display name for the object author. | Optional | 
| author_url | URL for the object author. | Optional | 
| author_user_agent | User agent for the object author. | Optional | 
| content | The content for the object. | Optional | 
| parent | The ID for the parent of the object. | Optional | 
| post | The ID of the associated post object. | Optional | 
| status | State of the object. | Optional | 
| meta | Meta fields (JSON dict). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Comments.post | String | Post ID | 
| Wordpress.Comments.meta | String | Metadata | 
| Wordpress.Comments.parent | Number | Parent ID | 
| Wordpress.Comments.author | Number | Author ID | 
| Wordpress.Comments.date | String | Date | 
| Wordpress.Comments.status | String | Status | 
| Wordpress.Comments.author_avatar_urls | List | Author svatars | 
| Wordpress.Comments.content.rendered | String | Rendered content | 
| Wordpress.Comments._links | List | Links | 
| Wordpress.Comments.type | String | Type | 
| Wordpress.Comments.link | String | Link | 
| Wordpress.Comments.author_url | String | Author URL | 
| Wordpress.Comments.id | Number | id | 
| Wordpress.Comments.date_gmt | String | Date GMT | 
| Wordpress.Comments.author_name | String | Author name | 

### wordpress-get-comment
***
Retrieves a comment


#### Base Command

`wordpress-get-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context | Scope under which the request is made; determines fields present in response (default is view). Possible values are: view, edit, embed. Default is view. | Optional | 
| id | Comment ID. | Required | 
| password | The password for the parent post of the comment (if the post is password protected). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Comments.post | String | Post ID | 
| Wordpress.Comments.meta | String | Metadata | 
| Wordpress.Comments.parent | Number | Parent ID | 
| Wordpress.Comments.author | Number | Author ID | 
| Wordpress.Comments.date | String | Date | 
| Wordpress.Comments.status | String | Status | 
| Wordpress.Comments.author_avatar_urls | List | Author svatars | 
| Wordpress.Comments.content.rendered | String | Rendered content | 
| Wordpress.Comments._links | List | Links | 
| Wordpress.Comments.type | String | Type | 
| Wordpress.Comments.link | String | Link | 
| Wordpress.Comments.author_url | String | Author URL | 
| Wordpress.Comments.id | Number | id | 
| Wordpress.Comments.date_gmt | String | Date GMT | 
| Wordpress.Comments.author_name | String | Author name | 

### wordpress-update-comment
***
Update a comment


#### Base Command

`wordpress-update-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Comment ID. | Required | 
| author | The ID of the user object, if author was a user. | Optional | 
| author_email | Email address for the object author. | Optional | 
| author_ip | IP address for the object author. | Optional | 
| author_name | Display name for the object author. | Optional | 
| author_url | URL for the object author. | Optional | 
| author_user_agent | User agent for the object author. | Optional | 
| content | The content for the object. | Optional | 
| date | The date the object was published, in the sites timezone. | Optional | 
| date_gmt | The date the object was published, as GMT. | Optional | 
| parent | The ID for the parent of the object. | Optional | 
| post | The ID of the associated post object. | Optional | 
| status | State of the object. | Optional | 
| meta | Meta fields (JSON dict). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Comments.post | String | Post ID | 
| Wordpress.Comments.meta | String | Metadata | 
| Wordpress.Comments.parent | Number | Parent ID | 
| Wordpress.Comments.author | Number | Author ID | 
| Wordpress.Comments.date | String | Date | 
| Wordpress.Comments.status | String | Status | 
| Wordpress.Comments.author_avatar_urls | List | Author svatars | 
| Wordpress.Comments.content.rendered | String | Rendered content | 
| Wordpress.Comments._links | List | Links | 
| Wordpress.Comments.type | String | Type | 
| Wordpress.Comments.link | String | Link | 
| Wordpress.Comments.author_url | String | Author URL | 
| Wordpress.Comments.id | Number | id | 
| Wordpress.Comments.date_gmt | String | Date GMT | 
| Wordpress.Comments.author_name | String | Author name | 

### wordpress-delete-comment
***
Delete a comment


#### Base Command

`wordpress-delete-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Tag ID. | Required | 
| force | Whether to bypass Trash and force deletion (default is false). Possible values are: true, false. Default is false. | Optional | 
| password | The password for the parent post of the comment (if the post is password protected). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Comments.post | String | Post ID | 
| Wordpress.Comments.meta | String | Metadata | 
| Wordpress.Comments.parent | Number | Parent ID | 
| Wordpress.Comments.author | Number | Author ID | 
| Wordpress.Comments.date | String | Date | 
| Wordpress.Comments.status | String | Status | 
| Wordpress.Comments.author_avatar_urls | List | Author svatars | 
| Wordpress.Comments.content.rendered | String | Rendered content | 
| Wordpress.Comments._links | List | Links | 
| Wordpress.Comments.type | String | Type | 
| Wordpress.Comments.link | String | Link | 
| Wordpress.Comments.author_url | String | Author URL | 
| Wordpress.Comments.id | Number | id | 
| Wordpress.Comments.date_gmt | String | Date GMT | 
| Wordpress.Comments.author_name | String | Author name | 

### wordpress-list-users
***
List users


#### Base Command

`wordpress-list-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context | Scope under which the request is made; determines fields present in response (default is view). Possible values are: view, edit, embed. Default is view. | Optional | 
| page | Current page of the collection (defaults is 1). Default is 1. | Optional | 
| per_page | Maximum number of items to be returned in result set (default is 10). | Optional | 
| search | Limit results to those matching a string. | Optional | 
| exclude | Ensure result set excludes specific IDs. | Optional | 
| include | Limit result set to specific IDs. | Optional | 
| offset | Offset the result set by a specific number of items. | Optional | 
| order | Order sort attribute ascending or descending (default is desc). Possible values are: desc, asc. Default is desc. | Optional | 
| orderby | Sort collection by object attribute (default is name). Possible values are: id, include, name, registered_date, slug, include_slugs, email, url. Default is name. | Optional | 
| slug | Limit result set to users with one or more specific slugs. | Optional | 
| roles | Limit result set to users matching at least one specific role provided (CSV). | Optional | 
| who | Limit result set to users who are considered authors. Possible values are: authors. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Users.meta | List | Metadata | 
| Wordpress.Users.avatar_urls | List | Avatar URLs | 
| Wordpress.Users.name | String | Name | 
| Wordpress.Users.slug | String | Slug | 
| Wordpress.Users.url | String | URL | 
| Wordpress.Users._links | List | Links | 
| Wordpress.Users.link | String | Link | 
| Wordpress.Users.id | Number | User ID | 
| Wordpress.Users.description | String | Description | 

### wordpress-get-user
***
Retrieve a user.


#### Base Command

`wordpress-get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID. | Required | 
| context | Scope under which the request is made; determines fields present in response (default is view). Possible values are: view, edit, embed. Default is view. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Users.meta | List | Metadata | 
| Wordpress.Users.avatar_urls | List | Avatar URLs | 
| Wordpress.Users.name | String | Name | 
| Wordpress.Users.slug | String | Slug | 
| Wordpress.Users.url | String | URL | 
| Wordpress.Users._links | List | Links | 
| Wordpress.Users.link | String | Link | 
| Wordpress.Users.id | Number | User ID | 
| Wordpress.Users.description | String | Description | 

### wordpress-create-user
***
Create a user


#### Base Command

`wordpress-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| locale | Locale for the user (default is en_US). Default is en_US. | Optional | 
| username | Login name for the user. | Required | 
| name | Display name for the user. | Optional | 
| first_name | First name for the user. | Optional | 
| last_name | Last name for the user. | Optional | 
| email | The email address for the user. | Required | 
| url | URL of the user. | Optional | 
| description | Description of the user. | Optional | 
| nickname | The nickname for the user. | Optional | 
| slug | An alphanumeric identifier for the user. | Optional | 
| roles | Roles assigned to the user (CSV). | Optional | 
| password | Password for the user. | Required | 
| meta | Meta fields (JSON dict). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Users.meta | List | Metadata | 
| Wordpress.Users.avatar_urls | List | Avatar URLs | 
| Wordpress.Users.name | String | Name | 
| Wordpress.Users.slug | String | Slug | 
| Wordpress.Users.url | String | URL | 
| Wordpress.Users._links | List | Links | 
| Wordpress.Users.link | String | Link | 
| Wordpress.Users.id | Number | User ID | 
| Wordpress.Users.description | String | Description | 

### wordpress-update-user
***
Update a user


#### Base Command

`wordpress-update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID. | Required | 
| locale | Locale for the user (default is en_US). Default is en_US. | Optional | 
| username | Login name for the user. | Optional | 
| name | Display name for the user. | Optional | 
| first_name | First name for the user. | Optional | 
| last_name | Last name for the user. | Optional | 
| email | The email address for the user. | Optional | 
| url | URL of the user. | Optional | 
| description | Description of the user. | Optional | 
| nickname | The nickname for the user. | Optional | 
| slug | An alphanumeric identifier for the user. | Optional | 
| roles | Roles assigned to the user (CSV). | Optional | 
| password | Password for the user. | Optional | 
| meta | Meta fields (JSON dict). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wordpress.Users.meta | List | Metadata | 
| Wordpress.Users.avatar_urls | List | Avatar URLs | 
| Wordpress.Users.name | String | Name | 
| Wordpress.Users.slug | String | Slug | 
| Wordpress.Users.url | String | URL | 
| Wordpress.Users._links | List | Links | 
| Wordpress.Users.link | String | Link | 
| Wordpress.Users.id | Number | User ID | 
| Wordpress.Users.description | String | Description | 

### wordpress-delete-user
***
Delete a user


#### Base Command

`wordpress-delete-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID. | Required | 
| reassign | Reassign the deleted users posts and links to this user ID. | Required | 


#### Context Output

There is no context output for this command.