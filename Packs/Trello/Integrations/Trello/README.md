Interact with the Trello task manager
This integration was integrated and tested with version 1.0.0 of Trello
## Configure Trello in Cortex

First, retrieve an API key from the trello API page, by following [this link](https://trello.com/app-key)
For more information, see the following [Trello documentation](https://developer.atlassian.com/cloud/trello/guides/rest-api/api-introduction/)


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://example.net) |  | True |
| Fetch incidents |  | False |
| Use system proxy settings |  | False |
| Default and Fetch Board ID | ID of Trello board used both to fetch incidents and as the default for all integration commands. | False |
| API Key |  | False |
| List to Fetch Incidents from | Optional - If specified, incidents will only be fetched when cards are created in this specific list. Use trello-list-lists command to display IDs of available lists in Board. | False |
| Incident type |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### trello-list-boards
***
List the boards available to the provided API Key


#### Base Command

`trello-list-boards`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trello.Boards.Id | Unknown | The board ID | 
| Trello.Boards.Name | Unknown | Board name | 
| Trello.Boards.Closed | Unknown | Bool - True if board closed. | 
| Trello.Boards.DateLastActivity | Unknown | The last time this board was updated. | 


#### Command Example
```!trello-list-boards```

#### Context Example
```json
{
    "Trello": {
        "Boards": [
            {
                "Closed": false,
                "DateLastActivity": "2021-03-24T04:38:20.193Z",
                "Id": "5f84cf4db437823603f98ad0",
                "Name": "Current Tasks",
                "Url": "https://trello.com/b/lGTEPWR6/current-tasks"
            },
            {
                "Closed": false,
                "DateLastActivity": "2021-03-29T05:18:09.118Z",
                "Id": "602f2f91cc8a4e23e393556a",
                "Name": "Devel",
                "Url": "https://trello.com/b/RqO8rfpZ/devel"
            },
            {
                "Closed": false,
                "DateLastActivity": "2020-12-06T23:15:15.945Z",
                "Id": "5ea81000966eeb7e86362b35",
                "Name": "MOXSOAR",
                "Url": "https://trello.com/b/L6eBwR31/moxsoar"
            },
            {
                "Closed": false,
                "DateLastActivity": "2021-03-29T00:28:52.283Z",
                "Id": "5f0fc9c1e1ca6e3eef34913d",
                "Name": "XSOAR",
                "Url": "https://trello.com/b/WGwDIdS4/xsoar"
            }
        ]
    }
}
```

#### Human Readable Output

>### Trello Boards
>|id|name|dateLastActivity|
>|---|---|---|
>| 5f84cf4db437823603f98ad0 | Current Tasks | 2021-03-24T04:38:20.193Z |
>| 602f2f91cc8a4e23e393556a | Devel | 2021-03-29T05:18:09.118Z |
>| 5ea81000966eeb7e86362b35 | MOXSOAR | 2020-12-06T23:15:15.945Z |
>| 5f0fc9c1e1ca6e3eef34913d | XSOAR | 2021-03-29T00:28:52.283Z |


### trello-list-lists
***
List all the lists associated with the trello board.


#### Base Command

`trello-list-lists`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| board_id | Optional - the ID of  the board to query, if not provided will use configured . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trello.Lists.Id | Unknown | List ID | 
| Trello.Lists.Name | Unknown | List Name | 
| Trello.Lists.Closed | Unknown | Bool - True if list is closed | 
| Trello.Lists.IdBoard | Unknown | ID Of the board this list belongs to | 


#### Command Example
```!trello-list-lists```

#### Context Example
```json
{
    "Trello": {
        "Lists": [
            {
                "Closed": false,
                "Id": "606120363e1eb362adcfdb47",
                "IdBoard": "602f2f91cc8a4e23e393556a",
                "Name": "New Tasks"
            },
            {
                "Closed": false,
                "Id": "605d2a706398646de27a1f8f",
                "IdBoard": "602f2f91cc8a4e23e393556a",
                "Name": "Created by XSOAR"
            },
            {
                "Closed": false,
                "Id": "603c6dcfe6f2ef24e161d31f",
                "IdBoard": "602f2f91cc8a4e23e393556a",
                "Name": "Xsoar to Investigate"
            },
            {
                "Closed": false,
                "Id": "605ac66f9f37c20f9f3205d9",
                "IdBoard": "602f2f91cc8a4e23e393556a",
                "Name": "Completed List"
            }
        ]
    }
}
```

#### Human Readable Output

>### Trello Lists
>|closed|id|idBoard|name|pos|softLimit|subscribed|
>|---|---|---|---|---|---|---|
>| false | 606120363e1eb362adcfdb47 | 602f2f91cc8a4e23e393556a | New Tasks | 65535.5 |  | false |
>| false | 605d2a706398646de27a1f8f | 602f2f91cc8a4e23e393556a | Created by XSOAR | 98303.25 |  | false |
>| false | 603c6dcfe6f2ef24e161d31f | 602f2f91cc8a4e23e393556a | Xsoar to Investigate | 131071 |  | false |
>| false | 605ac66f9f37c20f9f3205d9 | 602f2f91cc8a4e23e393556a | Completed List | 196607 |  | false |


### trello-create-card
***
Create a new card.


#### Base Command

`trello-create-card`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Card name. | Required | 
| desc | Card Description - Markdown Compatible. | Optional | 
| list_id | ID of list to create card within. | Required | 
| idLabels | CSV list of Labels (by ID) to add to the card. Use trello-list-labels command to display. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trello.CreatedCard.Id | Unknown | ID of created card | 
| Trello.CreatedCard.Name | Unknown | Name of created card | 
| Trello.CreatedCard.Url | Unknown | URL Of created card | 
| Trello.CreatedCard.IdList | Unknown | ID of list this card belongs to | 


#### Command Example
``` ```

#### Human Readable Output



### trello-update-card
***
Update an existing card


#### Base Command

`trello-update-card`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| card_id | ID of card to be updated. | Required | 
| closed | If true, archives the card. Possible values are: true, false. | Optional | 
| idLabels | CSV Of Trello Label IDs to add to card. | Optional | 
| idList | ID Of list to move card to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trello.UpdatedCard.Id | Unknown | ID of Updated Card | 
| Trello.UpdatedCard.Name | Unknown | Name of updated card | 


#### Command Example
``` ```

#### Human Readable Output



### trello-delete-card
***
Delete a card


#### Base Command

`trello-delete-card`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| card_id | ID of card to delete. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### trello-list-actions
***
List all actions on a board, such as card updates, additions, and deletes.


#### Base Command

`trello-list-actions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| board_id | Optional - the ID of  the board to query, if not provided will use configured . | Optional | 
| filter | CSV of action types used to filter response. Possible values are: , acceptEnterpriseJoinRequest<br/>, addAttachmentToCard<br/>, addChecklistToCard<br/>, addLabelToCard<br/>, addMemberToBoard<br/>, addMemberToCard<br/>, addMemberToOrganization<br/>, addOrganizationToEnterprise<br/>, addToEnterprisePluginWhitelist<br/>, addToOrganizationBoard<br/>, commentCard<br/>, convertToCardFromCheckItem<br/>, copyBoard<br/>, copyCard<br/>, copyChecklist<br/>, createLabel<br/>, copyCommentCard<br/>, createBoard<br/>, createBoardInvitation<br/>, createBoardPreference<br/>, createCard<br/>, createList<br/>, createOrganization<br/>, createOrganizationInvitation<br/>, deleteAttachmentFromCard<br/>, deleteBoardInvitation<br/>, deleteCard<br/>, deleteCheckItem<br/>, deleteLabel<br/>, deleteOrganizationInvitation<br/>, disableEnterprisePluginWhitelist<br/>, disablePlugin<br/>, disablePowerUp<br/>, emailCard<br/>, enableEnterprisePluginWhitelist<br/>, enablePlugin<br/>, enablePowerUp<br/>, makeAdminOfBoard<br/>, makeAdminOfOrganization<br/>, makeNormalMemberOfBoard<br/>, makeNormalMemberOfOrganization<br/>, makeObserverOfBoard<br/>, memberJoinedTrello<br/>, moveCardFromBoard<br/>, moveCardToBoard<br/>, moveListFromBoard<br/>, moveListToBoard<br/>, removeAdminFromBoard (Deprecated in favor of makeNormalMemberOfBoard) removeAdminFromOrganization (Deprecated in favor of - makeNormalMemberOfOrganization)<br/>, removeChecklistFromCard<br/>, removeFromEnterprisePluginWhitelist<br/>, removeFromOrganizationBoard<br/>, removeLabelFromCard<br/>, removeMemberFromBoard<br/>, removeMemberFromCard<br/>, removeMemberFromOrganization<br/>, removeOrganizationFromEnterprise<br/>, unconfirmedBoardInvitation<br/>, unconfirmedOrganizationInvitation<br/>, updateBoard<br/>, updateCard<br/>, updateCheckItem<br/>, updateCheckItemStateOnCard<br/>, updateChecklist<br/>, updateLabel<br/>, updateList<br/>, updateMember<br/>, updateOrganization, voteOnCard. | Optional | 
| since | First action time. | Optional | 
| before | Last action time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trello.Actions.Id | Unknown | Action ID | 
| Trello.Actions.Type | Unknown | Type of action | 
| Trello.Actions.Date | Date | Date of action | 
| Trello.Actions.ListId | Unknown | List ID - Null if not card or list action | 
| Trello.Actions.CardId | Unknown | Card ID - Null if not card action | 
| Trello.Actions.BoardId | Unknown | Board ID | 


#### Command Example
```!trello-list-actions filter="createCard" since="2021-03-29T00:53:21.972Z"```

#### Context Example
```json
{
    "Trello": {
        "Actions": [
            {
                "BoardId": "602f2f91cc8a4e23e393556a",
                "CardId": "606163113a492b52f69c40de",
                "Date": "2021-03-29T05:18:09.138Z",
                "Id": "606163113a492b52f69c40df",
                "ListId": "605d2a706398646de27a1f8f",
                "Type": "createCard"
            },
            {
                "BoardId": "602f2f91cc8a4e23e393556a",
                "CardId": "6061628bedda298c34aa588d",
                "Date": "2021-03-29T05:15:55.706Z",
                "Id": "6061628bedda298c34aa588e",
                "ListId": "605d2a706398646de27a1f8f",
                "Type": "createCard"
            }
        ]
    }
}
```

#### Human Readable Output

>### Trello Actions
>|id|type|date|
>|---|---|---|
>| 606163113a492b52f69c40df | createCard | 2021-03-29T05:18:09.138Z |
>| 6061628bedda298c34aa588e | createCard | 2021-03-29T05:15:55.706Z |


### trello-list-labels
***
List all the labels in a given board


#### Base Command

`trello-list-labels`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| board_id | Optional - Board ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trello.Labels.Id | Unknown | Label ID | 
| Trello.Labels.Name | Unknown | Label Name | 
| Trello.Labels.Color | Unknown | Label Color | 


#### Command Example
```!trello-list-labels```

#### Context Example
```json
{
    "Trello": {
        "Labels": [
            {
                "Color": "green",
                "Id": "60596b0b080907067c65c0ee",
                "Name": "Low"
            },
            {
                "Color": "green",
                "Id": "603c6bd95984232d2a060953",
                "Name": "test-xsoar-label"
            },
            {
                "Color": "pink",
                "Id": "6059585c1b00040da553cd77",
                "Name": "LabelFromXsoar"
            },
            {
                "Color": "orange",
                "Id": "605973a683fc7129761f000b",
                "Name": "High"
            },
            {
                "Color": "red",
                "Id": "602f2f9186c6bc9cc5d3d1d1",
                "Name": ""
            },
            {
                "Color": "yellow",
                "Id": "60596d0a7dc72638aea5ef8d",
                "Name": "Medium"
            },
            {
                "Color": "orange",
                "Id": "602f2f9186c6bc9cc5d3d1d0",
                "Name": ""
            },
            {
                "Color": "green",
                "Id": "602f2f9186c6bc9cc5d3d1cb",
                "Name": ""
            },
            {
                "Color": "purple",
                "Id": "602f2f9186c6bc9cc5d3d1d4",
                "Name": ""
            },
            {
                "Color": "blue",
                "Id": "602f2f9186c6bc9cc5d3d1d6",
                "Name": ""
            },
            {
                "Color": "yellow",
                "Id": "602f2f9186c6bc9cc5d3d1ce",
                "Name": ""
            },
            {
                "Color": "green",
                "Id": "6059493cd83e275095800912",
                "Name": "Testlabel"
            },
            {
                "Color": null,
                "Id": "606162c31caee583b35a0772",
                "Name": "Test label"
            }
        ]
    }
}
```

#### Human Readable Output

>### Trello Labels
>|color|id|idBoard|name|
>|---|---|---|---|
>| green | 60596b0b080907067c65c0ee | 602f2f91cc8a4e23e393556a | Low |
>| green | 603c6bd95984232d2a060953 | 602f2f91cc8a4e23e393556a | test-xsoar-label |
>| pink | 6059585c1b00040da553cd77 | 602f2f91cc8a4e23e393556a | LabelFromXsoar |
>| orange | 605973a683fc7129761f000b | 602f2f91cc8a4e23e393556a | High |
>| red | 602f2f9186c6bc9cc5d3d1d1 | 602f2f91cc8a4e23e393556a |  |
>| yellow | 60596d0a7dc72638aea5ef8d | 602f2f91cc8a4e23e393556a | Medium |
>| orange | 602f2f9186c6bc9cc5d3d1d0 | 602f2f91cc8a4e23e393556a |  |
>| green | 602f2f9186c6bc9cc5d3d1cb | 602f2f91cc8a4e23e393556a |  |
>| purple | 602f2f9186c6bc9cc5d3d1d4 | 602f2f91cc8a4e23e393556a |  |
>| blue | 602f2f9186c6bc9cc5d3d1d6 | 602f2f91cc8a4e23e393556a |  |
>| yellow | 602f2f9186c6bc9cc5d3d1ce | 602f2f91cc8a4e23e393556a |  |
>| green | 6059493cd83e275095800912 | 602f2f91cc8a4e23e393556a | Testlabel |
>|  | 606162c31caee583b35a0772 | 602f2f91cc8a4e23e393556a | Test label |


### trello-create-label
***
Create a new trello label


#### Base Command

`trello-create-label`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| board_id | Optional - Board ID. | Optional | 
| name | Name of Label. | Required | 
| color | Label Color. Possible values are: yellow, purple, blue, red, green, orange, black, sky, pink, lime. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trello.CreatedLabel.Id | Unknown | ID Of created label | 
| Trello.CreatedLabel.Name | Unknown | Name of created label | 


#### Command Example
``` ```

#### Human Readable Output



### trello-add-comment
***
Add a comment to a Trello card


#### Base Command

`trello-add-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | Comment to add. | Required | 
| card_id | Card to add comment to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trello.AddedComment.Id | Unknown | ID Of comment action | 
| Trello.AddedComment.Date | Unknown | Date of comment | 


#### Command Example
``` ```

#### Human Readable Output



### trello-list-cards
***
List all the trello cards


#### Base Command

`trello-list-cards`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | ID of list containing cards. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trello.Cards.Id | Unknown | Card ID | 
| Trello.Cards.Name | Unknown | Card Name | 
| Trello.Cards.IdList | Unknown | ID of parent list | 
| Trello.Cards.Due | Date | Due date of card | 
| Trello.Cards.Labels | Unknown | List of labels associated with card | 
| Trello.Cards.Desc | Unknown | Card description | 
| Trello.Cards.Start | Date | Card Start date | 
| Trello.Cards.Labels.id | Unknown | Label ID | 


#### Command Example
```!trello-list-cards list_id=605d2a706398646de27a1f8f```

#### Context Example
```json
{
    "Trello": {
        "Cards": [
            {
                "Desc": "",
                "Due": null,
                "Id": "6061628bedda298c34aa588d",
                "IdList": "605d2a706398646de27a1f8f",
                "Labels": [],
                "Name": "Temp card",
                "Start": null,
                "Url": "https://trello.com/c/oq5kliob/99-temp-card"
            },
            {
                "Desc": "",
                "Due": null,
                "Id": "606163113a492b52f69c40de",
                "IdList": "605d2a706398646de27a1f8f",
                "Labels": [],
                "Name": "This is a test card from XSOAR!",
                "Start": null,
                "Url": "https://trello.com/c/63F5dXGw/100-this-is-a-test-card-from-xsoar"
            }
        ]
    }
}
```

#### Human Readable Output

>### Trello Cards
>|id|name|url|
>|---|---|---|
>| 6061628bedda298c34aa588d | Temp card | https://trello.com/c/oq5kliob/99-temp-card |
>| 606163113a492b52f69c40de | This is a test card from XSOAR! | https://trello.com/c/63F5dXGw/100-this-is-a-test-card-from-xsoar |