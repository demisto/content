Google Sheets is a spreadsheet program that is part of the free web-based Google applications to create and format spreadsheets. Use this integration to create and modify spreadsheets.
This integration was integrated and tested with version 4 of Google Sheets API.

## Configure Google Sheets in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Service Account Key | A service account key from Google. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Email - Associate to Google Drive | Used to impersonate a Google workspace user, so the spreadsheets is created in the associated Google Drive and is easily accessible from a UI. This parameter is used during the authentication process.<br/> | False |


## Known limitations
You can only delete a spreadsheet with the Google Drive integrations. 

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### google-sheets-spreadsheet-create
***
Create a new spreadsheet.


#### Base Command

`google-sheets-spreadsheet-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The title of the spreadsheet to create. | Required | 
| locale | The locale of the spreadsheet to create. Default is en. | Optional | 
| cell_format_type | The type of the cell format of the spreadsheet to create. Possible values are: NUMBER, TEXT, PERCENT, CURRENCY, DATE, TIME, DATE_TIME, SCIENTIFIC. Default is TEXT. | Optional | 
| cell_format_backgroundColor | A comma-separated list of background colors in the following order - red,green,blue,alpha. All values must be between 0-1. If chosen, you must specify all fields. | Optional | 
| cell_format_textformat_font_size | Cell font size in the spreadsheet to create. Default is 11. | Optional | 
| cell_format_textformat_text_direction | Cell text direction in the spreadsheet to create. Possible values are: LEFT_TO_RIGHT, RIGHT_TO_LEFT. Default is LEFT_TO_RIGHT. | Optional | 
| sheet_title | Sets the title of the first sheet in the spreadsheet to create. | Required | 
| sheet_type | Sets the type of the first sheet in the spreadsheet to create. Possible values are: GRID, OBJECT, DATASOURCE. Default is GRID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSheets.Spreadsheet.properties.title | Unknown | Spreadsheet title. | 
| GoogleSheets.Spreadsheet.spreadsheetId | Unknown | Spreadsheet ID. | 

#### Command example
```!google-sheets-spreadsheet-create title=NewSpreadsheet sheet_title=newSheetTitle cell_format_backgroundColor=1,1,1,1 cell_format_textformat_font_size=11 cell_format_type=TEXT```
#### Context Example
```json
{
    "GoogleSheets": {
        "Spreadsheet": {
            "properties": {
                "autoRecalc": "ON_CHANGE",
                "defaultFormat": {
                    "backgroundColor": {
                        "blue": 1,
                        "green": 1,
                        "red": 1
                    },
                    "backgroundColorStyle": {
                        "rgbColor": {
                            "blue": 1,
                            "green": 1,
                            "red": 1
                        }
                    },
                    "padding": {
                        "bottom": 2,
                        "left": 3,
                        "right": 3,
                        "top": 2
                    },
                    "textFormat": {
                        "bold": false,
                        "fontFamily": "arial,sans,sans-serif",
                        "fontSize": 10,
                        "foregroundColor": {},
                        "foregroundColorStyle": {
                            "rgbColor": {}
                        },
                        "italic": false,
                        "strikethrough": false,
                        "underline": false
                    },
                    "verticalAlignment": "BOTTOM",
                    "wrapStrategy": "OVERFLOW_CELL"
                },
                "locale": "en",
                "spreadsheetTheme": {
                    "primaryFontFamily": "Arial",
                    "themeColors": [
                        {
                            "color": {
                                "rgbColor": {}
                            },
                            "colorType": "TEXT"
                        },
                        {
                            "color": {
                                "rgbColor": {
                                    "blue": 1,
                                    "green": 1,
                                    "red": 1
                                }
                            },
                            "colorType": "BACKGROUND"
                        },
                        {
                            "color": {
                                "rgbColor": {
                                    "blue": 0.95686275,
                                    "green": 0.52156866,
                                    "red": 0.25882354
                                }
                            },
                            "colorType": "ACCENT1"
                        },
                        {
                            "color": {
                                "rgbColor": {
                                    "blue": 0.20784314,
                                    "green": 0.2627451,
                                    "red": 0.91764706
                                }
                            },
                            "colorType": "ACCENT2"
                        },
                        {
                            "color": {
                                "rgbColor": {
                                    "blue": 0.015686275,
                                    "green": 0.7372549,
                                    "red": 0.9843137
                                }
                            },
                            "colorType": "ACCENT3"
                        },
                        {
                            "color": {
                                "rgbColor": {
                                    "blue": 0.3254902,
                                    "green": 0.65882355,
                                    "red": 0.20392157
                                }
                            },
                            "colorType": "ACCENT4"
                        },
                        {
                            "color": {
                                "rgbColor": {
                                    "blue": 0.003921569,
                                    "green": 0.42745098,
                                    "red": 1
                                }
                            },
                            "colorType": "ACCENT5"
                        },
                        {
                            "color": {
                                "rgbColor": {
                                    "blue": 0.7764706,
                                    "green": 0.7411765,
                                    "red": 0.27450982
                                }
                            },
                            "colorType": "ACCENT6"
                        },
                        {
                            "color": {
                                "rgbColor": {
                                    "blue": 0.8,
                                    "green": 0.33333334,
                                    "red": 0.06666667
                                }
                            },
                            "colorType": "LINK"
                        }
                    ]
                },
                "timeZone": "Etc/GMT",
                "title": "NewSpreadsheet"
            },
            "sheets": [
                {
                    "properties": {
                        "gridProperties": {
                            "columnCount": 26,
                            "rowCount": 1000
                        },
                        "index": 0,
                        "sheetId": 387199274,
                        "sheetType": "GRID",
                        "title": "newSheetTitle"
                    }
                }
            ],
            "spreadsheetId": "1yRsYph-litbiP4opkjzWwVzJ3ZyOybYL5D2f840-uog",
            "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/1yRsYph-litbiP4opkjzWwVzJ3ZyOybYL5D2f840-uog/edit?ouid=103020731686044834269"
        }
    }
}
```

#### Human Readable Output

>### Success
>|spreadsheet Id|spreadsheet title|
>|---|---|
>| 1yRsYph-litbiP4opkjzWwVzJ3ZyOybYL5D2f840-uog | NewSpreadsheet |


### google-sheets-spreadsheet-get
***
Returns the spreadsheet of the given ID. If include_grid_data is set to true and no ranges given, will defaultly return the first 500 rows and 20 columns of the first sheet.


#### Base Command

`google-sheets-spreadsheet-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | ID of the spreadsheet to get. | Required | 
| include_grid_data | True if grid data should be returned. This parameter is ignored if a field mask was set in the request. Possible values are: true, false. Default is false. | Optional | 
| ranges | Works only with include_grid_data = True. The ranges to retrieve from the spreadsheet. Ranges are specified using A1 notation. For example, Sheet1!A1:D5. For further explanation and examples, see https://developers.google.com/sheets/api/guides/concepts#expandable-1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSheets.Spreadsheet.spreadsheetTitle | Unknown | Spreadsheet title. | 
| GoogleSheets.Spreadsheet.spreadsheetId | Unknown | SpreadSheet ID. | 
| GoogleSheets.Spreadsheet.spreadsheetUrl | Unknown | Spreadsheet URL. | 
| GoogleSheets.Spreadsheet.sheets.title | Unknown | Sheet title. | 
| GoogleSheets.Spreadsheet.sheets.index | Unknown | Sheet index. | 
| GoogleSheets.Spreadsheet.sheets.sheetId | Unknown | Sheet ID. | 
| GoogleSheets.Spreadsheet.sheets.gridProperties | Unknown | Sheet grid properties. | 
| GoogleSheets.Spreadsheet.sheets.rowData | Unknown | Sheet row data. | 

#### Command example
```!google-sheets-spreadsheet-get spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk```
#### Context Example
```json
{
    "GoogleSheets": {
        "Spreadsheet": {
            "sheets": [
                {
                    "gridProperties": {
                        "columnCount": 26,
                        "rowCount": 1000
                    },
                    "index": 0,
                    "rowData": [],
                    "sheetId": 0,
                    "title": "Sheet1"
                },
                {
                    "gridProperties": {
                        "columnCount": 26,
                        "rowCount": 1000
                    },
                    "index": 1,
                    "rowData": [],
                    "sheetId": 3,
                    "title": "newSheetTitle"
                }
            ],
            "spreadsheetId": "1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk",
            "spreadsheetTitle": "NewSpreadsheet",
            "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk/edit?ouid=103020731686044834269"
        }
    }
}
```

#### Human Readable Output

>### Success
>### NewSpreadsheet
>|spreadsheet Id|spreadsheet url|
>|---|---|
>| 1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk | https:<span>//</span>docs.google.com/spreadsheets/d/1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk/edit?ouid=103020731686044834269 |
>
>### Content
>|SheetId|Sheet title|
>|---|---|
>| 0 | Sheet1 |
>| 3 | newSheetTitle |


#### Command example
```!google-sheets-spreadsheet-get spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk,1meYzOYg7oCK7zYGBJu_hw3iQ_oEvJ6EecCBOV8ZQvFA```
#### Human Readable Output

>### Success
>
>### NewSpreadsheet
>|spreadsheet Id|spreadsheet url|
>|---|---|
>| 1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk | https:<span>//</span>docs.google.com/spreadsheets/d/1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk/edit?ouid=103020731686044834269 |
>
>### Content
>|SheetId|Sheet title|
>|---|---|
>| 0 | Sheet1 |
>| 3 | newSheetTitle |
>---
>### SpreadSheet2
>|spreadsheet Id|spreadsheet url|
>|---|---|
>| 1meYzOYg7oCK7zYGBJu_hw3iQ_oEvJ6EecCBOV8ZQvFA | https:<span>//</span>docs.google.com/spreadsheets/d/1meYzOYg7oCK7zYGBJu_hw3iQ_oEvJ6EecCBOV8ZQvFA/edit?ouid=103020731686044834269 |
>
>### Content
>|SheetId|Sheet title|
>|---|---|
>| 1144878200 | Sheet1 |
>---


#### Command example
```!google-sheets-spreadsheet-get spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk include_grid_data=true ranges=newSheetTitle!A1:F10```
#### Context Example
```json
{
    "GoogleSheets": {
        "Spreadsheet": {
            "sheets": [
                {
                    "gridProperties": {
                        "columnCount": 26,
                        "rowCount": 1000
                    },
                    "index": 1,
                    "rowData": [
                        {
                            "values": [
                                "a",
                                "b",
                                "c",
                                "d",
                                "!"
                            ]
                        },
                        {
                            "values": []
                        },
                        {
                            "values": [
                                "1",
                                "2",
                                "3",
                                "4",
                                "5"
                            ]
                        },
                        {
                            "values": [
                                "a",
                                "b",
                                "c",
                                "d",
                                "!"
                            ]
                        },
                        {
                            "values": [
                                "a",
                                "b",
                                "c",
                                "d",
                                "!"
                            ]
                        }
                    ],
                    "sheetId": 3,
                    "title": "newSheetTitle"
                }
            ],
            "spreadsheetId": "1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk",
            "spreadsheetTitle": "NewSpreadsheet",
            "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk/edit?ouid=103020731686044834269"
        }
    }
}
```

#### Human Readable Output

>### Success
>|spreadsheet Id|spreadsheet url|
>|---|---|
>| 1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk | https:<span>//</span>docs.google.com/spreadsheets/d/1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk/edit?ouid=103020731686044834269 |
>
>### ***Name: newSheetTitle     Sheet Id: 3***
>|col 0 |col 1 |col 2 |col 3 |col 4 |
>|-------------- | -------------- | -------------- | -------------- | -------------- | 
>|a |b |c |d |! |
>|
>|1 |2 |3 |4 |5 |
>|a |b |c |d |! |
>|a |b |c |d |! |


### google-sheets-sheet-create
***
Adds a new sheet. When a sheet is added at a given index, all subsequent sheet indexes are incremented.


#### Base Command

`google-sheets-sheet-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | Spreadsheet ID in which to create a new sheet. | Required | 
| echo_spreadsheet | Include the spreadsheet in the response. Possible values are: true, false. Default is false. | Optional | 
| sheet_title | Sheet title to create. | Required | 
| sheet_index | The index of the sheet within the spreadsheet. | Optional | 
| sheet_type | Sheet type to create. Possible values are: GRID, OBJECT, DATA_SOURCE. Default is GRID. | Optional | 
| right_to_left | True if the sheet is a right_to_left sheet instead of a left_to_right sheet. Possible values are: false, true. | Optional | 
| tab_color | A comma-separated list of the color of the tab in the UI in the following order - red,green,blue,alpha. All values must be between 0-1. If chosen, you must specify all fields. | Optional | 
| hidden | True if the sheet is hidden in the UI. False if it is visible. | Optional | 
| sheet_id | The ID of the sheet to create. (Needs to be unique. If not specified, the sheet ID will be generated by Google Sheets. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSheets.Spreadsheet.updatedSpreadsheet.properties.title | Unknown | Spreadsheet title. | 
| GoogleSheets.Spreadsheet.spreadsheetId | Unknown | Spreadsheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.spreadsheetUrl | Unknown | Spreadsheet URL. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.sheetId | String | Sheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.title | String | Sheet title. | 

#### Command example
```!google-sheets-sheet-create spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk sheet_title=newSheetTitle sheet_id=3 sheet_index=2 tab_color=1,1,1,1 right_to_left=false```
#### Human Readable Output

>### Success


### google-sheets-sheet-duplicate
***
Duplicates the contents of a sheet.


#### Base Command

`google-sheets-sheet-duplicate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | Spreadsheet ID from which to copy a sheet. | Required | 
| echo_spreadsheet | True to add the spreadsheet to the output. Possible values are: true, false. Default is false. | Optional | 
| source_sheet_id | The ID of the sheet to copy. | Required | 
| new_sheet_index | If set, the ID of the new sheet. If not set, an ID is chosen. If set, the ID must not conflict with any existing sheet ID and it must be non-negative number. | Optional | 
| new_sheet_name | The name of the new sheet. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSheets.Spreadsheet.updatedSpreadsheet.properties.title | String | Spreadsheet title. | 
| GoogleSheets.Spreadsheet.spreadsheetId | String | Spreadsheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.spreadsheetUrl | Unknown | Spreadsheet URL. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.sheetId | String | Sheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.title | String | Sheet title. | 

#### Command example
```!google-sheets-sheet-duplicate new_sheet_name=duplicated_sheet spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk source_sheet_id=3 echo_spreadsheet=true```
#### Context Example
```json
{
    "GoogleSheets": {
        "Spreadsheet": {
            "replies": [
                {
                    "duplicateSheet": {
                        "properties": {
                            "gridProperties": {
                                "columnCount": 26,
                                "rowCount": 997
                            },
                            "index": 0,
                            "sheetId": 2030116478,
                            "sheetType": "GRID",
                            "tabColor": {
                                "blue": 1,
                                "green": 1,
                                "red": 1
                            },
                            "tabColorStyle": {
                                "rgbColor": {
                                    "blue": 1,
                                    "green": 1,
                                    "red": 1
                                }
                            },
                            "title": "duplicated_sheet"
                        }
                    }
                }
            ],
            "spreadsheetId": "1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk",
            "updatedSpreadsheet": {
                "properties": {
                    "autoRecalc": "ON_CHANGE",
                    "defaultFormat": {
                        "backgroundColor": {
                            "blue": 1,
                            "green": 1,
                            "red": 1
                        },
                        "backgroundColorStyle": {
                            "rgbColor": {
                                "blue": 1,
                                "green": 1,
                                "red": 1
                            }
                        },
                        "padding": {
                            "bottom": 2,
                            "left": 3,
                            "right": 3,
                            "top": 2
                        },
                        "textFormat": {
                            "bold": false,
                            "fontFamily": "arial,sans,sans-serif",
                            "fontSize": 10,
                            "foregroundColor": {},
                            "foregroundColorStyle": {
                                "rgbColor": {}
                            },
                            "italic": false,
                            "strikethrough": false,
                            "underline": false
                        },
                        "verticalAlignment": "BOTTOM",
                        "wrapStrategy": "OVERFLOW_CELL"
                    },
                    "locale": "en",
                    "spreadsheetTheme": {
                        "primaryFontFamily": "Arial",
                        "themeColors": [
                            {
                                "color": {
                                    "rgbColor": {}
                                },
                                "colorType": "TEXT"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 1,
                                        "green": 1,
                                        "red": 1
                                    }
                                },
                                "colorType": "BACKGROUND"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.95686275,
                                        "green": 0.52156866,
                                        "red": 0.25882354
                                    }
                                },
                                "colorType": "ACCENT1"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.20784314,
                                        "green": 0.2627451,
                                        "red": 0.91764706
                                    }
                                },
                                "colorType": "ACCENT2"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.015686275,
                                        "green": 0.7372549,
                                        "red": 0.9843137
                                    }
                                },
                                "colorType": "ACCENT3"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.3254902,
                                        "green": 0.65882355,
                                        "red": 0.20392157
                                    }
                                },
                                "colorType": "ACCENT4"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.003921569,
                                        "green": 0.42745098,
                                        "red": 1
                                    }
                                },
                                "colorType": "ACCENT5"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.7764706,
                                        "green": 0.7411765,
                                        "red": 0.27450982
                                    }
                                },
                                "colorType": "ACCENT6"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.8,
                                        "green": 0.33333334,
                                        "red": 0.06666667
                                    }
                                },
                                "colorType": "LINK"
                            }
                        ]
                    },
                    "timeZone": "Etc/GMT",
                    "title": "NewSpreadsheet"
                },
                "sheets": [
                    {
                        "properties": {
                            "gridProperties": {
                                "columnCount": 26,
                                "rowCount": 997
                            },
                            "index": 0,
                            "sheetId": 2030116478,
                            "sheetType": "GRID",
                            "tabColor": {
                                "blue": 1,
                                "green": 1,
                                "red": 1
                            },
                            "tabColorStyle": {
                                "rgbColor": {
                                    "blue": 1,
                                    "green": 1,
                                    "red": 1
                                }
                            },
                            "title": "duplicated_sheet"
                        }
                    },
                    {
                        "properties": {
                            "gridProperties": {
                                "columnCount": 26,
                                "rowCount": 1000
                            },
                            "index": 1,
                            "sheetId": 0,
                            "sheetType": "GRID",
                            "tabColor": {
                                "blue": 1,
                                "green": 1,
                                "red": 1
                            },
                            "tabColorStyle": {
                                "rgbColor": {
                                    "blue": 1,
                                    "green": 1,
                                    "red": 1
                                }
                            },
                            "title": "Sheet1"
                        }
                    },
                    {
                        "properties": {
                            "gridProperties": {
                                "columnCount": 26,
                                "rowCount": 997
                            },
                            "index": 2,
                            "sheetId": 3,
                            "sheetType": "GRID",
                            "tabColor": {
                                "blue": 1,
                                "green": 1,
                                "red": 1
                            },
                            "tabColorStyle": {
                                "rgbColor": {
                                    "blue": 1,
                                    "green": 1,
                                    "red": 1
                                }
                            },
                            "title": "newSheetTitle"
                        }
                    }
                ],
                "spreadsheetId": "1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk",
                "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk/edit?ouid=103020731686044834269"
            }
        }
    }
}
```

#### Human Readable Output

>### Success
>### NewSpreadsheet
>|spreadsheet Id|spreadsheet url|
>|---|---|
>| 1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk | https:<span>//</span>docs.google.com/spreadsheets/d/1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk/edit?ouid=103020731686044834269 |
>
>### Content
>|SheetId|Sheet title|
>|---|---|
>| 2030116478 | duplicated_sheet |
>| 0 | Sheet1 |
>| 3 | newSheetTitle |


### google-sheets-sheet-copy-to
***
Copies a single sheet from a spreadsheet to another spreadsheet.


#### Base Command

`google-sheets-sheet-copy-to`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_spreadsheet_id | Spreadsheet ID to copy from. | Required | 
| source_sheet_id | The ID of the sheet to copy. | Required | 
| destination_spreadsheet_id | The ID of the spreadsheet to copy the sheet to. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!google-sheets-sheet-copy-to source_sheet_id=3 source_spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk destination_spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk```
#### Human Readable Output

>### Success

### google-sheets-sheet-delete
***
Delete a sheet from a spreadsheet by ID.


#### Base Command

`google-sheets-sheet-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | Spreadsheet from which to delete sheet. | Required | 
| echo_spreadsheet | True to add the spreadsheet to the output. Possible values are: true, false. Default is false. | Optional | 
| sheet_id | ID of sheet to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSheets.Spreadsheet.updatedSpreadsheet.properties.title | String | Spreadsheet title. | 
| GoogleSheets.Spreadsheet.spreadsheetId | String | Spreadsheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.spreadsheetUrl | Unknown | Spreadsheet URL. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.sheetId | String | Sheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.title | String | Sheet title. | 

#### Command example
```!google-sheets-sheet-delete sheet_id=3 spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk```
#### Human Readable Output

>### Success


### google-sheets-sheet-clear
***
Clears values from a spreadsheet. The caller must specify the spreadsheet ID and range. Only values are cleared. All other properties of the cell (such as formatting, data validation, etc..) are kept.


#### Base Command

`google-sheets-sheet-clear`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | Spreadsheet ID to update. | Required | 
| range | A1 notation or R1C1 notation of the values to clear. A1 notation example, Sheet1!A1:D5. For further explanation and examples, see https://developers.google.com/sheets/api/guides/concepts#expandable-1. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSheets.Spreadsheet.updatedSpreadsheet.properties.title | String | Spreadsheet title. | 
| GoogleSheets.Spreadsheet.spreadsheetId | String | Spreadsheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.spreadsheetUrl | Unknown | Spreadsheet URL. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.sheetId | String | Sheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.title | String | Sheet title. | 

#### Command example
```!google-sheets-sheet-clear spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk range=newSheetTitle!2:2```
#### Human Readable Output

>### Success

#### Command example
```!google-sheets-sheet-clear range=newSheetTitle spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk```
#### Human Readable Output

>### Success

### google-sheets-range-delete
***
Deletes a range of cells, shifting other cells into the deleted area.


#### Base Command

`google-sheets-range-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | Spreadsheet ID. | Required | 
| echo_spreadsheet | True to add the spreadsheet to the output. Possible values are: true, false. Default is false. | Optional | 
| sheet_id | The sheet this range is in. | Required | 
| start_row_index | The start row (inclusive) of the range, or not set if unbounded. | Required | 
| end_row_index | The end row (exclusive) of the range, or not set if unbounded. | Required | 
| start_column_index | The start column (inclusive) of the range, or not set if unbounded. | Required | 
| end_column_index | The end column (exclusive) of the range, or not set if unbounded. | Required | 
| shift_dimension | The dimension from which deleted cells will be replaced with. If ROWS, existing cells will be shifted upward to replace the deleted cells. If COLUMNS, existing cells will be shifted left to replace the deleted cells. Possible values are: ROWS, COLUMNS. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSheets.Spreadsheet.updatedSpreadsheet.properties.title | String | Spreadsheet title. | 
| GoogleSheets.Spreadsheet.spreadsheetId | String | Spreadsheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.spreadsheetUrl | Unknown | Spreadsheet URL. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.sheetId | String | Sheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.title | String | Sheet title. | 

#### Command example
```!google-sheets-range-delete spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk sheet_id=3 shift_dimension=COLUMNS start_row_index=0 end_row_index=2 start_column_index=0 end_column_index=2```
#### Human Readable Output

>### Success


### google-sheets-dimension-delete
***
Deletes the dimensions from the sheet. Note that the indexing starts from 0.


#### Base Command

`google-sheets-dimension-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | Spreadsheet ID. | Required | 
| echo_spreadsheet | True to add the spreadsheet to the output. Possible values are: true, false. Default is false. | Optional | 
| dimension_type | The dimension of the span. Possible values are: ROWS, COLUMNS. | Required | 
| sheet_id | The sheet this span is in. | Required | 
| start_index | The start (inclusive) of the span, or not set if unbounded. | Required | 
| end_index | The end (exclusive) of the span, or not set if unbounded. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSheets.Spreadsheet.updatedSpreadsheet.properties.title | String | Spreadsheet title. | 
| GoogleSheets.Spreadsheet.spreadsheetId | String | Spreadsheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.spreadsheetUrl | Unknown | Spreadsheet URL. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.sheetId | String | Sheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.title | String | Sheet title. | 

#### Command example
```!google-sheets-dimension-delete dimension_type=ROWS sheet_id=3 spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk start_index=0 end_index=3 echo_spreadsheet=true```
#### Context Example
```json
{
    "GoogleSheets": {
        "Spreadsheet": {
            "replies": [
                {}
            ],
            "spreadsheetId": "1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk",
            "updatedSpreadsheet": {
                "properties": {
                    "autoRecalc": "ON_CHANGE",
                    "defaultFormat": {
                        "backgroundColor": {
                            "blue": 1,
                            "green": 1,
                            "red": 1
                        },
                        "backgroundColorStyle": {
                            "rgbColor": {
                                "blue": 1,
                                "green": 1,
                                "red": 1
                            }
                        },
                        "padding": {
                            "bottom": 2,
                            "left": 3,
                            "right": 3,
                            "top": 2
                        },
                        "textFormat": {
                            "bold": false,
                            "fontFamily": "arial,sans,sans-serif",
                            "fontSize": 10,
                            "foregroundColor": {},
                            "foregroundColorStyle": {
                                "rgbColor": {}
                            },
                            "italic": false,
                            "strikethrough": false,
                            "underline": false
                        },
                        "verticalAlignment": "BOTTOM",
                        "wrapStrategy": "OVERFLOW_CELL"
                    },
                    "locale": "en",
                    "spreadsheetTheme": {
                        "primaryFontFamily": "Arial",
                        "themeColors": [
                            {
                                "color": {
                                    "rgbColor": {}
                                },
                                "colorType": "TEXT"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 1,
                                        "green": 1,
                                        "red": 1
                                    }
                                },
                                "colorType": "BACKGROUND"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.95686275,
                                        "green": 0.52156866,
                                        "red": 0.25882354
                                    }
                                },
                                "colorType": "ACCENT1"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.20784314,
                                        "green": 0.2627451,
                                        "red": 0.91764706
                                    }
                                },
                                "colorType": "ACCENT2"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.015686275,
                                        "green": 0.7372549,
                                        "red": 0.9843137
                                    }
                                },
                                "colorType": "ACCENT3"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.3254902,
                                        "green": 0.65882355,
                                        "red": 0.20392157
                                    }
                                },
                                "colorType": "ACCENT4"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.003921569,
                                        "green": 0.42745098,
                                        "red": 1
                                    }
                                },
                                "colorType": "ACCENT5"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.7764706,
                                        "green": 0.7411765,
                                        "red": 0.27450982
                                    }
                                },
                                "colorType": "ACCENT6"
                            },
                            {
                                "color": {
                                    "rgbColor": {
                                        "blue": 0.8,
                                        "green": 0.33333334,
                                        "red": 0.06666667
                                    }
                                },
                                "colorType": "LINK"
                            }
                        ]
                    },
                    "timeZone": "Etc/GMT",
                    "title": "NewSpreadsheet"
                },
                "sheets": [
                    {
                        "properties": {
                            "gridProperties": {
                                "columnCount": 26,
                                "rowCount": 1000
                            },
                            "index": 0,
                            "sheetId": 0,
                            "sheetType": "GRID",
                            "tabColor": {
                                "blue": 1,
                                "green": 1,
                                "red": 1
                            },
                            "tabColorStyle": {
                                "rgbColor": {
                                    "blue": 1,
                                    "green": 1,
                                    "red": 1
                                }
                            },
                            "title": "Sheet1"
                        }
                    },
                    {
                        "properties": {
                            "gridProperties": {
                                "columnCount": 26,
                                "rowCount": 997
                            },
                            "index": 1,
                            "sheetId": 3,
                            "sheetType": "GRID",
                            "tabColor": {
                                "blue": 1,
                                "green": 1,
                                "red": 1
                            },
                            "tabColorStyle": {
                                "rgbColor": {
                                    "blue": 1,
                                    "green": 1,
                                    "red": 1
                                }
                            },
                            "title": "newSheetTitle"
                        }
                    }
                ],
                "spreadsheetId": "1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk",
                "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk/edit?ouid=103020731686044834269"
            }
        }
    }
}
```

#### Human Readable Output

>### Success
>### NewSpreadsheet
>|spreadsheet Id|spreadsheet url|
>|---|---|
>| 1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk | https:<span>//</span>docs.google.com/spreadsheets/d/1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk/edit?ouid=103020731686044834269 |
>
>### Content
>|SheetId|Sheet title|
>|---|---|
>| 0 | Sheet1 |
>| 3 | newSheetTitle |


### google-sheets-data-paste
***
Inserts data into the spreadsheet starting at the specified coordinate.


#### Base Command

`google-sheets-data-paste`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | Spreadsheet ID. | Required | 
| echo_spreadsheet | True to add the spreadsheet to the output. Possible values are: true, false. Default is false. | Optional | 
| sheet_id | The sheet this coordinate is in. | Required | 
| row_index | The row index of the coordinate. | Required | 
| column_index | The column index of the coordinate. | Required | 
| data | The data to insert. If data_kind is delimiter, the delimiter will be ',' and the data should be in the following format cell1, cell2, cell3... If data_kind is html, enter a single value. | Required | 
| data_kind | How to interpret the data inserted in data argument. Possible values are: delimiter, html. | Required | 
| paste_type | The way the data should be pasted. Possible values are: NORMAL, VALUES, FORMAT, NO_BORDERS, FORMULA, DATA_VALIDATION, CONDITIONAL_FORMATTING. Default is NORMAL. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSheets.Spreadsheet.updatedSpreadsheet.properties.title | String | Spreadsheet title. | 
| GoogleSheets.Spreadsheet.spreadsheetId | String | Spreadsheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.spreadsheetUrl | Unknown | Spreadsheet URL. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.sheetId | String | Sheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.title | String | Sheet title. | 

#### Command example
```!google-sheets-data-paste column_index=0 row_index=2 data_kind=delimiter data=1,2,3,4,5 spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk sheet_id=3```
#### Human Readable Output

>### Success


### google-sheets-find-replace
***
Finds and replaces data in cells over a range, sheet, or all sheets.


#### Base Command

`google-sheets-find-replace`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | Spreadsheet ID. | Required | 
| echo_spreadsheet | True to add the spreadsheet to the output. Possible values are: true, false. Default is false. | Optional | 
| find | The value to find. | Required | 
| replacement | The value to use as the replacement. | Required | 
| sheet_id | The sheet to find/replace. | Optional | 
| all_sheets | True to find/replace over all sheets. Possible values are: True, False. | Optional | 
| match_case | True if the search is case sensitive. Possible values are: True, False. | Optional | 
| match_entire_cell | True if the find value should match the entire cell. Possible values are: True, False. | Optional | 
| range_sheet_id | The sheet this range is on. | Optional | 
| range_start_row_Index | The start row (inclusive) of the range, or not set if unbounded. | Optional | 
| range_end_row_Index | The end row (exclusive) of the range, or not set if unbounded. | Optional | 
| range_start_column_Index | The start column (inclusive) of the range, or not set if unbounded. | Optional | 
| range_end_column_Index | The end column (exclusive) of the range, or not set if unbounded. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSheets.Spreadsheet.updatedSpreadsheet.properties.title | String | Spreadsheet title. | 
| GoogleSheets.Spreadsheet.spreadsheetId | String | Spreadsheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.spreadsheetUrl | Unknown | Spreadsheet URL. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.sheetId | String | Sheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.title | String | Sheet title. | 

#### Command example
```!google-sheets-find-replace find=e replacement=! spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk all_sheets=True```
#### Human Readable Output

>### Success


### google-sheets-value-update
***
Sets values in a range of a spreadsheet. The caller must specify the spreadsheet ID, range, and a valueInputOption.


#### Base Command

`google-sheets-value-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | Spreadsheet ID. | Required | 
| range | The A1 notation of the values to update. For example, Sheet1!A1:D5. For further explanation and examples, see https://developers.google.com/sheets/api/guides/concepts#expandable-1. | Required | 
| input_option | Determines how input data should be interpreted. Possible values are: RAW, USER_ENTERED. | Required | 
| major_dimension | The major dimension of the values. Possible values are: ROWS, COLUMNS. | Required | 
| values | The data that was read or to be written. This is an array of arrays. The outer array representing all the data and each inner array representing a major dimension. Each item in the inner array corresponds to one cell. To be entered in the following format - [1,2,3],[4,5,6] where each bracket will be the row or column, and each value inside will correspond to a cell. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!google-sheets-value-update input_option=RAW major_dimension=ROWS range=newSheetTitle!A1:E5 values=[a,b,c,d,e],[a,b,c,d,e],[a,b,c,d,e],[a,b,c,d,e],[a,b,c,d,e] spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk```
#### Human Readable Output

>### Success


### google-sheets-value-append
***
Appends values to a spreadsheet. The input range is used to search for existing data and find a "table" within that range. Values will be appended to the next row of the table, starting with the first column of the table. See the guide (https://developers.google.com/sheets/api/guides/values#appending_values) and sample code (https://developers.google.com/sheets/api/samples/writing#append_values) for specific details of how tables are detected and data is appended. The caller must specify the spreadsheet ID, range, and a valueInputOption. The valueInputOption only controls how the input data will be added to the sheet (column-wise or row-wise), it does not influence what cell the data starts being written to.


#### Base Command

`google-sheets-value-append`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | Spreadsheet ID. | Required | 
| range | The A1 notation of a range to search for a logical table of data. Values are appended after the last row of the table. A1 notation example, Sheet1!A1:D5 For further explanation and examples, see https://developers.google.com/sheets/api/guides/concepts#expandable-1. | Required | 
| input_option | The way input data should be interpreted. Possible values are: RAW, USER_ENTERED. | Optional | 
| insert_option | The way input data should be inserted. Possible values are: OVERWRITE, INSERT_ROWS. | Required | 
| major_dimension | The major dimension of the values. Possible values are: ROWS, COLUMNS. | Required | 
| values | The data that was read or to be written. This is an array of arrays. The outer array representing all the data and each inner array representing a major dimension. Each item in the inner array corresponds to one cell. To be entered in the following format - [1,2,3],[4,5,6] where each bracket will be the row or column, and each value inside will correspond to a cell. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!google-sheets-value-append insert_option=OVERWRITE major_dimension=ROWS range=newSheetTitle!A1:D5 spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk input_option=RAW values=[77,77,77],[777,777,777]```
#### Human Readable Output

>### Success


### google-sheets-spreadsheet-update
***
This is a custom update command, used to apply any of the Google Sheets API options. Applies one or more updates to the spreadsheet. Each request is validated before being applied. If any request is not valid, the entire request will fail and nothing will be applied.


#### Base Command

`google-sheets-spreadsheet-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spreadsheet_id | Spreadsheet ID. | Required | 
| echo_spreadsheet | True to add the spreadsheet to the output. Possible values are: False, True. Default is False. | Optional | 
| requests | JSON input according to the method documentation and object documentation - for advanced users' free use (Google Sheets API) https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets/batchUpdate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSheets.Spreadsheet.updatedSpreadsheet.properties.title | String | Spreadsheet title. | 
| GoogleSheets.Spreadsheet.spreadsheetId | String | Spreadsheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.spreadsheetUrl | Unknown | Spreadsheet URL. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.sheetId | String | Sheet ID. | 
| GoogleSheets.Spreadsheet.updatedSpreadsheet.sheets.title | String | Sheet title. | 

#### Command example
```!google-sheets-spreadsheet-update spreadsheet_id=1EwL7rqcSVdkXCAwuGt4jIiDrDUEKW3bmP63dqTBolfk requests=`{"requests": [{"copyPaste": {"destination": {"startRowIndex": 0, "startColumnIndex": 0, "endRowIndex": 5, "endColumnIndex": 5, "sheetId": 3}, "pasteOrientation": "TRANSPOSE", "source": {"sheetId": 3, "startRowIndex": 0, "startColumnIndex": 0, "endColumnIndex": 5, "endRowIndex": 5}, "pasteType": "PASTE_NORMAL"}}]}````
#### Human Readable Output

>### Success
