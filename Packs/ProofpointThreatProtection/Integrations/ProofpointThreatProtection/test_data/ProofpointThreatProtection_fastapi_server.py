from fastapi import FastAPI, Response
from pydantic import BaseModel

import urllib3
urllib3.disable_warnings()

URL_SUFFIX_BLOCKLIST = '/api/v1/emailProtection/modules/spam/orgBlockList'
URL_SUFFIX_SAFELIST = '/api/v1/emailProtection/modules/spam/orgSafeList'

MOCK_SAFELIST_ENTRIES = {
    "entries": [
        {
            "attribute": "$hfrom",
            "operator": "equal",
            "value": "test@mydomain.com",
            "comment": "comment 1"
        },
        {
            "attribute": "$from",
            "operator": "equal",
            "value": "sample@example.com",
            "comment": "comment B"
        }
    ]
}

VALID_API_LIST_ACTIONS = ['add', 'delete']
VALID_API_LIST_ATTRIBUTES = ['$hfrom', '$from', '$ip', '$host', '$helo', '$rcpt']
VALID_SAFE_LIST_OPERATORS = ['equal', 'contain']
VALID_BLOCK_LIST_OPERATORS = ['equal', 'not_equal', 'contain', 'not_contain']


class Mock_API_List_Entry(BaseModel):
    action: str = ''
    attribute: str = ''
    operator: str = ''
    value: str = ''
    comment: str = ''


class Mock_API_List_EntryOut(BaseModel):
    attribute: str = ''
    operator: str = ''
    value: str = ''
    comment: str = ''


app = FastAPI()


@app.get(URL_SUFFIX_SAFELIST)
@app.get(URL_SUFFIX_BLOCKLIST)
async def get_safelist(clusterId: str, response: Response):
    if clusterId is None or clusterId == '':
        response.status_code = 400
        return {"errors": ["Bad request."]}
    return MOCK_SAFELIST_ENTRIES


@app.post(URL_SUFFIX_SAFELIST, response_model=Mock_API_List_EntryOut)
@app.post(URL_SUFFIX_BLOCKLIST, response_model=Mock_API_List_EntryOut)
async def add_or_delete_safe_list_entry(
    response: Response,
    clusterId: str,
    api_list_entry: Mock_API_List_Entry,
):

    def return_api_error(fieldname, fieldvalue, valid_values):
        return {'errors': ['Bad request. ({}) not '
                           'in list of valid {} values {}'.format(
                               fieldvalue,
                               fieldname,
                               valid_values
                           )]
                }

    if clusterId is None or clusterId == '':
        response.status_code = 400
        return {"errors": ["Bad request."]}

    if api_list_entry.action not in VALID_API_LIST_ACTIONS:
        response.status_code = 400
        return return_api_error(
            'action',
            api_list_entry.action,
            VALID_API_LIST_ACTIONS
        )

    if api_list_entry.attribute not in VALID_API_LIST_ATTRIBUTES:
        response.status_code = 400
        return return_api_error(
            'attribute',
            api_list_entry.attribute,
            VALID_API_LIST_ATTRIBUTES
        )

    if api_list_entry.operator not in VALID_SAFE_LIST_OPERATORS:
        response.status_code = 400
        return return_api_error(
            'operator',
            api_list_entry.operator,
            VALID_SAFE_LIST_OPERATORS
        )

    if not isinstance(api_list_entry.value, str):
        response.status_code = 400
        return return_api_error(
            'value',
            api_list_entry.value,
            'valid object of type str()'
        )

    return api_list_entry
