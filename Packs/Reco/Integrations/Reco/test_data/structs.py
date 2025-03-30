import json
from enum import Enum
from typing import List, Any
from json import JSONEncoder


def _default(self, obj: Any):
    return getattr(obj.__class__, "to_json", _default.default)(obj)  # type: ignore


_default.default = JSONEncoder.default  # type: ignore # Save unmodified default.
JSONEncoder.default = _default  # type: ignore # Replace it.


class RiskLevel(Enum):
    UNSPECIFIED = 0
    # Low risk level score
    LOW = 10
    # Medium risk level score
    MEDIUM = 20
    # High risk level score
    HIGH = 30
    # Critical risk level score
    CRITICAL = 40

    def __dict__(self):
        return self.to_json()

    def to_json(self):
        return self.value


class GetTableResponse:
    """
    GetTableResponse - this message is the output result for the GetTable RPC
    call
    """

    # this is a JSON string representing the table definition used by our
    # frontend UI code Note - we are currently using Tabulator
    table_definition: str
    # this field contains the dynamic table definition. Note - as JSON can only
    # contain string and numbers, we need this field in order to notify the
    # frontend to use a callback function for a certain field attribute
    dynamic_table_definition: str
    # the token is used for pagination. using the token and the "GetTablePage", a
    # user can retrieve more pages for the same query
    token: str
    # the data to return
    data: "TableData"
    # total number of results. Note - if the table has pagination, the number of
    # rows in the 'data' field is <= to the total number of results
    total_number_of_results: int

    def __init__(
        self,
        table_definition: str,
        dynamic_table_definition: str,
        token: str,
        data: "TableData",
        total_number_of_results: int,
    ) -> None:
        self.table_definition = table_definition
        self.dynamic_table_definition = dynamic_table_definition
        self.token = token
        self.data = data
        self.total_number_of_results = total_number_of_results

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GetIncidentTableResponse:
    """
    GetIncidentTableResponse is a wrapper around GetTableResponse. It contains
    the first page you should show, and the table definition, so the data
    enclosed in this response should be enough to display a table to the user.
    """

    getTableResponse: "GetTableResponse"

    def __init__(self, get_table_response: "GetTableResponse") -> None:
        self.getTableResponse = get_table_response

    def to_json(self):
        return json.loads(json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4))


class TableData:
    """a list of rows"""

    rows: List["RowData"]

    def __init__(self, rows: List["RowData"]):
        self.rows = rows

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class RowData:
    """a list of cells - which are key value pairs"""

    cells: List["KeyValuePair"]

    def __init__(self, cells: List["KeyValuePair"]):
        self.cells = cells

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class KeyValuePair:
    """a cell wich is a key value pair"""

    key: str
    # the key name
    value: str

    def __init__(self, key: str, value: str):
        self.key = key
        self.value = value

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GetTablePageResponse:
    # the data to return
    data: "TableData"
    # total number of results. Note - if the table has pagination, the number of
    # rows in the 'data' field is <= to the total number of results
    total_number_of_results: int

    def __init__(self, data: "TableData", total_number_of_results: int):
        self.data = data
        self.total_number_of_results = total_number_of_results

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
