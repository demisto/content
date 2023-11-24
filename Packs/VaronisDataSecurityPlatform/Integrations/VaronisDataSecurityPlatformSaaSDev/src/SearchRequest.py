from CommonServerUserPython import *
from Query import Query
from RequestParams import RequestParams
from Rows import Rows


import json


class SearchRequest:
    def __init__(self):
        self.query = Query()
        self.rows = Rows()
        self.requestParams = RequestParams()

    def set_query(self, query):
        self.query = query
        return self

    def set_rows(self, rows):
        self.rows = rows
        return self

    def set_request_params(self, request_params):
        self.requestParams = request_params
        return self

    def __repr__(self):
        return f"Query: {self.query}, Rows: {self.rows}, Request Params: {self.requestParams}"

    def to_json(self):
        dataJSON = json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
        return dataJSON