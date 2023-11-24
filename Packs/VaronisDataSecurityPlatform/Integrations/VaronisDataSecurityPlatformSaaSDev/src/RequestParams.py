class RequestParams:
    def __init__(self):
        self.searchSource = None
        self.searchSourceName = None

    def set_search_source(self, search_source):
        self.searchSource = search_source
        return self

    def set_search_source_name(self, search_source_name):
        self.searchSourceName = search_source_name
        return self

    def __repr__(self):
        return f"Search Source: {self.searchSource}, Search Source Name: {self.searchSourceName}"