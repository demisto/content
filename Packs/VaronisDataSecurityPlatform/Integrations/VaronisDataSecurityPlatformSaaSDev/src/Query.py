from Filters import Filters


class Query:
    def __init__(self):
        self.entityName = None
        self.filter = Filters()

    def set_entity_name(self, entity_name):
        self.entityName = entity_name
        return self

    def set_filter(self, filter_):
        self.filter = filter_
        return self

    def __repr__(self):
        return f"Entity Name: {self.entityName}, Filter: {self.filter}"