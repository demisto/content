class Filters:
    def __init__(self):
        self.filterOperator = None
        self.filters = []

    def set_filter_operator(self, filter_operator):
        self.filterOperator = filter_operator
        return self

    def add_filter(self, filter_):
        self.filters.append(filter_)
        return self

    def __repr__(self):
        return f"Filter Operator: {self.filterOperator}, Filters: {self.filters}"