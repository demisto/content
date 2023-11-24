class Rows:
    def __init__(self):
        self.columns = []
        self.filter = []
        self.grouping = None
        self.ordering = []

    def add_column(self, column):
        self.columns.append(column)
        return self

    def add_filter(self, filter_):
        self.filter.append(filter_)
        return self

    def set_grouping(self, grouping):
        self.grouping = grouping
        return self

    def add_ordering(self, ordering):
        self.ordering.append(ordering)
        return self

    def __repr__(self):
        return f"Columns: {self.columns}, Filter: {self.filter}, Grouping: {self.grouping}, Ordering: {self.ordering}"