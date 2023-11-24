class FilterCondition:
    def __init__(self):
        self.path = None
        self.operator = None
        self.values = []

    def set_path(self, path):
        self.path = path
        return self

    def set_operator(self, operator):
        self.operator = operator
        return self

    def add_value(self, value):
        self.values.append(value)  # FilterValue(value)
        return self

    def __repr__(self):
        return f"{self.path} {self.operator} {self.values}"