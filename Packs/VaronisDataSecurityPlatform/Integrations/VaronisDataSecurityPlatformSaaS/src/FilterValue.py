class FilterValue:
    def __init__(self, value):
        self = value
        # self.displayValue = value.get("displayValue", None)

    def __repr__(self):
        return f"{self.value}"