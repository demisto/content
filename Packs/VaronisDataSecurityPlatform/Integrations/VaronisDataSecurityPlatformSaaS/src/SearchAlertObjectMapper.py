from AlertAttributes import AlertAttributes
from AlertItem import AlertItem
from BaseMapper import BaseMapper
from CommonServerPython import *


from typing import List


class SearchAlertObjectMapper(BaseMapper):
    def map(self, json_data):
        key_valued_objects = self.convert_json_to_key_value(json_data)

        mapped_items = []
        for obj in key_valued_objects:
            mapped_items.append(self.map_item(obj).to_dict())

        return mapped_items

    def map_item(self, row: dict) -> AlertItem:
        alert_item = AlertItem(row)

        return alert_item
