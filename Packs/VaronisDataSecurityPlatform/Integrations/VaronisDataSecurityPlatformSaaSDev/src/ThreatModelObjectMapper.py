from BaseMapper import BaseMapper
from ThreatModelAttributes import ThreatModelAttributes
from ThreatModelItem import ThreatModelItem


class ThreatModelObjectMapper(BaseMapper):
    def map(self, json_data):
        key_valued_objects = json_data

        mapped_items = []
        for obj in key_valued_objects:
            mapped_items.append(self.map_item(obj).to_dict())

        return mapped_items

    def map_item(self, row: dict) -> ThreatModelItem:
        threat_model_item = ThreatModelItem()
        threat_model_item.ID = row[ThreatModelAttributes.Id]
        threat_model_item.Name = row[ThreatModelAttributes.Name]
        threat_model_item.Category = row[ThreatModelAttributes.Category]
        threat_model_item.Source = row[ThreatModelAttributes.Source]
        threat_model_item.Severity = row[ThreatModelAttributes.Severity]

        return threat_model_item