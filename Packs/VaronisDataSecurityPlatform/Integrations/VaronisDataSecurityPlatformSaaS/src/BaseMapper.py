from CommonServerPython import *


from typing import Any, Dict, List


class BaseMapper:
    @staticmethod
    def convert_json_to_key_value(json_data) -> List[Dict[str, Any]]:
        data = json_data
        result = []
        for row in data["rows"]:
            obj = {}
            for col, val in zip(data["columns"], row):
                obj[col] = val
            result.append(obj)
        return result
