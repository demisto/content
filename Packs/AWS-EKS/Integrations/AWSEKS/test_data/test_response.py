from datetime import datetime

UPDATE_CLUSTER_CONFIG_LOGGING_RESPONSE = {
    "update": {
        "createdAt": datetime(2024, 1, 1),
        "error": [],
        "id": "11111111-1111-1111-1111-111111111111",
        "params": [
            {
                "type": "ClusterLogging",
                "value": "{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\"],\"enabled\":true}]}"
            }
        ],
        "status": "InProgress",
        "type": "LoggingUpdate"
    }
}
