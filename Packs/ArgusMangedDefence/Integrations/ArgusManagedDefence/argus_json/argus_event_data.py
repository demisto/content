ARGUS_EVENTS_FOR_CASE = {
    "responseCode": 0,
    "limit": 0,
    "offset": 0,
    "count": 0,
    "size": 0,
    "metaData": {},
    "messages": [
        {
            "message": "string",
            "messageTemplate": "string",
            "type": "FIELD_ERROR",
            "field": "string",
            "parameter": {},
            "timestamp": 0,
        }
    ],
    "data": [
        {
            "customerInfo": {
                "id": 0,
                "name": "string",
                "shortName": "string",
                "domain": {"id": 0, "name": "string"},
            },
            "properties": {
                "additionalProp1": "string",
                "additionalProp2": "string",
                "additionalProp3": "string",
            },
            "comments": [
                {
                    "timestamp": 0,
                    "user": {
                        "id": 0,
                        "customerID": 0,
                        "customer": {
                            "id": 0,
                            "name": "string",
                            "shortName": "string",
                            "domain": {"id": 0, "name": "string"},
                        },
                        "domain": {"id": 0, "name": "string"},
                        "userName": "string",
                        "name": "string",
                        "type": "user",
                    },
                    "comment": "string",
                }
            ],
            "associatedCase": {
                "id": 0,
                "subject": "string",
                "categoryID": 0,
                "categoryName": "string",
                "service": "string",
                "status": "ATTACHMENT_ADDED",
                "priority": "low",
            },
            "location": {
                "shortName": "string",
                "name": "string",
                "timeZone": "string",
                "id": 0,
            },
            "attackInfo": {
                "alarmID": 0,
                "alarmDescription": "string",
                "attackCategoryID": 0,
                "attackCategoryName": "string",
                "signature": "string",
            },
            "domain": {"fqdn": "string"},
            "uri": "string",
            "count": 0,
            "source": {
                "port": 0,
                "geoLocation": {
                    "countryCode": "string",
                    "countryName": "string",
                    "locationName": "string",
                    "latitude": 0,
                    "longitude": 0,
                },
                "networkAddress": {
                    "ipv6": True,
                    "public": True,
                    "maskBits": 0,
                    "multicast": True,
                    "host": True,
                    "address": "string",
                },
            },
            "destination": {
                "port": 0,
                "geoLocation": {
                    "countryCode": "string",
                    "countryName": "string",
                    "locationName": "string",
                    "latitude": 0,
                    "longitude": 0,
                },
                "networkAddress": {
                    "ipv6": True,
                    "public": True,
                    "maskBits": 0,
                    "multicast": True,
                    "host": True,
                    "address": "string",
                },
            },
            "protocol": "string",
            "timestamp": 0,
            "startTimestamp": 0,
            "endTimestamp": 0,
            "lastUpdatedTimestamp": 0,
            "flags": ["ESTABLISHED"],
            "detailedEventIDS": ["string"],
            "severity": "low",
            "id": "string",
        }
    ],
}

ARGUS_EVENT_PAYLOAD = {
    "responseCode": 0,
    "limit": 0,
    "offset": 0,
    "count": 0,
    "size": 0,
    "metaData": {},
    "messages": [
        {
            "message": "string",
            "messageTemplate": "string",
            "type": "FIELD_ERROR",
            "field": "string",
            "parameter": {},
            "timestamp": 0,
        }
    ],
    "data": {"id": "string", "type": "ethernet", "payload": "string"},
}

ARGUS_EVENT = {
    "responseCode": 0,
    "limit": 0,
    "offset": 0,
    "count": 0,
    "size": 0,
    "metaData": {},
    "messages": [
        {
            "message": "string",
            "messageTemplate": "string",
            "type": "FIELD_ERROR",
            "field": "string",
            "parameter": {},
            "timestamp": 0,
        }
    ],
    "data": {
        "timestamp": 0,
        "flags": 0,
        "customerID": 0,
        "aggregationKey": "string",
        "sourceType": "string",
        "customerInfo": {
            "id": 0,
            "name": "string",
            "shortName": "string",
            "domain": {"id": 0, "name": "string"},
        },
        "update": True,
        "aggregated": True,
        "encodedFlags": ["ESTABLISHED"],
    },
}
