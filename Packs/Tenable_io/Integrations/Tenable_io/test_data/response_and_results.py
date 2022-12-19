#adding so null don't get seen as variable.
null = None
false = False

MOCK_RAW_ASSET_BY_IP = {
  "info": {
    "time_end": "2022-09-07T19:08:36.038Z",
    "time_start": "2022-09-07T18:57:37.275Z",
    "id": "fake_asset_id",
    "uuid": "fake_asset_id",
    "operating_system": [
      "Linux Kernel 3.2"
    ],
    "fqdn": [
      "1.2.3.1.bc.googleusercontent.com"
    ],
    "counts": {
      "vulnerabilities": {
        "total": 26,
        "severities": [
          {
            "count": 19,
            "level": 0,
            "name": "Info"
          },
          {
            "count": 1,
            "level": 1,
            "name": "Low"
          },
          {
            "count": 6,
            "level": 2,
            "name": "Medium"
          },
          {
            "count": 0,
            "level": 3,
            "name": "High"
          },
          {
            "count": 0,
            "level": 4,
            "name": "Critical"
          }
        ]
      },
      "audits": {
        "total": 0,
        "statuses": [
          {
            "count": 0,
            "level": 1,
            "name": "Passed"
          },
          {
            "count": 0,
            "level": 2,
            "name": "Warning"
          },
          {
            "count": 0,
            "level": 3,
            "name": "Failed"
          }
        ]
      }
    },
    "has_agent": false,
    "created_at": "2022-09-07T19:08:42.737Z",
    "updated_at": "2022-11-18T16:41:46.737Z",
    "first_seen": "2022-09-07T19:08:36.038Z",
    "last_seen": "2022-09-07T19:25:28.329Z",
    "last_scan_target": "1.3.2.1",
    "last_authenticated_scan_date": null,
    "last_licensed_scan_date": "2022-09-07T19:08:36.038Z",
    "last_scan_id": "fake_asset_id",
    "last_schedule_id": "template-fake_asset_id",
    "sources": [
      {
        "name": "NESSUS_SCAN",
        "first_seen": "2022-09-07T19:08:36.038Z",
        "last_seen": "2022-09-07T19:25:28.329Z"
      }
    ],
    "tags": [
      {
        "tag_uuid": "fake_asset_id",
        "tag_key": "GCP-Tags",
        "tag_value": "GCP",
        "added_by": "fake_asset_id",
        "added_at": "2022-09-07T19:58:03.786Z",
        "source": "static"
      }
    ],
    "interfaces": [
      {
        "name": "UNKNOWN",
        "fqdn": [
          "1.2.3.1.bc.googleusercontent.com"
        ],
        "mac_address": [],
        "ipv4": [
          "1.3.2.1"
        ],
        "ipv6": []
      }
    ],
    "ipv4": [
      "1.3.2.1"
    ]
  }
}

MOCK_RAW_ASSET_ATTRIBUTES = {
  "attributes": [
    {
      "name": "owner",
      "id": "fake_asset_id",
      "value": "owner@demisto.com"
    }
  ]
}

EXPECTED_ASSET_INFO_RESULTS = {
    "attributes": [
        {
            "owner": "owner@demisto.com"
        }
    ],
    "counts": {
        "audits": {
            "statuses": [
                {
                    "count": 0,
                    "level": 1,
                    "name": "Passed"
                },
                {
                    "count": 0,
                    "level": 2,
                    "name": "Warning"
                },
                {
                    "count": 0,
                    "level": 3,
                    "name": "Failed"
                }
            ],
            "total": 0
        },
        "vulnerabilities": {
            "severities": [
                {
                    "count": 19,
                    "level": 0,
                    "name": "Info"
                },
                {
                    "count": 1,
                    "level": 1,
                    "name": "Low"
                },
                {
                    "count": 6,
                    "level": 2,
                    "name": "Medium"
                },
                {
                    "count": 0,
                    "level": 3,
                    "name": "High"
                },
                {
                    "count": 0,
                    "level": 4,
                    "name": "Critical"
                }
            ],
            "total": 26
        }
    },
    "created_at": "2022-09-07T19:08:42.737Z",
    "first_seen": "2022-09-07T19:08:36.038Z",
    "fqdn": [
        "1.2.3.1.bc.googleusercontent.com"
    ],
    "has_agent": false,
    "id": "fake_asset_id",
    "interfaces": [
        {
            "fqdn": [
                "1.2.3.1.bc.googleusercontent.com"
            ],
            "ipv4": [
                "1.3.2.1"
            ],
            "ipv6": [],
            "mac_address": [],
            "name": "UNKNOWN"
        }
    ],
    "ipv4": [
        "1.3.2.1"
    ],
    "last_authenticated_scan_date": null,
    "last_licensed_scan_date": "2022-09-07T19:08:36.038Z",
    "last_scan_id": "fake_asset_id",
    "last_scan_target": "1.3.2.1",
    "last_schedule_id": "template-fake_asset_id",
    "last_seen": "2022-09-07T19:25:28.329Z",
    "operating_system": [
        "Linux Kernel 3.2"
    ],
    "sources": [
        {
            "first_seen": "2022-09-07T19:08:36.038Z",
            "last_seen": "2022-09-07T19:25:28.329Z",
            "name": "NESSUS_SCAN"
        }
    ],
    "tags": [
        {
            "added_at": "2022-09-07T19:58:03.786Z",
            "added_by": "fake_asset_id",
            "source": "static",
            "tag_key": "GCP-Tags",
            "tag_uuid": "fake_asset_id",
            "tag_value": "GCP"
        }
    ],
    "time_end": "2022-09-07T19:08:36.038Z",
    "time_start": "2022-09-07T18:57:37.275Z",
    "updated_at": "2022-11-18T16:41:46.737Z",
    "uuid": "fake_asset_id"
}