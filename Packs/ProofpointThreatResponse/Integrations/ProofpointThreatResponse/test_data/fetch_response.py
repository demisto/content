FETCH_RESPOSNE = [
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T11:49:48Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T11:49:48Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3064,
      "users": [
        "test1"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 0,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T11:44:24Z",
          "attackers": [
            {
              "location": "127.0.0.1"
            },
            {
              "location": "http://test.com/"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617103759000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<ABCD1234@cpus>",
              "recipient": {
                "vap": False,
                "email": "sabrina.test@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:28 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "id": 9225
        }
      ],
      "description": "",
      "quarantine_results": [],
      "event_count": 1,
      "created_at": "2021-03-30T11:44:24Z",
      "summary": "",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "127.0.0.1"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T11:49:48Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T11:49:48Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3063,
      "users": [
        "test1"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 1,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T11:42:24Z",
          "attackers": [
            {
              "location": "http://test.com/"
            },
            {
              "location": "127.0.0.1"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617103759000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<ABCD1234@cpus>",
              "recipient": {
                "vap": False,
                "email": "sabrina.test@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:28 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "id": 9224
        }
      ],
      "description": "",
      "quarantine_results": [
        {
          "status": "successful",
          "recipientType": "Original Recipient",
          "wasUndone": "false",
          "isRead": "false",
          "details": "Success",
          "startTime": "2021-03-30T11:42:25.165Z",
          "messageId": "<ABCD1234@cpus>",
          "alertSource": "Proofpoint TAP",
          "endTime": "2021-03-30T11:49:48.806Z",
          "recipient": "sabrina.test@test.com"
        }
      ],
      "event_count": 1,
      "created_at": "2021-03-30T11:42:24Z",
      "summary": "",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "127.0.0.1"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T11:26:17Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T11:26:17Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3062,
      "users": [
        "test2"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 0,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T11:24:24Z",
          "attackers": [
            {
              "location": "http://test.com/"
            },
            {
              "location": "127.0.0.1"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617102528000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<ABCDE12345@pair>",
              "recipient": {
                "vap": False,
                "email": "john.test@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:08 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "id": 9223
        }
      ],
      "description": "",
      "quarantine_results": [],
      "event_count": 1,
      "created_at": "2021-03-30T11:24:24Z",
      "summary": "",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "127.0.0.1"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T11:26:17Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T11:26:17Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3056,
      "users": [
        "test2"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 1,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T11:21:24Z",
          "attackers": [
            {
              "location": "http://test.com/"
            },
            {
              "location": "127.0.0.1"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617102528000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<ABCDE12345@pair>",
              "recipient": {
                "vap": False,
                "email": "john.test@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:08 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "id": 9217
        }
      ],
      "description": "",
      "quarantine_results": [
        {
          "status": "successful",
          "recipientType": "Original Recipient",
          "wasUndone": "false",
          "isRead": "false",
          "details": "Success",
          "startTime": "2021-03-30T11:21:24.43Z",
          "messageId": "<ABCDE12345@pair>",
          "alertSource": "Proofpoint TAP",
          "endTime": "2021-03-30T11:26:17.667Z",
          "recipient": "john.test@test.com"
        }
      ],
      "event_count": 1,
      "created_at": "2021-03-30T11:21:24Z",
      "summary": "",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "127.0.0.1"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T11:24:40Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T11:24:40Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3060,
      "users": [
        "test3"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 0,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T11:24:24Z",
          "attackers": [
            {
              "location": "http://test.com/"
            },
            {
              "location": "127.0.0.1"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617102542000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<ABCDEF123456@gate>",
              "recipient": {
                "vap": False,
                "email": "laura.test@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:08 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "id": 9221
        }
      ],
      "description": "",
      "quarantine_results": [],
      "event_count": 1,
      "created_at": "2021-03-30T11:24:24Z",
      "summary": "",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "127.0.0.1"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T11:24:40Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T11:24:40Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3057,
      "users": [
        "test3"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 1,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T11:21:24Z",
          "attackers": [
            {
              "location": "http://test.com/"
            },
            {
              "location": "127.0.0.1"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617102542000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<ABCDEF123456@gate>",
              "recipient": {
                "vap": False,
                "email": "laura.test@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:08 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "id": 9218
        }
      ],
      "description": "",
      "quarantine_results": [
        {
          "status": "successful",
          "recipientType": "Original Recipient",
          "wasUndone": "false",
          "isRead": "false",
          "details": "Success",
          "startTime": "2021-03-30T11:21:24.612Z",
          "messageId": "<ABCDEF123456@gate>",
          "alertSource": "Proofpoint TAP",
          "endTime": "2021-03-30T11:24:40.491Z",
          "recipient": "laura.test@test.com"
        }
      ],
      "event_count": 1,
      "created_at": "2021-03-30T11:21:24Z",
      "summary": "",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "127.0.0.1"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T11:24:24Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T11:24:24Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3061,
      "users": [
        "test4"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 0,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T11:24:24Z",
          "attackers": [
            {
              "location": "http://test.com/"
            },
            {
              "location": "127.0.0.1"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617102715000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "recipient": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "sender": {
                "vap": False,
                "email": "btv1==723f6d06c50==t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<abcdef@meg>"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "id": 9222
        }
      ],
      "description": "",
      "quarantine_results": [],
      "event_count": 1,
      "created_at": "2021-03-30T11:24:24Z",
      "summary": "",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "127.0.0.1"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T11:21:45Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T11:21:45Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3059,
      "users": [
        "test5"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 0,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T11:21:24Z",
          "attackers": [
            {
              "location": "http://test.com/"
            },
            {
              "location": "127.0.0.1"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617102339000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<ABCDEFG1234567@meg>",
              "recipient": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:04 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "id": 9220
        }
      ],
      "description": "",
      "quarantine_results": [],
      "event_count": 1,
      "created_at": "2021-03-30T11:21:24Z",
      "summary": "",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "127.0.0.1"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T11:21:45Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T11:21:45Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3055,
      "users": [
        "test5"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 1,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T11:18:24Z",
          "attackers": [
            {
              "location": "http://test.com/"
            },
            {
              "location": "127.0.0.1"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617102339000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<ABCDEFG1234567@meg>",
              "recipient": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:04 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "id": 9216
        }
      ],
      "description": "",
      "quarantine_results": [
        {
          "status": "successful",
          "recipientType": "Original Recipient",
          "wasUndone": "false",
          "isRead": "true",
          "details": "Success",
          "startTime": "2021-03-30T11:18:24.504Z",
          "messageId": "<ABCDEFG1234567@meg>",
          "alertSource": "Proofpoint TAP",
          "endTime": "2021-03-30T11:21:45.083Z",
          "recipient": "t.t@test.com"
        }
      ],
      "event_count": 1,
      "created_at": "2021-03-30T11:18:24Z",
      "summary": "",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "127.0.0.1"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T11:21:37Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T11:21:37Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3058,
      "users": [
        "test4"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 1,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T11:21:24Z",
          "attackers": [
            {
              "location": "http://test.com/"
            },
            {
              "location": "127.0.0.1"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617102715000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<abcdef@meg>",
              "recipient": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:11 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "id": 9219
        }
      ],
      "description": "",
      "quarantine_results": [
        {
          "status": "successful",
          "recipientType": "Original Recipient",
          "wasUndone": "false",
          "isRead": "false",
          "details": "Success",
          "startTime": "2021-03-30T11:21:24.761Z",
          "messageId": "<abcdef@meg>",
          "alertSource": "Proofpoint TAP",
          "endTime": "2021-03-30T11:21:37.871Z",
          "recipient": "t.t@test.com"
        }
      ],
      "event_count": 1,
      "created_at": "2021-03-30T11:21:24Z",
      "summary": "",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "127.0.0.1"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "An automatic Close Incident response was taken.",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T14:33:31Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T14:33:31Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful close incident response",
      "id": 3071,
      "users": [
        "test7"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Spam"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "Critical"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 0,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "spam",
          "attackDirection": "inbound",
          "alertType": "spam",
          "severity": "Critical",
          "received": "2021-03-30T14:33:29Z",
          "attackers": [
            {
              "location": "208.107.91.131"
            },
            {
              "location": "https://test2/test3"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "abuseCopy": False,
              "recipient": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "messageId": "<5A0C3B10-34F4-4E8F-BF1C-06714D329DDF@t.com>"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "threatname": "Redirect to affiliate dating site",
          "id": 9232,
          "description": "Redirect to affiliate dating site"
        }
      ],
      "description": "",
      "quarantine_results": [],
      "event_count": 1,
      "created_at": "2021-03-30T14:33:29Z",
      "summary": "Redirect to affiliate dating site",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "208.107.91.131",
          "https://test2/test3"
        ],
        "forensics": [
          "bit.ly",
          "https://test2/test3"
        ]
      },
      "team": "Unassigned"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "Incident was already closed.",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T14:31:37Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T14:31:37Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3070,
      "users": [
        "test7"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Spam"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "Critical"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 2,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "spam",
          "attackDirection": "inbound",
          "alertType": "spam",
          "severity": "Critical",
          "received": "2021-03-30T14:26:29Z",
          "attackers": [
            {
              "location": "https://test2/test3"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "abuseCopy": False,
              "recipient": {
                "vap": False,
                "email": "t.t@test.com"
              }
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "threatname": "Redirect to affiliate dating site",
          "id": 9231,
          "description": "Redirect to affiliate dating site"
        }
      ],
      "description": "",
      "quarantine_results": [
        {
          "status": "successful",
          "recipientType": "None",
          "wasUndone": "false",
          "isRead": "true",
          "details": "Success",
          "startTime": "2021-03-30T14:29:25.849Z",
          "messageId": "None",
          "alertSource": "Not Available",
          "endTime": "2021-03-30T14:31:37.043Z",
          "recipient": "None"
        },
        {
          "status": "successful",
          "recipientType": "Search",
          "wasUndone": "false",
          "isRead": "None",
          "details": "Searched for missing message ids",
          "startTime": "2021-03-30T14:26:30.315Z",
          "alertSource": "Proofpoint TAP",
          "endTime": "2021-03-30T14:29:25.821Z",
          "recipient": "t.t@test.com"
        }
      ],
      "event_count": 1,
      "created_at": "2021-03-30T14:26:29Z",
      "summary": "Redirect to affiliate dating site",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "https://test2/test3"
        ],
        "forensics": [
          "bit.ly",
          "https://test2/test3"
        ]
      },
      "team": "Unassigned"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T13:24:22Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T13:24:22Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3068,
      "users": [
        "test6"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "Critical"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 5000,
      "successful_quarantines": 1,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Critical",
          "received": "2021-03-30T13:19:27Z",
          "attackers": [
            {
              "location": "52.100.8.238"
            },
            {
              "location": "https:/test5:443/o"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "abuseCopy": False,
              "messageId": "<t@t.t.t.outlook.com>",
              "recipient": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "subject": "[EXTERNAL] t t  shared the folder "
            }
          ],
          "fileName": "C:\\\\Users\\\\user\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\INetCache\\\\IE\\\\0GPQ3ADT\\\\onenoteframe[1].htm",
          "source": "Proofpoint TAP",
          "state": "Linked",
          "threatname": "Malicious content dropped during execution",
          "id": 9230,
          "description": "Malicious content dropped during execution"
        }
      ],
      "description": "",
      "quarantine_results": [
        {
          "status": "successful",
          "recipientType": "Original Recipient",
          "wasUndone": "false",
          "isRead": "true",
          "details": "Success",
          "startTime": "2021-03-30T13:19:27.878Z",
          "messageId": "<T1@T1.prod.outlook.com>",
          "alertSource": "Proofpoint TAP",
          "endTime": "2021-03-30T13:24:22.206Z",
          "recipient": "t.t@test.com"
        }
      ],
      "event_count": 1,
      "created_at": "2021-03-30T13:19:27Z",
      "summary": "Malicious content dropped during execution",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "https:/test5:443/o",
          "52.100.8.238"
        ],
        "forensics": [
          "https:/test5:443/o",
          "wesleyruff.cool",
          "https://wesleyruff.cool/wp-admin/Jah",
          "1drv.ms"
        ],
        "cnc": [
          "172.217.5.74",
          "52.109.20.75",
          "69.49.230.158",
          "152.199.4.33",
          "13.65.40.209",
          "13.107.6.171",
          "52.114.88.22",
          "142.250.68.10",
          "13.107.42.13",
          "69.16.175.42",
          "104.18.11.207",
          "23.79.41.28",
          "157.55.109.230",
          "172.64.203.28",
          "52.109.2.159",
          "104.18.23.52",
          "23.223.57.152",
          "52.114.74.43",
          "104.16.18.94",
          "23.79.40.98"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T13:21:09Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T13:21:09Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3069,
      "users": [
        "test8"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "Critical"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 5000,
      "successful_quarantines": 1,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Critical",
          "received": "2021-03-30T13:19:26Z",
          "attackers": [
            {
              "location": "52.100.8.238"
            },
            {
              "location": "https:/test5:443/o"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "abuseCopy": False,
              "messageId": "<t@t.t.t.outlook.com>",
              "recipient": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "subject": "[EXTERNAL] t t  shared the folder with you."
            }
          ],
          "fileName": "C:\\\\Users\\\\user\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\INetCache\\\\IE\\\\0GPQ3ADT\\\\onenoteframe[1].htm",
          "source": "Proofpoint TAP",
          "state": "Linked",
          "threatname": "Malicious content dropped during execution",
          "id": 9229,
          "description": "Malicious content dropped during execution"
        }
      ],
      "description": "",
      "quarantine_results": [
        {
          "status": "successful",
          "recipientType": "Original Recipient",
          "wasUndone": "false",
          "isRead": "true",
          "details": "Success",
          "startTime": "2021-03-30T13:19:27.996Z",
          "messageId": "<T1@T1.prod.outlook.com>",
          "alertSource": "Proofpoint TAP",
          "endTime": "2021-03-30T13:21:09.006Z",
          "recipient": "t.t@test.com"
        }
      ],
      "event_count": 1,
      "created_at": "2021-03-30T13:19:26Z",
      "summary": "Malicious content dropped during execution",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "https:/test5:443/o",
          "52.100.8.238"
        ],
        "forensics": [
          "https:/test5:443/o",
          "wesleyruff.cool",
          "https://wesleyruff.cool/wp-admin/Jah",
          "1drv.ms"
        ],
        "cnc": [
          "172.217.5.74",
          "52.109.20.75",
          "152.199.4.33",
          "69.49.230.158",
          "13.107.6.171",
          "13.65.40.209",
          "52.114.88.22",
          "142.250.68.10",
          "13.107.42.13",
          "104.18.11.207",
          "69.16.175.42",
          "157.55.109.230",
          "23.79.41.28",
          "172.64.203.28",
          "52.109.2.159",
          "23.223.57.152",
          "104.18.23.52",
          "52.114.74.43",
          "104.16.18.94",
          "23.79.40.98"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T13:00:37Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T13:00:37Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3066,
      "users": [
        "test9"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 0,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T12:52:25Z",
          "attackers": [
            {
              "location": "127.0.0.1"
            },
            {
              "location": "http://test8.com"
            },
            {
              "location": "https://test10/test/test="
            },
            {
              "location": "http://test.com/"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617102069000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<abcde@pair>",
              "recipient": {
                "vap": False,
                "email": "jean.test@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:00 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "threatname": "Generic phishing detection",
          "id": 9228,
          "description": "Generic phishing detection"
        }
      ],
      "description": "",
      "quarantine_results": [],
      "event_count": 1,
      "created_at": "2021-03-30T12:52:25Z",
      "summary": "Generic phishing detection",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "http://test8.com",
          "127.0.0.1",
          "https://test10/test/test="
        ],
        "forensics": [
          "https://test10/test/test=",
          "gmzrmedipfazkvg.jetteamfinance.com.au"
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T13:00:37Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T13:00:37Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful quarantine",
      "id": 3065,
      "users": [
        "test9"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Phishing"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "High"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 4000,
      "successful_quarantines": 1,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "phish",
          "attackDirection": "inbound",
          "alertType": "phish",
          "severity": "Major",
          "received": "2021-03-30T12:52:25Z",
          "attackers": [
            {
              "location": "127.0.0.1"
            },
            {
              "location": "http://test8.com"
            },
            {
              "location": "https://test10/test/test="
            },
            {
              "location": "http://test.com/"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617102069000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<abcde@pair>",
              "recipient": {
                "vap": False,
                "email": "jean.test@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:00 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "id": 9227
        }
      ],
      "description": "",
      "quarantine_results": [
        {
          "status": "successful",
          "recipientType": "Original Recipient",
          "wasUndone": "false",
          "isRead": "false",
          "details": "Success",
          "startTime": "2021-03-30T12:52:27.371Z",
          "messageId": "<abcde@pair>",
          "alertSource": "Proofpoint TAP",
          "endTime": "2021-03-30T13:00:37.495Z",
          "recipient": "jean.test@test.com"
        }
      ],
      "event_count": 1,
      "created_at": "2021-03-30T12:52:25Z",
      "summary": "",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "http://test8.com",
          "127.0.0.1",
          "https://test10/test/test="
        ]
      },
      "team": "TEST-TEST"
    },
    {
      "event_sources": [
        "Proofpoint TAP"
      ],
      "close_summary": "An automatic Close Incident response was taken.",
      "false_positive_count": 0,
      "updated_at": "2021-03-30T12:52:27Z",
      "assignee": "Unassigned",
      "closed_at": "2021-03-30T12:52:27Z",
      "event_ids": None,
      "close_detail": "Automatically closed after successful close incident response",
      "id": 3067,
      "users": [
        "test9"
      ],
      "incident_field_values": [
        {
          "name": "Classification",
          "value": "Spam"
        },
        {
          "name": "Attack Vector",
          "value": "Email"
        },
        {
          "name": "Abuse Disposition",
          "value": None
        },
        {
          "name": "Severity",
          "value": "Low"
        }
      ],
      "comments": [],
      "state": "Closed",
      "score": 2000,
      "successful_quarantines": 0,
      "pending_quarantines": 0,
      "events": [
        {
          "category": "spam",
          "attackDirection": "inbound",
          "alertType": "spam",
          "severity": "Minor",
          "received": "2021-03-30T12:52:26Z",
          "attackers": [
            {
              "location": "127.0.0.1"
            },
            {
              "location": "http://test8.com"
            },
            {
              "location": "https://test10/test/test="
            },
            {
              "location": "http://test.com/"
            }
          ],
          "falsePositive": False,
          "emails": [
            {
              "messageDeliveryTime": {
                "zone": {
                  "fixed": True,
                  "id": "UTC"
                },
                "millis": 1617102069000,
                "chronology": {
                  "zone": {
                    "fixed": True,
                    "id": "UTC"
                  }
                },
                "afterNow": False,
                "equalNow": False,
                "beforeNow": True
              },
              "sender": {
                "vap": False,
                "email": "t.t@test.com"
              },
              "abuseCopy": False,
              "messageId": "<abcde@pair>",
              "recipient": {
                "vap": False,
                "email": "jean.test@test.com"
              },
              "subject": "[EXTERNAL] FW: Message from test Reception 01:00 PM, March 30, 2021"
            }
          ],
          "source": "Proofpoint TAP",
          "state": "Linked",
          "threatname": "Unsolicited Bulk Email",
          "id": 9226
        }
      ],
      "description": "",
      "quarantine_results": [],
      "event_count": 1,
      "created_at": "2021-03-30T12:52:26Z",
      "summary": "Unsolicited Bulk Email",
      "failed_quarantines": 0,
      "hosts": {
        "attacker": [
          "http://test.com/",
          "http://test8.com",
          "127.0.0.1",
          "https://test10/test/test="
        ]
      },
      "team": "Unassigned"
    }
  ]