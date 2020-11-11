import json

j = {"signature": "HIPS/IPConnect-002", "dest_risk_object_type": "system", "host_risk_score": "0",
     "dest_bunit": "americas", "dest_lat": "38.959405", "index": "notable",
     "rule_title": "Endpoint - High Or Critical Priority Host With Malware - Rule", "severity": "unknown",
     "linecount": "2", "dest_is_expected": "false", "dest_should_timesync": "TRUE",
     "_bkt": "notable~870~66D21DF4-F4FD-4886-A986-82E72ADCBFE9",
     "rule_description": "Endpoint - High Or Critical Priority Host With Malware - Rule", "priority": "high",
     "host_risk_object_type": "system", "dest_asset_id": "7028e149c4722ef06794c47a42c539565ae55713",
     "dest_nt_host": "ACME-prod-014", "dest_priority": "high", "dest_asset_tag": "americas",
     "dest_requires_av": "false", "dest_city": "Washington D.C.", "dest_pci_domain": "untrust", "dest": "ACME-prod-014",
     "security_domain": "Endpoint - High Or Critical Priority Host With Malware - Rule", "dest_country": "USA",
     "rule_name": "Endpoint - High Or Critical Priority Host With Malware - Rule", "dest_risk_score": "24160",
     "_sourcetype": "stash", "_indextime": "1605110774", "splunk_server": "ip-172-31-44-193", "_cd": "870:20873",
     "sourcetype": "stash", "_si": ["ip-172-31-44-193", "notable"], "_serial": "0", "host": "ip-172-31-44-193",
     "priorities": "high", "_time": "2020-11-11T08:06:14.000-08:00",
     "source": "Endpoint - High Or Critical Priority Host With Malware - Rule",
     "_raw": "1605110771, search_name=\"Endpoint - High Or Critical Priority Host With Malware - Rule\", count=\"1\", dest=\"ACME-prod-014\", dest_priority=\"high\", info_max_time=\"+Infinity\", info_min_time=\"0.000\", info_search_time=\"1605055869.683322000\", lastTime=\"1605110581\", orig_raw=\"InsertedAt=\\\"2020-11-11 16:03:01\\\"; EventID=\\\"404141\\\"; EventType=\\\"Suspicious behavior\\\"; Action=\\\"None\\\"; ComputerName=\\\"ACME-prod-014\\\"; ComputerDomain=\\\"ACME\\\"; ComputerIPAddress=\\\"108.10.82.188\\\"; EventTime=\\\"2020-11-11 16:03:01\\\"; ActionTakenID=\\\"101\\\"; UserName=\\\"ACME\\\\apela\\\"; ScannerTypeID=\\\"200\\\"; ScannerType=\\\"Unknown\\\"; StatusID=\\\"100\\\"; Status=\\\"Threat type not cleanable\\\"; ThreatTypeID=\\\"4\\\"; EventType=\\\"Suspicious behavior\\\"; EventName=\\\"HIPS/IPConnect-002\\\"; FullFilePath=\\\"C:\\\\Users\\\\pn\\\\AppData\\\\Local\\\\Temp\\\\install_reader10_uk_mssa_aih.exe\\\"; GroupName=\\\"ACME\\\\Computers\\\";\n\", signature=\"HIPS/IPConnect-002\"",
     "dest_should_update": "TRUE", "dest_ip": "192.168.2.14", "dest_long": "-77.04", "risk_score": "24160",
     "urgency": "medium"}
k = j["_raw"]
orig_raw = k.split('orig_raw=')[1]
parts = orig_raw.split('; ')
event_id = [part for part in parts if part.startswith('EventID')]
print(event_id)

# print(json.dumps(j["_raw"], indent=4))
