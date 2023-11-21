# adding so null don't get seen as variable.
null = None
false = False

MOCK_RAW_ASSET_BY_IP = {
    "info": {
        "time_end": "2022-09-07T19:08:36.038Z",
        "time_start": "2022-09-07T18:57:37.275Z",
        "id": "fake_asset_id",
        "uuid": "fake_asset_id",
        "operating_system": ["Linux Kernel 3.2"],
        "fqdn": ["1.2.3.1.bc.googleusercontent.com"],
        "counts": {
            "vulnerabilities": {
                "total": 26,
                "severities": [
                    {"count": 19, "level": 0, "name": "Info"},
                    {"count": 1, "level": 1, "name": "Low"},
                    {"count": 6, "level": 2, "name": "Medium"},
                    {"count": 0, "level": 3, "name": "High"},
                    {"count": 0, "level": 4, "name": "Critical"},
                ],
            },
            "audits": {
                "total": 0,
                "statuses": [
                    {"count": 0, "level": 1, "name": "Passed"},
                    {"count": 0, "level": 2, "name": "Warning"},
                    {"count": 0, "level": 3, "name": "Failed"},
                ],
            },
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
                "last_seen": "2022-09-07T19:25:28.329Z",
            }
        ],
        "tags": [
            {
                "tag_uuid": "fake_asset_id",
                "tag_key": "GCP-Tags",
                "tag_value": "GCP",
                "added_by": "fake_asset_id",
                "added_at": "2022-09-07T19:58:03.786Z",
                "source": "static",
            }
        ],
        "interfaces": [
            {
                "name": "UNKNOWN",
                "fqdn": ["1.2.3.1.bc.googleusercontent.com"],
                "mac_address": [],
                "ipv4": ["1.3.2.1"],
                "ipv6": [],
            }
        ],
        "ipv4": ["1.3.2.1"],
    }
}

MOCK_RAW_ASSET_ATTRIBUTES = {
    "attributes": [
        {"name": "owner", "id": "fake_asset_id", "value": "owner@demisto.com"}
    ]
}

EXPECTED_ASSET_INFO_RESULTS = {
    "attributes": [{"owner": "owner@demisto.com"}],
    "counts": {
        "audits": {
            "statuses": [
                {"count": 0, "level": 1, "name": "Passed"},
                {"count": 0, "level": 2, "name": "Warning"},
                {"count": 0, "level": 3, "name": "Failed"},
            ],
            "total": 0,
        },
        "vulnerabilities": {
            "severities": [
                {"count": 19, "level": 0, "name": "Info"},
                {"count": 1, "level": 1, "name": "Low"},
                {"count": 6, "level": 2, "name": "Medium"},
                {"count": 0, "level": 3, "name": "High"},
                {"count": 0, "level": 4, "name": "Critical"},
            ],
            "total": 26,
        },
    },
    "created_at": "2022-09-07T19:08:42.737Z",
    "first_seen": "2022-09-07T19:08:36.038Z",
    "fqdn": ["1.2.3.1.bc.googleusercontent.com"],
    "has_agent": false,
    "id": "fake_asset_id",
    "interfaces": [
        {
            "fqdn": ["1.2.3.1.bc.googleusercontent.com"],
            "ipv4": ["1.3.2.1"],
            "ipv6": [],
            "mac_address": [],
            "name": "UNKNOWN",
        }
    ],
    "ipv4": ["1.3.2.1"],
    "last_authenticated_scan_date": null,
    "last_licensed_scan_date": "2022-09-07T19:08:36.038Z",
    "last_scan_id": "fake_asset_id",
    "last_scan_target": "1.3.2.1",
    "last_schedule_id": "template-fake_asset_id",
    "last_seen": "2022-09-07T19:25:28.329Z",
    "operating_system": ["Linux Kernel 3.2"],
    "sources": [
        {
            "first_seen": "2022-09-07T19:08:36.038Z",
            "last_seen": "2022-09-07T19:25:28.329Z",
            "name": "NESSUS_SCAN",
        }
    ],
    "tags": [
        {
            "added_at": "2022-09-07T19:58:03.786Z",
            "added_by": "fake_asset_id",
            "source": "static",
            "tag_key": "GCP-Tags",
            "tag_uuid": "fake_asset_id",
            "tag_value": "GCP",
        }
    ],
    "time_end": "2022-09-07T19:08:36.038Z",
    "time_start": "2022-09-07T18:57:37.275Z",
    "updated_at": "2022-11-18T16:41:46.737Z",
    "uuid": "fake_asset_id",
}

export_vulnerabilities_response = [
    {
        "asset": {
            "device_type": "general-purpose",
            "fqdn": "some_fqdn",
            "hostname": "some_hostname",
            "uuid": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
            "ipv4": "00.000.00.00",
            "last_unauthenticated_results": "2022-08-14T14:53:02Z",
            "operating_system": ["Linux Kernel 2.6"],
            "network_id": "00000000-0000-0000-0000-000000000000",
            "tracked": True,
        },
        "output": "some_output",
        "plugin": {
            "bid": [11111],
            "checks_for_default_account": False,
            "checks_for_malware": False,
            "cpe": ["cpe:/z:cpe:some_cpe", "cpe:/z:cpe:some_cpe"],
            "cve": ["CVE-2004-2761"],
            "cvss3_base_score": 0,
            "cvss3_temporal_score": 0,
            "cvss_base_score": 0,
            "cvss_temporal_score": 0,
            "description": "some_description",
            "exploit_available": True,
            "exploit_framework_canvas": True,
            "exploit_framework_core": True,
            "exploit_framework_d2_elliot": True,
            "exploit_framework_exploithub": True,
            "exploit_framework_metasploit": True,
            "exploitability_ease": "Exploits are available",
            "exploited_by_malware": True,
            "exploited_by_nessus": True,
            "family": "General",
            "family_id": 11,
            "has_patch": True,
            "id": 11111,
            "in_the_news": True,
            "name": "some_name",
            "modification_date": "2023-06-15T00:00:00Z",
            "publication_date": "2012-04-04T00:00:00Z",
            "risk_factor": "None",
            "solution": "solution.",
            "synopsis": "synopsis",
            "type": "remote",
            "unsupported_by_vendor": True,
            "version": "0.0",
            "vuln_publication_date": "2005-04-19T00:00:00Z",
            "xrefs": [
                {"type": "CERT", "id": "000000"},
                {"type": "CWE", "id": "000000"},
            ],
            "vpr": {
                "score": 5.2,
                "drivers": {
                    "age_of_vuln": {"lower_bound": 345},
                    "exploit_code_maturity": "PROOF_OF_CONCEPT",
                    "cvss_impact_score_predicted": True,
                    "cvss3_impact_score": 3.6,
                    "threat_intensity_last28": "VERY_LOW",
                    "threat_sources_last28": ["No recorded events"],
                    "product_coverage": "LOW",
                },
                "updated": "2023-04-18T11:52:55Z",
            },
        },
        "port": {"port": 21, "protocol": "TCP", "service": "ftp"},
        "scan": {
            "completed_at": "2022-08-14T14:53:18.852Z",
            "schedule_uuid": "template-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "started_at": "2022-08-14T14:22:51.230Z",
            "uuid": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
        },
        "severity": "info",
        "severity_id": 0,
        "severity_default_id": 0,
        "severity_modification_type": "NONE",
        "first_found": "2023-08-15T15:56:18.852Z",
        "last_found": "2023-08-15T15:56:18.852Z",
        "state": "OPEN",
        "indexed": "2023-08-15T15:56:18.852Z",
    }
]

export_assets_response = [
    {
        "id": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
        "has_agent": False,
        "has_plugin_results": True,
        "created_at": "2024-08-13T15:11:08.145Z",
        "terminated_at": None,
        "terminated_by": None,
        "updated_at": "2024-08-13T15:11:08.145Z",
        "deleted_at": None,
        "deleted_by": None,
        "first_seen": "2024-08-13T15:11:08.145Z",
        "last_seen": "2024-08-13T15:11:08.145Z",
        "first_scan_time": "2024-08-13T15:11:08.145Z",
        "last_scan_time": "2024-08-13T15:11:08.145Z",
        "last_authenticated_scan_date": None,
        "last_licensed_scan_date": "2022-12-28T17:10:47.756Z",
        "last_scan_id": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
        "last_schedule_id": "template-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "azure_vm_id": None,
        "azure_resource_id": None,
        "gcp_project_id": None,
        "gcp_zone": None,
        "gcp_instance_id": None,
        "aws_ec2_instance_ami_id": None,
        "aws_ec2_instance_id": None,
        "agent_uuid": None,
        "bios_uuid": None,
        "network_id": "00000000-0000-0000-0000-000000000000",
        "network_name": "Default",
        "aws_owner_id": None,
        "aws_availability_zone": None,
        "aws_region": None,
        "aws_vpc_id": None,
        "aws_ec2_instance_group_name": None,
        "aws_ec2_instance_state_name": None,
        "aws_ec2_instance_type": None,
        "aws_subnet_id": None,
        "aws_ec2_product_code": None,
        "aws_ec2_name": None,
        "mcafee_epo_guid": None,
        "mcafee_epo_agent_guid": None,
        "servicenow_sysid": None,
        "bigfix_asset_id": None,
        "agent_names": [],
        "installed_software": ["cpe:/z:cpe:some_cpe"],
        "ipv4s": ["00.000.00.00"],
        "ipv6s": [],
        "fqdns": ["some_fqdns"],
        "mac_addresses": [],
        "netbios_names": [],
        "operating_systems": ["Linux Kernel 2.6"],
        "system_types": ["general-purpose"],
        "hostnames": [],
        "ssh_fingerprints": ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"],
        "qualys_asset_ids": [],
        "qualys_host_ids": [],
        "manufacturer_tpm_ids": [],
        "symantec_ep_hardware_keys": [],
        "sources": [
            {
                "name": "SOME_SCAN",
                "first_seen": "2024-08-13T15:11:08.145Z",
                "last_seen": "2024-08-13T15:11:08.145Z",
            }
        ],
        "tags": [
            {
                "uuid": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
                "key": "some_key",
                "value": "test",
                "added_by": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
                "added_at": "2024-08-13T15:11:08.145Z",
            }
        ],
        "network_interfaces": [
            {
                "name": "UNKNOWN",
                "virtual": None,
                "aliased": None,
                "fqdns": ["some_fqdns"],
                "mac_addresses": [],
                "ipv4s": ["00.000.00.00"],
                "ipv6s": [],
            }
        ],
    }
]
