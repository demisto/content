MESSAGES = {
    'INVALID_INDICATOR_TYPE': 'Invalid indicator type {}. Valid values are certficate_sha1, certificate_sha1, domain, '
                              'email, hash_md5, hash_sha256, ip, pdb_path, soa_email, url, whois_email.',
    'INVALID_SOURCE': 'Invalid indicator source {}. Valid values are osint, riskiq.',
    'INVALID_PAGE_SIZE': '{} is an invalid value for page size. Page size must be between 1 and int32.',
    'INVALID_PAGE_NUMBER': '{} is an invalid value for page number. Page number must be between 0 and int32.',
    "INVALID_PROFILE_TYPE": "Invalid profile type {}. Valid profile types are actor, backdoor, tool.",
    "REQUIRED_INDICATOR_VALUE": "'indicator_value' must be specified if the arguments 'source' or 'category' are used.",
    "REQUIRED_ARGUMENT": "Invalid argument value. {} is a required argument.",
    "INVALID_PRIORITY_LEVEL": "Invalid priority level {}. Valid priority level are low, medium, high.",
    "NOT_VALID_PAGE_SIZE": "{} is an invalid value for page size. Page size must be between 1 and 1000."
}

intel_profile_indicator_invalid_args = [
    ({"id": ""}, MESSAGES['REQUIRED_ARGUMENT'].format('id')),
    ({"id": "apt33", "page_size": -1}, MESSAGES['INVALID_PAGE_SIZE'].format(-1)),
    ({"id": "apt33", "page_size": 12345678901234}, MESSAGES['INVALID_PAGE_SIZE'].format(12345678901234)),
    ({"id": "apt33", "page_number": -1}, MESSAGES['INVALID_PAGE_NUMBER'].format(-1)),
    ({"id": "apt33", "page_number": 12345678901234}, MESSAGES['INVALID_PAGE_NUMBER'].format(12345678901234)),
    ({"id": "apt33", "type": "dummy"}, MESSAGES['INVALID_INDICATOR_TYPE'].format("dummy")),
    ({"id": "apt33", "source": "dummy"}, MESSAGES['INVALID_SOURCE'].format("dummy")),
]

list_intel_profile_invalid_args = [
    ({"type": "abc"}, MESSAGES["INVALID_PROFILE_TYPE"].format("abc")),
    ({"source": "osint"}, MESSAGES["REQUIRED_INDICATOR_VALUE"]),
    ({"indicator_value": "abc.com", "source": "dummy"}, MESSAGES['INVALID_SOURCE'].format("dummy")),
    ({"category": "osint"}, MESSAGES["REQUIRED_INDICATOR_VALUE"]),
    ({"page_size": -5}, MESSAGES["NOT_VALID_PAGE_SIZE"].format(-5)),
    ({"page_size": 5000}, MESSAGES["NOT_VALID_PAGE_SIZE"].format(5000))
]

list_asi_insights_invalid_args = [
    ({"priority": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("priority")),
    ({"priority": "dummy"}, MESSAGES["INVALID_PRIORITY_LEVEL"].format("dummy")),
    ({"priority": "low", "page_size": -5}, MESSAGES["NOT_VALID_PAGE_SIZE"].format(-5)),
    ({"priority": "low", "page_size": 5000}, MESSAGES["NOT_VALID_PAGE_SIZE"].format(5000))
]

list_asi_assets_invalid_args = [
    ({"id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("id")),
    ({"id": "100", "segment_by": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("segment_by")),
    ({"id": "100", "segment_by": "100", "page_size": -1}, MESSAGES['INVALID_PAGE_SIZE'].format(-1)),
    ({"id": "100", "segment_by": "100", "page_size": 12345678901234},
     MESSAGES['INVALID_PAGE_SIZE'].format(12345678901234)),
    ({"id": "100", "segment_by": "100", "page_number": -1}, MESSAGES['INVALID_PAGE_NUMBER'].format(-1)),
    ({"id": "100", "segment_by": "100", "page_number": 12345678901234},
     MESSAGES['INVALID_PAGE_NUMBER'].format(12345678901234))
]

list_third_party_asi_invalid_args = [
    ({"page_size": -1}, MESSAGES['INVALID_PAGE_SIZE'].format(-1)),
    ({"page_size": 12345678901234}, MESSAGES['INVALID_PAGE_SIZE'].format(12345678901234)),
    ({"page_number": -1}, MESSAGES['INVALID_PAGE_NUMBER'].format(-1)),
    ({"page_number": 12345678901234}, MESSAGES['INVALID_PAGE_NUMBER'].format(12345678901234))
]

common_args = [
    ({}, {'page': 0, 'size': 50}),
    ({"page_size": ""}, {'page': 0, 'size': 50}),
    ({"page_size": "1"}, {'page': 0, 'size': 1}),
    ({"page_size": "100"}, {'page': 0, 'size': 100}),
    ({"page_number": ""}, {'size': 50, "page": 0}),
    ({"page_number": "1"}, {'size': 50, "page": 1}),
    ({"page_size": "1", "page_number": "1"}, {"size": 1, "page": 1})
]

list_third_party_asi_insights_invalid_args = [
    ({"id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("id")),
    ({"id": 88256, "priority": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("priority")),
    ({"id": 88256, "priority": "dummy"}, MESSAGES["INVALID_PRIORITY_LEVEL"].format("dummy")),
    ({"id": 88256, "priority": "low", "page_size": -5}, MESSAGES["NOT_VALID_PAGE_SIZE"].format(-5)),
    ({"id": 88256, "priority": "low", "page_size": 5000}, MESSAGES["NOT_VALID_PAGE_SIZE"].format(5000))
]

list_asi_observation_invalid_args = [
    ({"cve_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("cve_id")),
    ({"cve_id": "CVE-123", "page_size": -1}, MESSAGES['INVALID_PAGE_SIZE'].format(-1)),
    ({"cve_id": "CVE-123", "page_size": 12345678901234},
     MESSAGES['INVALID_PAGE_SIZE'].format(12345678901234)),
    ({"cve_id": "CVE-123", "page_number": -1}, MESSAGES['INVALID_PAGE_NUMBER'].format(-1)),
    ({"cve_id": "CVE-123", "page_number": 12345678901234},
     MESSAGES['INVALID_PAGE_NUMBER'].format(12345678901234))
]
list_third_party_asi_assets_invalid_args = [
    ({"vendor_id": "dummy"}, '"{}" is not a valid number'.format("dummy")),
    ({"vendor_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("vendor_id")),
    ({"vendor_id": "123", "id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("id")),
    ({"vendor_id": "123", "id": "100", "segment_by": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("segment_by")),
    ({"vendor_id": "123", "id": "100", "segment_by": "100", "page_size": -1}, MESSAGES['INVALID_PAGE_SIZE'].format(-1)),
    ({"vendor_id": "123", "id": "100", "segment_by": "100", "page_size": 12345678901234},
     MESSAGES['INVALID_PAGE_SIZE'].format(12345678901234)),
    ({"vendor_id": "123", "id": "100", "segment_by": "100", "page_number": -1},
     MESSAGES['INVALID_PAGE_NUMBER'].format(-1)),
    ({"vendor_id": "123", "id": "100", "segment_by": "100", "page_number": 12345678901234},
     MESSAGES['INVALID_PAGE_NUMBER'].format(12345678901234))
]

list_third_party_asi_vulnerable_component_invalid_args = [
    ({"id": ""}, MESSAGES['REQUIRED_ARGUMENT'].format("id")),
    ({"id": 45998, "page_size": -1}, MESSAGES['INVALID_PAGE_SIZE'].format(-1)),
    ({"id": 45998, "page_size": 12345678901234}, MESSAGES['INVALID_PAGE_SIZE'].format(12345678901234)),
    ({"id": 45998, "page_number": -1}, MESSAGES['INVALID_PAGE_NUMBER'].format(-1)),
    ({"id": 45998, "page_number": 12345678901234}, MESSAGES['INVALID_PAGE_NUMBER'].format(12345678901234))
]

list_third_party_asi_observation_invalid_args = [
    ({"id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("id")),
    ({"id": 45998, "cve_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("cve_id")),
    ({"id": 45998, "cve_id": "CVE-123", "page_size": -1}, MESSAGES['INVALID_PAGE_SIZE'].format(-1)),
    ({"id": 45998, "cve_id": "CVE-123", "page_size": 12345678901234},
     MESSAGES['INVALID_PAGE_SIZE'].format(12345678901234)),
    ({"id": 45998, "cve_id": "CVE-123", "page_number": -1}, MESSAGES['INVALID_PAGE_NUMBER'].format(-1)),
    ({"id": 45998, "cve_id": "CVE-123", "page_number": 12345678901234},
     MESSAGES['INVALID_PAGE_NUMBER'].format(12345678901234))
]

list_my_attack_surface_invalid_args = [
    ({"page_size": -5}, MESSAGES["NOT_VALID_PAGE_SIZE"].format(-5)),
    ({"page_size": 5000}, MESSAGES["NOT_VALID_PAGE_SIZE"].format(5000))
]
