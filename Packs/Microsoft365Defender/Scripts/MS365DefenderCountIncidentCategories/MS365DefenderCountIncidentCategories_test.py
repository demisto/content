def test_count_dict():
    from MS365DefenderCountIncidentCategories import count_dict
    input_value = "Impact,Malware,Impact,Malware,Impact,InitialAccess"
    expected_output = [
        {'category': 'Impact', 'count': 3},
        {'category': 'Malware', 'count': 2},
        {'category': 'InitialAccess', 'count': 1}
    ]
    assert count_dict(input_value) == expected_output
