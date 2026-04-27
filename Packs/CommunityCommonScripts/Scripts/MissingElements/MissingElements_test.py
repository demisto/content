from MissingElements import missing_elements, sanitize_input


def test_no_missing_elements():
    value = [12, 13, 14, 15, 16]
    start = None
    end = None
    value, start, end = sanitize_input(value, start, end)
    response = missing_elements(value, start, end)
    assert response.outputs == {"output": None}


def test_string_in_list_missing_elements():
    value = [12, 13, "14", 16, "17"]
    start = None
    end = None
    value, start, end = sanitize_input(value, start, end)
    response = missing_elements(value, start, end)
    assert response.outputs == {"output": [15]}


def test_list_in_string_missing_elements():
    value = "[12,13,14,16,17]"
    start = None
    end = None
    value, start, end = sanitize_input(value, start, end)
    response = missing_elements(value, start, end)
    assert response.outputs == {"output": [15]}


def test_list_in_string_quotes_missing_elements():
    value = '[12,"13",14,"16",17]'
    start = None
    end = None
    value, start, end = sanitize_input(value, start, end)
    response = missing_elements(value, start, end)
    assert response.outputs == {"output": [15]}


def test_single_missing_elements():
    value = [12, 13, 14, 16, 17]
    start = None
    end = None
    value, start, end = sanitize_input(value, start, end)
    response = missing_elements(value, start, end)
    assert response.outputs == {"output": [15]}


def test_multiple_missing_elements():
    value = [12, 14, 17]
    start = None
    end = None
    value, start, end = sanitize_input(value, start, end)
    response = missing_elements(value, start, end)
    assert response.outputs == {"output": [13, 15, 16]}


def test_start_missing_elements():
    value = [12, 14, 17]
    start = "10"
    end = None
    value, start, end = sanitize_input(value, start, end)
    response = missing_elements(value, start, end)
    assert response.outputs == {"output": [10, 11, 13, 15, 16]}


def test_end_missing_elements():
    value = [12, 14, 17]
    start = None
    end = "20"
    value, start, end = sanitize_input(value, start, end)
    response = missing_elements(value, start, end)
    assert response.outputs == {"output": [13, 15, 16, 18, 19, 20]}


def test_start_end_missing_elements():
    value = [12, 14, 17]
    start = "10"
    end = "20"
    value, start, end = sanitize_input(value, start, end)
    response = missing_elements(value, start, end)
    assert response.outputs == {"output": [10, 11, 13, 15, 16, 18, 19, 20]}
