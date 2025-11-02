def test_map_to_command_args_set_issue_args_only(mocker):
    """
    GIVEN:
        Arguments dictionary with only set_issue arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Arguments are mapped to set_issue_args_dict and update_issue_args_dict is empty.
    """
    from UpdateIssue import map_to_command_args

    args = {"systems": "web-server-01,db-server-02", "type": "Security Incident", "details": "Investigation details"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["systems"] == "web-server-01,db-server-02"
    assert set_issue_args_dict["type"] == "Security Incident"
    assert set_issue_args_dict["details"] == "Investigation details"
    assert len(update_issue_args_dict) == 0


def test_map_to_command_args_update_issue_args_only(mocker):
    """
    GIVEN:
        Arguments dictionary with only update_issue arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Arguments are mapped to update_issue_args_dict and set_issue_args_dict is empty.
    """
    from UpdateIssue import map_to_command_args

    args = {
        "name": "Test Issue",
        "assigned_user_mail": "user@example.com",
        "severity": "3",
        "occurred": "2024-01-01T00:00:00Z",
        "phase": "investigation",
    }

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert len(set_issue_args_dict) == 0
    assert update_issue_args_dict["name"] == "Test Issue"
    assert update_issue_args_dict["assigned_user_mail"] == "user@example.com"
    assert update_issue_args_dict["severity"] == "3"
    assert update_issue_args_dict["occurred"] == "2024-01-01T00:00:00Z"
    assert update_issue_args_dict["phase"] == "investigation"


def test_map_to_command_args_mixed_arguments(mocker):
    """
    GIVEN:
        Arguments dictionary with both set_issue and update_issue arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Arguments are correctly distributed to both dictionaries.
    """
    from UpdateIssue import map_to_command_args

    args = {
        "systems": "server-01,server-02",
        "type": "Malware",
        "name": "Security Incident",
        "severity": "4",
        "phase": "containment",
    }

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["systems"] == "server-01,server-02"
    assert set_issue_args_dict["type"] == "Malware"
    assert update_issue_args_dict["name"] == "Security Incident"
    assert update_issue_args_dict["severity"] == "4"
    assert update_issue_args_dict["phase"] == "containment"


def test_map_to_command_args_custom_fields_mapping(mocker):
    """
    GIVEN:
        Arguments dictionary with custom_fields argument.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        custom_fields is mapped to customFields in set_issue_args_dict.
    """
    from UpdateIssue import map_to_command_args

    args = {"custom_fields": '{"department":"IT","priority":"high"}'}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["customFields"] == '{"department":"IT","priority":"high"}'
    assert "custom_fields" not in set_issue_args_dict
    assert len(update_issue_args_dict) == 0


def test_map_to_command_args_id_argument(mocker):
    """
    GIVEN:
        Arguments dictionary with id argument.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        id is added to both set_issue_args_dict and update_issue_args_dict.
    """
    from UpdateIssue import map_to_command_args

    args = {"id": "12345", "name": "Test Issue", "type": "Security"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["id"] == "12345"
    assert set_issue_args_dict["type"] == "Security"
    assert update_issue_args_dict["id"] == "12345"
    assert update_issue_args_dict["name"] == "Test Issue"


def test_map_to_command_args_id_only(mocker):
    """
    GIVEN:
        Arguments dictionary with only id argument.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        id is added to both dictionaries and no other fields are present.
    """
    from UpdateIssue import map_to_command_args

    args = {"id": "67890"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["id"] == "67890"
    assert update_issue_args_dict["id"] == "67890"
    assert len(set_issue_args_dict) == 1
    assert len(update_issue_args_dict) == 1


def test_map_to_command_args_unknown_arguments(mocker):
    """
    GIVEN:
        Arguments dictionary with unknown/unsupported arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Unknown arguments are ignored and not included in either dictionary.
    """
    from UpdateIssue import map_to_command_args

    args = {"name": "Test Issue", "unknown_field": "some_value", "another_unknown": "another_value", "systems": "server-01"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["systems"] == "server-01"
    assert update_issue_args_dict["name"] == "Test Issue"
    assert "unknown_field" not in set_issue_args_dict
    assert "unknown_field" not in update_issue_args_dict
    assert "another_unknown" not in set_issue_args_dict
    assert "another_unknown" not in update_issue_args_dict


def test_map_to_command_args_empty_arguments(mocker):
    """
    GIVEN:
        Empty arguments dictionary.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Both returned dictionaries are empty.
    """
    from UpdateIssue import map_to_command_args

    args = {}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert len(set_issue_args_dict) == 0
    assert len(update_issue_args_dict) == 0


def test_map_to_command_args_all_set_issue_fields(mocker):
    """
    GIVEN:
        Arguments dictionary with all possible set_issue arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        All set_issue arguments are correctly mapped with custom_fields becoming customFields.
    """
    from UpdateIssue import map_to_command_args

    args = {
        "systems": "web-01,db-01,app-01",
        "type": "Data Breach",
        "custom_fields": '{"cost":"50000","impact":"high"}',
        "details": "Comprehensive incident details and timeline",
    }

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["systems"] == "web-01,db-01,app-01"
    assert set_issue_args_dict["type"] == "Data Breach"
    assert set_issue_args_dict["customFields"] == '{"cost":"50000","impact":"high"}'
    assert set_issue_args_dict["details"] == "Comprehensive incident details and timeline"
    assert len(update_issue_args_dict) == 0


def test_map_to_command_args_all_update_issue_fields(mocker):
    """
    GIVEN:
        Arguments dictionary with all possible update_issue arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        All update_issue arguments are correctly mapped.
    """
    from UpdateIssue import map_to_command_args

    args = {
        "name": "Critical Security Incident",
        "assigned_user_mail": "analyst@company.com",
        "severity": "4",
        "occurred": "2024-01-15T14:30:00Z",
        "phase": "recovery",
    }

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert len(set_issue_args_dict) == 0
    assert update_issue_args_dict["name"] == "Critical Security Incident"
    assert update_issue_args_dict["assigned_user_mail"] == "analyst@company.com"
    assert update_issue_args_dict["severity"] == "4"
    assert update_issue_args_dict["occurred"] == "2024-01-15T14:30:00Z"
    assert update_issue_args_dict["phase"] == "recovery"


def test_map_to_command_args_complete_scenario(mocker):
    """
    GIVEN:
        Arguments dictionary with all types of arguments including id.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        All arguments are correctly distributed with proper mappings.
    """
    from UpdateIssue import map_to_command_args

    args = {
        "id": "INC-2024-001",
        "name": "Advanced Persistent Threat",
        "assigned_user_mail": "senior.analyst@company.com",
        "severity": "4",
        "occurred": "2024-01-14T08:45:00Z",
        "phase": "containment",
        "systems": "DC01,EXCH01,WEB01",
        "type": "APT",
        "custom_fields": '{"threat_actor":"APT29","ttp":"T1566.001"}',
        "details": "Nation-state threat actor detected",
        "unknown_arg": "ignored_value",
    }

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    # Check set_issue_args_dict
    assert set_issue_args_dict["id"] == "INC-2024-001"
    assert set_issue_args_dict["systems"] == "DC01,EXCH01,WEB01"
    assert set_issue_args_dict["type"] == "APT"
    assert set_issue_args_dict["customFields"] == '{"threat_actor":"APT29","ttp":"T1566.001"}'
    assert set_issue_args_dict["details"] == "Nation-state threat actor detected"

    # Check update_issue_args_dict
    assert update_issue_args_dict["id"] == "INC-2024-001"
    assert update_issue_args_dict["name"] == "Advanced Persistent Threat"
    assert update_issue_args_dict["assigned_user_mail"] == "senior.analyst@company.com"
    assert update_issue_args_dict["severity"] == "4"
    assert update_issue_args_dict["occurred"] == "2024-01-14T08:45:00Z"
    assert update_issue_args_dict["phase"] == "containment"

    # Check unknown arguments are ignored
    assert "unknown_arg" not in set_issue_args_dict
    assert "unknown_arg" not in update_issue_args_dict


def test_map_to_command_args_none_values(mocker):
    """
    GIVEN:
        Arguments dictionary with None values.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        None values are preserved in the output dictionaries.
    """
    from UpdateIssue import map_to_command_args

    args = {"name": None, "systems": None, "severity": "3", "type": "Security"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["systems"] is None
    assert set_issue_args_dict["type"] == "Security"
    assert update_issue_args_dict["name"] is None
    assert update_issue_args_dict["severity"] == "3"


def test_map_to_command_args_empty_string_values(mocker):
    """
    GIVEN:
        Arguments dictionary with empty string values.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Empty string values are preserved in the output dictionaries.
    """
    from UpdateIssue import map_to_command_args

    args = {"name": "", "details": "", "severity": "2", "systems": "server-01"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["details"] == ""
    assert set_issue_args_dict["systems"] == "server-01"
    assert update_issue_args_dict["name"] == ""
    assert update_issue_args_dict["severity"] == "2"
