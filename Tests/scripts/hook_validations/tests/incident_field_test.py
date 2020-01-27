from Tests.scripts.hook_validations.incident_field import IncidentFieldValidator


def test_is_valid_name_sanity():
    validator = IncidentFieldValidator('temp_file', check_git=False)
    validator.current_incident_field = {
        'cliName': 'sanity name',
        'name': 'sanity name',
        'id': 'incident',
        'content': True,
    }

    assert validator.is_valid_name()
    assert validator.is_valid()


def test_is_valid_name_bad_cli_name():
    validator = IncidentFieldValidator('temp_file', check_git=False)
    validator.current_incident_field = {
        'cliName': 'Incident',
        'name': 'sanity name',
        'content': True,
    }

    assert not validator.is_valid_name()
    assert not validator.is_valid()

    validator.current_incident_field = {
        'cliName': 'case',
        'name': 'sanity name',
        'content': True,
    }
    assert not validator.is_valid_name()
    assert not validator.is_valid()

    validator.current_incident_field = {
        'cliName': 'Playbook',
        'name': 'sanity name',
        'content': True,
    }
    assert not validator.is_valid_name()
    assert not validator.is_valid()

    validator.current_incident_field = {
        'cliName': 'Alerting feature',
        'name': 'sanity name',
        'content': True,
    }
    assert not validator.is_valid_name()
    assert not validator.is_valid()

    validator.current_incident_field = {
        'cliName': 'INciDeNts',
        'name': 'sanity name',
        'content': True,
    }
    assert not validator.is_valid_name()
    assert not validator.is_valid()


def test_is_valid_name_bad_name():
    validator = IncidentFieldValidator('temp_file', check_git=False)
    validator.current_incident_field = {
        'cliName': 'sanity name',
        'name': 'Incident',
        'content': True,
    }

    assert not validator.is_valid_name()
    assert not validator.is_valid()

    validator.current_incident_field = {
        'cliName': 'sanity name',
        'name': 'case',
        'content': True,
    }
    assert not validator.is_valid_name()
    assert not validator.is_valid()

    validator.current_incident_field = {
        'cliName': 'sanity name',
        'name': 'Playbook',
        'content': True,
    }
    assert not validator.is_valid_name()
    assert not validator.is_valid()

    validator.current_incident_field = {
        'cliName': 'sanity name',
        'name': 'Alerting feature',
        'content': True,
    }
    assert not validator.is_valid_name()
    assert not validator.is_valid()

    validator.current_incident_field = {
        'cliName': 'sanity name',
        'name': 'INciDeNts',
        'content': True,
    }
    assert not validator.is_valid_name()
    assert not validator.is_valid()


def test_is_valid_content_flag_sanity():
    validator = IncidentFieldValidator('temp_file', check_git=False)
    validator.current_incident_field = {
        'content': True
    }

    assert validator.is_valid_content_flag()
    assert validator.is_valid()


def test_is_valid_content_flag_invalid_values():
    validator = IncidentFieldValidator('temp_file', check_git=False)
    validator.current_incident_field = {
        'content': False
    }

    assert not validator.is_valid_content_flag()
    assert not validator.is_valid()

    validator.current_incident_field = {
        'something': True
    }

    assert not validator.is_valid_content_flag()
    assert not validator.is_valid()


def test_is_valid_system_flag_sanity():
    validator = IncidentFieldValidator('temp_file', check_git=False)
    validator.current_incident_field = {
        'system': False,
        'content': True,
    }

    assert validator.is_valid_system_flag()
    assert validator.is_valid()

    validator.current_incident_field = {
        'content': True,
    }
    assert validator.is_valid_system_flag()
    assert validator.is_valid()


def test_is_valid_system_flag_invalid():
    validator = IncidentFieldValidator('temp_file', check_git=False)
    validator.current_incident_field = {
        'system': True,
        'content': True,
    }

    assert not validator.is_valid_system_flag()
    assert not validator.is_valid()
