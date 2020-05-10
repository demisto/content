import pytest


def test_strip():
    test_string = "T'hi's >is a t[]es[t t<]ext."
    from PcapMinerV2 import strip
    assert strip(test_string) == "Thisisatesttext."


def test_heirarchy_to_md():
    test_heirarchy = {'First Layer': 50,
                      'Second Layer': 50,
                      'Third Layer': 50,
                      'Fourth Layer': 50
                      }
    from PcapMinerV2 import hierarchy_to_md
    assert hierarchy_to_md(test_heirarchy) == '|Layer| # of Packets|% of Packets|\n|---|----|---|\n' \
                                              '| -> First Layer|50|25.0%|\n| -> Fourth Layer|50|25.0%|\n' \
                                              '| -> Second Layer|50|25.0%|\n| -> Third Layer|50|25.0%|\n'


def test_conversations_to_md():
    converstation_test = {
        ('1.1.1.1', '2.2.2.2'): 15,
        ('1.1.1.3', '2.2.2.2'): 15,
        ('1.1.1.3', '8.8.8.8'): 15
    }
    from PcapMinerV2 import conversations_to_md
    assert conversations_to_md(converstation_test, 4) == "|A|B|# of Packets|\n|---|---|---|\n|1.1.1.1|2.2.2.2|15|\n" \
                                                         "|1.1.1.3|2.2.2.2|15|\n|1.1.1.3|8.8.8.8|15|\n"


def test_remove_nones():
    d = {'Oh': 1,
         'My': None,
         'God': None}
    from PcapMinerV2 import remove_nones
    assert remove_nones(d) == {'Oh': 1}


args_to_test = [
    ({}, {'ID': 1}, None, {}),  # Test that just an ID is not added.
    ({}, {'ID': 2, 'Input': 'wow'}, None, {2: {'ID': 2, 'Input': 'wow'}}),  # Test data added correctly
    ({}, {'ID': 2, 'Input': 'wow'}, 10, {10: {'ID': 2, 'Input': 'wow'}}),  # Test that a future id is added instead
    ({}, {'ID': 2}, 10, {}),  # Tests that future ID doesn't add empty data.
    ({2: {'ID': 2, 'Input': 'wow'}}, {'ID': 2, 'Input': 'amazing', 'new_key': 'new'}, None,
     {2: {'ID': 2, 'Input': 'amazing', 'new_key': 'new'}}),  # Test that ID changed and new added
    ({2: {'ID': 2, 'Input': 'wow'}}, {'ID': 2, 'Input': 'amazing', 'new_key': 'new'}, 10,
     {10: {'ID': 2, 'Input': 'amazing', 'new_key': 'new'}}),  # Test that ID changed and new added and future_id added
    ({}, {'noID': 15}, None, {})  # Test that data without ID isn't added
]
@pytest.mark.parametrize("main_data, data_to_add, future_id, wanted_output", args_to_test)
def test_add_to_data(mocker, main_data, data_to_add, future_id, wanted_output):
    from PcapMinerV2 import add_to_data
    add_to_data(main_data, data_to_add, future_id)

    assert main_data == wanted_output
