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


args_to_test = [
    ({}, {'ID': 1}, None, {}),  # Test that just an ID is not added.
    ({}, {'ID': 2, 'Input': 'wow'}, None, {2: {'ID': 2, 'Input': 'wow'}}),  # Test data added correctly
    ({}, {'ID': 2, 'Input': 'wow'}, 10, {10: {'ID': 2, 'Input': 'wow'}}),  # Test that a future id is added instead
    ({}, {'ID': 2}, 10, {}),  # Tests that future ID doesn't add empty data.
    ({2: {'ID': 2, 'Input': 'wow'}}, {'ID': 2, 'Input': 'amazing', 'new_key': 'new'}, None,
     {2: {'ID': 2, 'Input': 'amazing', 'new_key': 'new'}}),  # Test that ID changed and new added
    ({2: {'ID': 2, 'Input': 'wow'}}, {'ID': 2, 'Input': 'amazing', 'new_key': 'new'}, 10,
     {10: {'ID': 2, 'Input': 'amazing', 'new_key': 'new'}}),  # Test that ID changed and new added and future_id added
    ({}, {'noID': 15}, None, {}),  # Test that data without ID isn't added
    ({}, {'ID': 1, 'EntryID': 15}, None, {})  # Test that just an ID and EntryID is not added.
]
@pytest.mark.parametrize("main_data, data_to_add, future_id, wanted_output", args_to_test)
def test_add_to_data(main_data, data_to_add, future_id, wanted_output):
    from PcapMinerV2 import add_to_data
    add_to_data(main_data, data_to_add, future_id)

    assert main_data == wanted_output


def test_mine_pcap():
    file_path = './TestData/smb-on-windows-10.pcapng'
    wpa_password = ""
    conversation_number_to_display = 15
    is_flows = True
    is_reg_extract = True
    extracted_protocols = ['DNS', 'SMB2']
    pcap_filter = ''
    homemade_regex = 'M-SEARCH * (.+)'
    pcap_filter_new_file_path = ''
    unique_ips = False
    rsa_key_file_path = ''
    from PcapMinerV2 import PCAP
    pcap = PCAP(is_reg_extract, extracted_protocols, homemade_regex, unique_ips, 'entry_id')
    pcap.mine(file_path, wpa_password, rsa_key_file_path, is_flows, is_reg_extract, pcap_filter,
              pcap_filter_new_file_path)
    hr, ec, raw = pcap.get_outputs(conversation_number_to_display, is_flows, is_reg_extract)
    assert raw['EntryID'] == 'entry_id'
    assert raw['Packets'] == 1000
    assert len(ec['PCAPResultsDNS']) == 80
    assert len(ec['PCAPResultsSMB2']) == 7
    assert raw['URL'][0] == 'http://239.255.255.250:1900*'
    assert raw['Regex'] != []
