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
def test_add_to_data(main_data, data_to_add, future_id, wanted_output):
    from PcapMinerV2 import add_to_data
    add_to_data(main_data, data_to_add, future_id)

    assert main_data == wanted_output


def test_mine_pcap():
    file_path = '../../../../TestData/smb-on-windows-10.pcapng'
    decrypt_key = ""
    conversation_number_to_display = 15
    is_flows = True
    is_reg_extract = True
    extracted_protocols = ['DNS', 'SMB2']
    pcap_filter = ''
    homemade_regex = ''
    pcap_filter_new_file_path = ''
    unique_ips = False
    from PcapMinerV2 import PCAP
    pcap = PCAP(is_reg_extract, extracted_protocols, homemade_regex, unique_ips)
    pcap.mine(file_path, decrypt_key, is_flows, is_reg_extract, pcap_filter, pcap_filter_new_file_path)
    hr, ec, raw = pcap.get_outputs('entry_id', conversation_number_to_display, is_flows, is_reg_extract)
    assert raw['EntryID'] == 'entry_id'
    assert raw['StartTime'] == 'Sun Oct 16 11:07:57 2016'
    assert raw['Packets'] == 1000
    assert len(raw['DNS']) == 80
    assert len(raw['SMB2']) == 8
    assert raw['URL'][0] == 'http://239.255.255.250:1900*'


def test_mine_pcap_ipv6_regex():
    file_path = '../../../../TestData/smb-on-windows-10.pcapng'
    decrypt_key = ""
    conversation_number_to_display = 15
    is_flows = True
    is_reg_extract = True
    extracted_protocols = ['DNS', 'SMB2']
    pcap_filter = ''
    homemade_regex = '(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]' \
                     '{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:' \
                     '[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|' \
                     '2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]' \
                     '{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]' \
                     '|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
                     '(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]' \
                     '{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]' \
                     '{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}' \
                     ':){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25' \
                     '[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]' \
                     '{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}' \
                     '|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2' \
                     '}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4' \
                     '}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0' \
                     '-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]' \
                     '{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)$'
    pcap_filter_new_file_path = ''
    unique_ips = False
    from PcapMinerV2 import PCAP
    pcap = PCAP(is_reg_extract, extracted_protocols, homemade_regex, unique_ips)
    pcap.mine(file_path, decrypt_key, is_flows, is_reg_extract, pcap_filter, pcap_filter_new_file_path)
    hr, ec, raw = pcap.get_outputs('entry_id', conversation_number_to_display, is_flows, is_reg_extract)
    assert raw['Regex'] != []
