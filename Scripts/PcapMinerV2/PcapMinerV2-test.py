def test_strip():
    test_string = "T'hi's >is a t[]es[t t<]ext."
    from PcapMinerV2 import strip
    assert strip(test_string) == "This is a test text."


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
        "['1.1.1.1', '2.2.2.2']": 15,
        "['1.1.1.3', '2.2.2.2']": 15,
        "['1.1.1.3', '8.8.8.8']": 15
    }
    from PcapMinerV2 import conversations_to_md
    assert conversations_to_md(converstation_test, 4) == "|A|B|# of Packets\n|---|---|---|\n|1.1.1.1| 2.2.2.2|15|\n" \
                                                         "|1.1.1.3| 2.2.2.2|15|\n|1.1.1.3| 8.8.8.8|15|\n"


def test_remove_nones():
    d = {'Oh': 1,
            'My': None,
            'God': None}
    from PcapMinerV2 import remove_nones
    assert remove_nones(d) == {'Oh': 1}


def test_add_to_data():
    from PcapMinerV2 import add_to_data
    data = {}
    data_to_add = {'ID': '1',
                   'Length': 5}
    add_to_data(data, data_to_add)
    data_to_add = {'ID': '2',
                   'Length': 6}
    add_to_data(data, data_to_add)
    data_to_add = {'Length': 6}
    add_to_data(data, data_to_add)

    assert data == {'1': {'ID': '1', 'Length': 5}, '2': {'ID': '2', 'Length': 6}}
