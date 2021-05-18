from CommonServerPython import *
from DBotTrainTextClassifierV2 import get_phishing_map_labels, read_file, read_files_by_name, \
    get_data_with_mapped_label, set_tag_field, DBOT_TAG_FIELD, ALL_LABELS


def test_get_phishing_map_labels():
    mapping = get_phishing_map_labels("Phishing:malicious , malware : malicious, spam")
    assert mapping['Phishing'] == "malicious"
    assert mapping['malware'] == "malicious"
    assert mapping['spam'] == "spam"

    mapping = get_phishing_map_labels(ALL_LABELS)
    assert mapping == ALL_LABELS


def test_read_file(mocker):
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './TestData/input_json_file_test'})
    obj = read_file('231342@343', 'json')
    assert len(obj) >= 1
    with open('./TestData/input_json_file_test', 'r') as f:
        obj = read_file(f.read(), 'json_string')
        assert len(obj) >= 1
    with open('./TestData/input_json_file_test', 'r') as f:
        b64_input = base64.b64encode(f.read().encode('utf-8'))  # base64.b64encode(f.read())
        obj = read_file(b64_input, 'json_b64_string')
        assert len(obj) >= 1


def test_read_files_by_name(mocker):
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './TestData/input_json_file_test'})
    mocker.patch.object(demisto, 'dt', return_value={'EntryID': 'ads@Asd2'})
    data = read_files_by_name("file1,file2", "json")
    assert len(data) == 4
    data = read_files_by_name("file1,", "json")
    assert len(data) == 2


def test_get_data_with_mapped_label():
    mapping = get_phishing_map_labels("Phishing:malicious , malware : malicious, spam")
    data = [{"tag": "Phishing"}, {"tag": "malware"}, {"tag": "spam"}, {"tag": "not"}, {"tag": "not"}]
    new_data, exist_labels_counter, missing_labels_counter = get_data_with_mapped_label(data, mapping, "tag")
    assert new_data[0]['tag'] == 'malicious'
    assert new_data[2]['tag'] == 'spam'
    assert exist_labels_counter['Phishing'] == 1
    assert exist_labels_counter['malware'] == 1
    assert exist_labels_counter['spam'] == 1
    assert missing_labels_counter['not'] == 2

    mapping = get_phishing_map_labels("phishing:malicious,spam:spam")
    data = [{"tag": "Phishing"}, {"tag": "Spam"}]
    new_data, exist_labels_counter, missing_labels_counter = get_data_with_mapped_label(data, mapping, "tag")
    assert new_data[0]['tag'] == 'malicious'
    assert new_data[1]['tag'] == 'spam'
    assert exist_labels_counter['phishing'] == 1
    assert exist_labels_counter['spam'] == 1


def test_set_tag_field():
    data = [{"tag": "Phishing"}, {"tag1": "malware"}, {"tag": "spam"}, {"tag2": "not"}, {"tag2": "not"}]
    new_data = set_tag_field(data, ["tag", "tag1"])
    assert len(new_data) == 3
    assert new_data[0][DBOT_TAG_FIELD] == 'Phishing'
    assert new_data[1][DBOT_TAG_FIELD] == 'malware'
    assert new_data[2][DBOT_TAG_FIELD] == 'spam'
