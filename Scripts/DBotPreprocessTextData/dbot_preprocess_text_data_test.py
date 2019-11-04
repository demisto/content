import pickle

from CommonServerPython import *
from DBotPreprocessTextData import clean_html, remove_line_breaks, hash_word, read_file, \
    concat_text_fields, whitelist_dict_fields, remove_short_text, remove_duplicate_by_indices, pre_process, main


def test_clean_html(mocker):
    html_string = """
    <!DOCTYPE html>
        <html>
        <body>
        <h1>My First Heading</h1>
        </body>
        </html>
    """
    assert clean_html(html_string) == "My First Heading"


def test_remove_line_breaks():
    html_string = """
    line1
    line2
    """
    assert remove_line_breaks(html_string) == "line1 line2"


def test_hash_word():
    html_string = "word1"
    assert hash_word(html_string, 5381) == "279393330"


def test_read_file(mocker):
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './TestData/input_json_file_test'})
    obj = read_file('231342@343', 'json')
    assert len(obj) >= 1
    with open('./TestData/input_json_file_test', 'r') as f:
        obj = read_file(f.read(), 'json_string')
        assert len(obj) >= 1
        obj = read_file(pickle.dumps(obj), 'pickle_string')
        assert len(obj) >= 1

    with open('./TestData/input_json_file_test', 'r') as f:
        b64_input = base64.b64encode(f.read())
        obj = read_file(b64_input, 'json_b64_string')
        assert len(obj) >= 1


def test_concat_text_field(mocker):
    data = [
        {
            'body': 'TestBody',
            'body2': 'TestBody2',
            'subject': 'TestSubject',
        },
        {
            'body': 'TestBody',
            'subject': 'TestSubject'
        },
        {
            'body2': 'TestBody2',
            'subject': 'TestSubject'
        }
    ]
    text_fields = 'subject | subject2, Body | body2'
    concat_text_fields(data, 'target', text_fields.split(","))
    assert data[0]['target'] == 'TestSubject TestBody'
    assert data[1]['target'] == 'TestSubject TestBody'
    assert data[2]['target'] == 'TestSubject TestBody2'

    mocker.patch.object(demisto, 'dt', return_value=["value"])
    data = [{"Email": {"Body": "value", "Subject": "value"}}]
    concat_text_fields(data, 'target', "Email.Subject, Email.Body")
    assert data[0]['target'] == 'value value'

    mocker.patch.object(demisto, 'dt', return_value="value")
    data = [{"Email": {"Body": "value", "Subject": "value"}}]
    concat_text_fields(data, 'target', "Email.Subject, Email.Body")
    assert data[0]['target'] == 'value value'


def test_remove_fields_from_dict():
    data = [
        {
            'body': 'TestBody',
            'body2': 'TestBody2',
            'subject': 'TestSubject',
        },
        {
            'body': 'TestBody',
            'subject': 'TestSubject',
        },
        {
            'body2': 'TestBody2',
            'subject': 'TestSubject',
        }
    ]
    data = whitelist_dict_fields(data, ['subject', 'body'])
    found = False
    for d in data:
        if 'body2' in d:
            found = True
    assert not found


def test_remove_short_text():
    data = [
        {
            'body': 'TestBody1 TestBody2 TestBody3 TestBody4',
        },
        {
            'body': 'TestBody1 TestBody2',
        }
    ]
    data, desc = remove_short_text(data, 'body', 2)
    assert desc == "Dropped 1 samples shorted then 2 words\n"
    assert len(data) == 1


def test_remove_dups():
    data = [
        {
            'body': 'TestBody1 TestBody2 TestBody3 TestBody4',
        },
        {
            'body': 'TestBody1 TestBody2',
        },
        {
            'body': 'TestBody1 TestBody2',
        }
    ]
    data, desc = remove_duplicate_by_indices(data, [1])
    assert desc == "Dropped 1 samples duplicate to other samples\n"
    assert len(data) == 2


def test_pre_process():
    data = [
        {
            'body': 'TestBody1 TestBody2 TestBody3 TestBody4',
        },
        {
            'body': 'TestBody1 TestBody2 <h1> html </h1>',
        }
    ]
    data1 = pre_process(data, "body", "processed", True, "none", None)
    assert data1 == [
        {'body': 'TestBody1 TestBody2 TestBody3 TestBody4', 'processed': 'TestBody1 TestBody2 TestBody3 TestBody4'},
        {'body': 'TestBody1 TestBody2 <h1> html </h1>', 'processed': 'TestBody1 TestBody2 html'}]
    data2 = pre_process(data, "body", "processed", True, "none", 5381)
    assert data2 == [
        {'body': 'TestBody1 TestBody2 TestBody3 TestBody4', 'processed': '148060132 148060133 148060134 148060135'},
        {'body': 'TestBody1 TestBody2 <h1> html </h1>', 'processed': '148060132 148060133 2090341082'}]


def test_main(mocker):
    args = {
        'textFields': 'subject|subject2,body|body2',
        'input': './TestData/input_json_file_test',
        'inputType': 'json',
        'removeShortTextThreshold': 5,
        'dedupThreshold': -1,
        'preProcessType': 'none',
        'cleanHTML': 'true',
        'outputFormat': 'json'
    }
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './TestData/input_json_file_test'})
    mocker.patch.object(demisto, 'args', return_value=args)
    entry = main()
    os.remove('1_' + entry['FileID'])
    assert 'Read initial 2 samples' in entry['HumanReadable']
    assert 'Done processing' in entry['HumanReadable']
    assert entry['EntryContext']['DBotPreProcessTextData']['TextField'] == 'dbot_text'
    assert entry['EntryContext']['DBotPreProcessTextData']['TextFieldProcessed'] == 'dbot_processed_text'
    assert len(entry['Contents']) > 1
