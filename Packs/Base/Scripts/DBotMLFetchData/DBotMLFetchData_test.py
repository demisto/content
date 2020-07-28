from DBotMLFetchData import *
from CommonServerPython import *
import string
from bs4 import BeautifulSoup


# disable-secrets-detection-start

def test_get_ml_features(mocker):
    dummy_word_to_vec = {'hello': [1.0, 0], 'world': [2.0, -1.0]}
    mock_read = mocker.mock_open(read_data='dummy data')
    mocker.patch('DBotMLFetchData.open', mock_read)
    mocker.patch.object(pickle, 'load', return_value=dummy_word_to_vec)

    text = ['hello', 'world']
    featurs = get_embedding_features(text)
    assert featurs['glove50_0'] == 1.5
    assert featurs['glove50_1'] == -0.5


def test_get_vocab_features(mocker):
    text = 'great deal no risk only for 24 hours!!! 24 hours!!!!!'
    res = get_vocab_features(text, transform_text_to_ngrams_counter(word_tokenize(text), []))
    assert res['x hours'] == 2
    assert res['deal'] == 1
    assert res['risk'] == 1


def test_get_vocab_features_subword(mocker):
    text = 'callable'
    res = get_vocab_features(text, transform_text_to_ngrams_counter(word_tokenize(text), []))
    assert 'call' not in res


def test_get_lexical_features(mocker):
    email_subject = 'dear sir'
    email_body = 'dear sir.  please send me your credit card! ok?'
    email_subject_word_tokenized, email_body_word_tokenized = email_subject.split(), email_body.split()
    res = get_lexical_features(email_subject, email_body, email_body_word_tokenized,
                               email_subject_word_tokenized)

    assert res['num_of_words'] == 9
    assert res['avg_word_length'] == sum(1.0 for c in email_body if c != ' ') / 9
    assert res['num_of_sentences'] == 3
    assert res['avg_sentence_length'] == sum(1.0 for c in email_body if c not in string.punctuation) / 3
    assert res['avg_number_of_words_in_sentence'] == 9.0 / 3
    assert res['text_length'] == len(email_body)
    assert res['num_of_words_subject'] == 2
    assert res['subject_length'] == len(email_subject)
    assert res['ending_dots'] == 1
    assert res['ending_explanation'] == 1
    assert res['ending_question'] == 1
    assert res['number_of_lines'] == 1


def test_get_characters_features(mocker):
    charchters_dict = {'a': 3, '!': 4, '?': 1}
    text = ''
    for c, count in charchters_dict.items():
        text += c * count
    lexical_features = get_characters_features(text)
    assert all(lexical_features[c] == charchters_dict[c] for c in charchters_dict)


def test_get_url_features(mocker):
    email_body = 'https://www.a.com/ https://www.b.com/ http://www.c.com/vcvc/vcvc/vc/b'   # disable-secrets-detection
    embedded_url = 'https://www.w3schools.com'   # disable-secrets-detection
    all_urls = email_body.split() + [embedded_url]
    email_html = '<a href="{}">Visit W3Schools</a>'.format(embedded_url)
    soup = BeautifulSoup(email_html, "html.parser")
    url_features = get_url_features(email_body, email_html, soup)

    assert url_features['https_urls_count'] == 2
    assert url_features['http_urls_count'] == 1
    assert url_features['embedded_urls_count'] == 1
    assert url_features['average_url_length'] == sum(float(len(u)) for u in all_urls) / len(all_urls)
    assert url_features['min_url_length'] == min(len(u) for u in all_urls)
    assert url_features['max_url_length'] == max(len(u) for u in all_urls)
    assert url_features['shortened_urls_count'] == 0
    assert url_features['drive_count'] == 0

    email_body_2 = 'https://bit.ly/3hi1EZN'
    empty_bs = BeautifulSoup('', "html.parser")
    url_features_2 = get_url_features(email_body_2, '', empty_bs)
    assert url_features_2['shortened_urls_count'] == 1

    email_body_3 = 'https://drive.google.com/file/d/1f9pBukhG_5jB-uh0TeZiYq0rV2GUXftr/view'   # disable-secrets-detection
    url_features_3 = get_url_features(email_body_3, '', empty_bs)
    assert url_features_3['drive_count'] == 1


def test_headers_features():
    headers = [
        {'name': 'Received-SPF', 'value': 'SoftFail (protection.outlook.com: domain of xvxdvcx.com discourages use of '
                                          'xxx.xxx.xxx.xxx.xxx permitted sender)'},   # disable-secrets-detection
        {'name': 'Authentication-Results', 'value': 'spf=neutral (sender IP is xxx.xxx.xxx.xxx) smtp.mailfrom=xxx.net; '
                                                    'dkim=fail (body hash did not verify) '
                                                    'header.d=salesenablementworld.com;hbo.com; dmarc=fail action=none '
                                                    'header.from=salesenablementworld.com;compauth=none '
                                                    'reason=405'}  # disable-secrets-detection
    ]
    res = get_headers_features(headers)
    assert res['spf::softfail'] == 1
    assert res['spf::non-positive'] == 1
    assert res['dkim::fail'] == 1
    assert res['dkim::non-positive'] == 1
    assert res['unsubscribe_headers'] == 0


def test_headers_features_2():
    headers = [
        {'name': 'From', 'value': ' =?UTF-8?B?TcKqIElzYWJlbCBHYXJjw61hIExvc2FkYSA8TUlHQGVsemFidXJ1LmVzPg==?= '
                                  '<fonsecaj@pecosacr.com>'},   # disable-secrets-detection
        {'name': 'Return-Path', 'value': 'fonsecaj@pecosacr.com'},   # disable-secrets-detection
        {'name': 'Received', 'value': 'from [194.152.220.26] ([194.152.220.26]) by pecosacr.com with MailEnable ESMTPA; '
                                      'Tue, 21 Jan 2020 05:16:47 -0600'},   # disable-secrets-detection
    ]
    res = get_headers_features(headers)
    assert res['return_path_same_as_from']
    assert not res['from_domain_with_received']


def test_headers_features_3_virus_total_format():
    headers = [
        {'name': 'From', 'value': 'Harry Clark<purchase@allislandequipment.com>'},   # disable-secrets-detection
        {'name': 'Return-Path', 'value': '<>'},
        {'name': 'Received', 'value': 'from allislandequipment.com ([213.227.154.65] [213.227.154.65]) by '
                                      'spin.electroputere.ro (amavisd-milter) with ESMTP id 009ALXqe015078; '
                                      'Thu, 9 Jan 2020 12:21:34 +0200 '
                                      '(envelope-from <purchase@allislandequipment.com>)'},  # disable-secrets-detection
    ]
    res = get_headers_features(headers)
    assert not res['return_path_same_as_from']
    assert res['from_domain_with_received']


def test_headers_features_4():
    headers = [
        {'name': 'List-Unsubscribe', 'value': 'Message-Id: Sender: Date; bh=GExv5cay5SOdSeHjP5vfnhswJAlO/X4tR2EBLXjqN'
                                              'Xw=; b=KPBtMUsmW0F+wD5qXzQoS6U2fzWPSEWbAVK+AEha2hxQ7q1PWplkMU7xIiehm0vlO'
                                              'C7eTrUh'},   # disable-secrets-detection
    ]
    res = get_headers_features(headers)
    assert res['unsubscribe_headers']


def test_headers_features_5():
    headers = [
        {'name': 'Content-type', 'value': 'text/plain;'},
    ]
    res = get_headers_features(headers)
    assert res['content-type::text/plain'] == 1
    headers_2 = [
        {'name': 'content-type', 'value': 'text/plain;'},
    ]
    res_2 = get_headers_features(headers_2)
    assert res_2['content-type::text/plain'] == 1


def test_headers_features_6():
    headers = [{'name': 'Received', 'value': ''}] * 5
    res = get_headers_features(headers)
    assert res['count_received'] == 5


def test_attachments_features():
    attachments = [
        {'description': '',
         'name': 'aaaaaaa.txt',
         'path': '',
         'showMediaFile': '',
         'type': ''},
        {'description': '',
         'name': 'bbbbb.pdf',
         'path': '',
         'showMediaFile': '',
         'type': ''},
    ]
    res = get_attachments_features(attachments)
    assert res['number_of_attachments'] == len(attachments)
    assert res['min_attachment_name_length'] == min(len(a['name']) for a in attachments)
    assert res['max_attachment_name_length'] == max(len(a['name']) for a in attachments)
    assert res['avg_attachment_name_length'] == sum(len(a['name']) for a in attachments) / len(attachments)
    assert res['image_extension'] == 0
    assert res['txt_extension'] == 1
    assert res['exe_extension'] == 0
    assert res['archives_extension'] == 0
    assert res['pdf_extension'] == 1
    assert res['disk_img_extension'] == 0
    assert res['other_executables_extension'] == 0
    assert all(extension in res['raw_extensions'] for extension in ['txt', 'pdf'])


def test_attachments_features_2():
    attachments = [
        {'description': '',
         'name': 'aaaaaaa.zip',
         'path': '',
         'showMediaFile': '',
         'type': ''},
        {'description': '',
         'name': 'bbbbb.xls',
         'path': '',
         'showMediaFile': '',
         'type': ''},
    ]
    res = get_attachments_features(attachments)
    assert res['number_of_attachments'] == len(attachments)
    assert res['min_attachment_name_length'] == min(len(a['name']) for a in attachments)
    assert res['max_attachment_name_length'] == max(len(a['name']) for a in attachments)
    assert res['avg_attachment_name_length'] == sum(len(a['name']) for a in attachments) / len(attachments)
    assert res['image_extension'] == 0
    assert res['txt_extension'] == 0
    assert res['exe_extension'] == 0
    assert res['archives_extension'] == 1
    assert res['pdf_extension'] == 0
    assert res['disk_img_extension'] == 0
    assert res['office_extension'] == 1
    assert all(extension in res['raw_extensions'] for extension in ['zip', 'xls'])


def test_whole_preprocessing(mocker):
    import cProfile
    debug = True
    glove_path = './glove_50_top_10.p'
    with open(glove_path, 'rb') as file:
        glove_data = file.read()
    mock_read = mocker.mock_open(read_data=glove_data)
    mocker.patch('DBotMLFetchData.open', mock_read)
    # mocker.patch.object(pickle, 'load', return_value = dummy_word_to_vec)

    data_file_path = 'test_data.p'
    with open(data_file_path, 'rb') as file:
        incidents = pickle.load(file)
    prof = cProfile.Profile()
    data = prof.runcall(extract_data_from_incidents, incidents=incidents)
    if debug:
        with open('output.txt', 'w') as file:
            json.dump(data, fp=file, indent=4)
        prof.print_stats(sort='cumtime')

# disable-secrets-detection-end
