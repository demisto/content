from collections import Counter

from DBotMLFetchData import *
from CommonServerPython import *
import string
from bs4 import BeautifulSoup
import math
import pandas as pd


def test_find_label_fields_candidates():
    d = {'phishing_correct_field': [float('nan')] * 20 + ['spam'] * 10 + ['phishing'] * 10,
         'slightly-related-field': [float('nan')] * 20 + ['spam'] * 10 + ['phishing'] * 10,
         'non-related-field': [float('nan')] * 20 + ['cat'] * 10 + ['dog'] * 10
         }
    df = pd.DataFrame(data=d)
    res = find_label_fields_candidates(df)
    assert res[0] == 'phishing_correct_field'
    assert res[1] == 'slightly-related-field'

    d = {'phishing_correct_field': [float('nan')] * 20 + [False] * 10 + [True] * 10,
         'non-related-field': [float('nan')] * 20 + ['cat'] * 10 + ['dog'] * 10
         }
    df = pd.DataFrame(data=d)
    res = find_label_fields_candidates(df)
    assert res[0] == 'phishing_correct_field'
    assert res[1] == 'non-related-field'


def test_get_ml_features(mocker):
    dummy_word_to_vec = {'hello': [1.0, 0], 'world': [2.0, -1.0]}
    mock_read = mocker.mock_open(read_data='dummy data')
    mocker.patch('DBotMLFetchData.open', mock_read)
    mocker.patch.object(pickle, 'load', return_value=dummy_word_to_vec)
    load_external_resources()
    text = ['hello', 'world']
    featurs = get_embedding_features(text)
    assert featurs['glove50_0'] == 1.5
    assert featurs['glove50_1'] == -0.5


def test_get_ngrams_features(mocker):
    mocker.patch('DBotMLFetchData.open', mock_read_func)
    load_external_resources()
    text = 'great deal no risk only for 24 hours!!! 24 hours!!!!!'
    res = get_ngrams_features(text, transform_text_to_ngrams_counter(word_tokenize(text), []))
    assert res['x hours'] == 2
    assert res['deal'] == 1
    assert res['risk'] == 1


def test_get_vocab_features_subword(mocker):
    text = 'callable'
    mocker.patch('DBotMLFetchData.open', mock_read_func)
    load_external_resources()
    res = get_ngrams_features(text, transform_text_to_ngrams_counter(word_tokenize(text), []))
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


def test_get_html_features():
    email_html = '<a href="{}">Link</a>'.format('link')
    soup = BeautifulSoup(email_html, "html.parser")
    res = get_html_features(soup)
    assert res['a'] == 1
    assert 'body' not in res


# disable-secrets-detection-start
def test_get_url_features(mocker):
    email_body = 'https://www.a.com https://www.b.com http://www.c.com/vcvc/vcvc/vc/b'  # disable-secrets-detection
    embedded_url = 'https://www.a.com'  # disable-secrets-detection
    all_urls = email_body.split() + [embedded_url]
    email_html = '<a href="{}">Link</a>'.format(embedded_url)
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

    email_body_3 = 'https://drive.google.com/file/d/1f9pBukhG_5jB-uh0TeZiYq0rV2GUXftr/view'  # disable-secrets-detection
    url_features_3 = get_url_features(email_body_3, '', empty_bs)
    assert url_features_3['drive_count'] == 1


# disable-secrets-detection-end


def test_extract_server_address():
    value = 'from po-out-1718.google.co.uk ([xxx.xxx.xxx.xxx]:54907) by cl35.gs01.gridserver.com with esmtp' \
            ' (Exim 4.63) (envelope-from <mt.kb.user@gmail.com>) id 1KDoNH-0000f0-RL for user@example.com;' \
            ' Tue, 25 Jan 2011 15:31:01 -0700'  # disable-secrets-detection
    domain, suffix = extract_server_address(value)
    assert domain == 'google'
    assert suffix == 'co.uk'

    address, domain, suffix = extract_envelop_from_address(value)
    assert domain == 'gmail'
    assert suffix == 'com'
    assert address == 'mt.kb.user@gmail.com'  # disable-secrets-detection


def test_parse_email_header():
    header_value = 'Taylor Evans <example_from@dc.edu>'
    email_headers = [{'headername': 'From', 'headervalue': header_value}]
    res = parse_email_header(email_headers, header_name='From')
    assert res['address'] == 'example_from@dc.edu'
    assert res['domain'] == 'dc'

    header_value = '"Taylor Evans" <example_from@dc.edu>'
    email_headers = [{'headername': 'From', 'headervalue': header_value}]
    res = parse_email_header(email_headers, header_name='From')
    assert res['address'] == 'example_from@dc.edu'
    assert res['domain'] == 'dc'

    header_value = 'example_from@dc.edu'
    email_headers = [{'headername': 'From', 'headervalue': header_value}]
    res = parse_email_header(email_headers, header_name='From')
    assert res['address'] == 'example_from@dc.edu'
    assert res['domain'] == 'dc'


def test_parse_received_headers_2():
    value = 'from po-out-1718.google.com ([xxx.xxx.xxx.xxx]:xxxx) by cl35.gs01.gridserver.com with esmtp (Exim 4.63) ' \
            '(envelope-from <mt.kb.user@gmail.com>) id 1KDoNH-0000f0-RL for user@example.com;' \
            ' Tue, 25 Jan 2011 15:31:01 -0700'  # disable-secrets-detection

    email_headers = [{'headername': 'Received', 'headervalue': value}] * 2
    n_received_headers, [first_server, first_envelop, _, _] = parse_received_headers(email_headers)
    assert n_received_headers == 2
    assert first_server['domain'] == 'google'
    assert first_envelop['address'] == 'mt.kb.user@gmail.com'  # disable-secrets-detection
    assert first_envelop['domain'] == 'gmail'


def test_parse_received_headers_3():
    value = 'from po-out-1718.google.com ([xxx.xxx.xxx.xxx]:xxxx) by cl35.gs01.gridserver.com with esmtp (Exim 4.63) ' \
            '(envelope-from <mt.kb.user@gmail.com>) id 1KDoNH-0000f0-RL for user@example.com;' \
            ' Tue, 25 Jan 2011 15:31:01 -0700'  # disable-secrets-detection

    email_headers = [{'headername': 'Received', 'headervalue': value}]
    n_received_headers, [_, _, second_server, second_envelop] = parse_received_headers(email_headers)
    assert n_received_headers == 1
    assert second_server['domain'] is None
    assert second_envelop['address'] is None
    assert second_envelop['domain'] is None

    email_headers = [{'headername': 'Received', 'headervalue': value}, {'headername': 'Received', 'headervalue': ''}]
    n_received_headers, [_, _, second_server, second_envelop] = parse_received_headers(email_headers)
    assert n_received_headers == 2
    assert second_server['domain'] == 'google'
    assert second_envelop['address'] == 'mt.kb.user@gmail.com'  # disable-secrets-detection
    assert second_envelop['domain'] == 'gmail'


def test_headers_features():
    headers = [
        {'headername': 'Received-SPF', 'headervalue': 'SoftFail (xxx.com: domain of xxx.com '
                                                      'discourages use of xxx.xxx.xxx.xxx.xxx '
                                                      'permitted sender)'},  # disable-secrets-detection
        {'headername': 'Authentication-Results', 'headervalue': 'spf=neutral (sender IP is xxx.xxx.xxx.xxx) '
                                                                'smtp.mailfrom=xxx.net; dkim=fail (body hash did not '
                                                                'verify) header.d=xxxx.com;xxxx.com; dmarc=fail '
                                                                'action=none header.from=xxxx.com;compauth=none '
                                                                'reason=405'}  # disable-secrets-detection
    ]
    res = get_headers_features(headers)
    assert res['spf::softfail'] == 1
    assert res['spf::non-positive'] == 1
    assert res['dkim::fail'] == 1
    assert res['dkim::non-positive'] == 1
    assert res['unsubscribe_headers'] == 0


def test_headers_features_2(mocker):
    mocker.patch('DBotMLFetchData.open', mock_read_func)
    load_external_resources()
    headers = [
        {'headername': 'From', 'headervalue': ' =?UTF-8?B?TcKqIElzYWJlbCBHYXJjw61hIExvc2FkYSA8TUlHQGVsemFidXJ1LmVz'
                                              'Pg==?= <name@domain.com>'},  # disable-secrets-detection
        {'headername': 'Return-Path', 'headervalue': 'name@domain.com'},  # disable-secrets-detection
        {'headername': 'Received', 'headervalue': 'from [xxx.xxx.xxx.xxx] ([xxx.xxx.xxx.xxx]) by domain.com with '
                                                  'MailEnable ESMTPA; Tue, 21 Jan 2020 05:16:47 '
                                                  '-0600'},  # disable-secrets-detection
    ]
    res = get_headers_features(headers)
    assert res['From.Domain==Return-Path.Domain']
    assert res['First-Received-Server::IP_DOMAIN']
    assert not res['First-Received-Server.Domain==From.Domain']


def test_headers_features_3_virus_total_format(mocker):
    mocker.patch('DBotMLFetchData.open', mock_read_func)
    load_external_resources()
    headers = [
        {'headername': 'From', 'headervalue': 'Jhon Jhon<purchase@domain.com>'},  # disable-secrets-detection
        {'headername': 'Return-Path', 'headervalue': '<>'},
        {'headername': 'Received', 'headervalue': 'from domain.com ([xxx.xxx.xxx.xxx] [xxx.xxx.xxx.xxx]) by xxx.xxx.ro '
                                                  '(amavisd-milter) with ESMTP id xxx; Thu, 9 Jan 2020 12:21:34 +0200 '
                                                  '(envelope-from '
                                                  '<purchase@domain.com>)'},  # disable-secrets-detection
    ]
    res = get_headers_features(headers)
    assert not res['From.Domain==Return-Path.Domain']
    assert res['First-Received-Server.Domain==From.Domain']
    assert math.isnan(res['Second-Received-Server.Domain==From.Domain'])
    assert res['First-Received-Server.Domain==From.Domain']
    assert not res['First-Received-Server::IP_DOMAIN']


def test_headers_features_domain_rank(mocker):
    mocker.patch('DBotMLFetchData.open', mock_read_func)
    load_external_resources()
    headers = {'headername': 'From', 'headervalue': 'Jhon <jhon@google.com>'},  # disable-secrets-detection
    res = get_headers_features(headers)
    assert res['From::Rank'] == 1


def test_headers_features_4():
    headers = [
        {'headername': 'List-Unsubscribe', 'headervalue': 'Message-Id: Sender: Date; bh=GExv5cay5SOdSeHjP5vfnhswJAlO/X4'
                                                          'tR2EBLXjqNXw=; b=KPBtMUsmW0F+wD5qXzQoS6U2fzWPSEWbAVK+AEha2hx'
                                                          'Q7q1PWplkMU7xIiehm0vlO'
                                                          'C7eTrUh'},  # disable-secrets-detection
    ]
    res = get_headers_features(headers)
    assert res['unsubscribe_headers']


def test_headers_features_5():
    headers = [
        {'headername': 'Content-type', 'headervalue': 'text/plain;'},
    ]
    res = get_headers_features(headers)
    assert res['content-type'] == 'text/plain'
    headers_2 = [
        {'headername': 'content-type', 'headervalue': 'text/plain;'},
    ]
    res_2 = get_headers_features(headers_2)
    assert res_2['content-type'] == 'text/plain'


def test_headers_features_6():
    headers = [{'headername': 'Received', 'headervalue': ''}] * 5
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


def mock_read_func(file_path, mode='r'):
    test_files = True
    if test_files:
        docker_path_to_test_path = {
            GLOVE_50_PATH: 'test_data/glove_50_top_10.p',
            GLOVE_100_PATH: 'test_data/glove_100_top_10.p',
            FASTTEXT_PATH: 'test_data/fasttext_top_10.p',
            DOMAIN_TO_RANK_PATH: 'test_data/domain_to_rank_top_5.p',
            WORD_TO_NGRAM_PATH: 'test_data/word_to_ngram.p',
            WORD_TO_REGEX_PATH: 'test_data/word_to_regex.p'
        }
    else:
        docker_path_to_test_path = {
            GLOVE_50_PATH: 'real_data/glove_50_top_20k.p',
            GLOVE_100_PATH: 'real_data/glove_100_top_20k.p',
            FASTTEXT_PATH: 'real_data/fasttext_top_20k.p',
            DOMAIN_TO_RANK_PATH: 'real_data/domain_to_rank.p',
            WORD_TO_NGRAM_PATH: 'test_data/word_to_ngram.p',
            WORD_TO_REGEX_PATH: 'test_data/word_to_regex.p'
        }
    return open(docker_path_to_test_path[file_path], mode=mode)


def test_whole_preprocessing(mocker):
    import cProfile
    debug = False
    mocker.patch('DBotMLFetchData.open', mock_read_func)

    data_file_path = 'test_data/100_incidents.p'
    with open(data_file_path, 'rb') as file:
        incidents = pickle.load(file)
    prof = cProfile.Profile()
    data = prof.runcall(extract_data_from_incidents, incidents=incidents)
    if debug:
        with open('output.txt', 'w') as file:
            json.dump(data, fp=file, indent=4)
        prof.print_stats(sort='cumtime')
    assert len(data['log']['exceptions']) == 0
    assert len(data['X']) == 100


def test_whole_preprocessing_short_incident(mocker):
    import cProfile
    debug = False
    mocker.patch('DBotMLFetchData.open', mock_read_func)

    data_file_path = 'test_data/100_incidents.p'
    with open(data_file_path, 'rb') as file:
        incidents = pickle.load(file)
    short_text_incident = {'closeReason': 'shortText', 'emailbody': 'short text',
                           'created': '2020-05-10T18:39:04+03:00',
                           'attachment': []}
    short_text_incident_index = 50
    incidents = incidents[:short_text_incident_index] + [short_text_incident] + incidents[short_text_incident_index:]
    prof = cProfile.Profile()
    data = prof.runcall(extract_data_from_incidents, incidents=incidents)
    if debug:
        with open('output.txt', 'w') as file:
            json.dump(data, fp=file, indent=4)
        prof.print_stats(sort='cumtime')
    assert len(data['log']['exceptions']) == 0
    assert len(data['X']) == 100
    # check labels order kept as original excluding the short label
    assert Counter(x['closeReason'] for x in data['X']) == Counter(
        [inc['closeReason'] for i, inc in enumerate(incidents) if i != short_text_incident_index])


def test_whole_preprocessing_incdient_without_label(mocker):
    import cProfile
    debug = False
    mocker.patch('DBotMLFetchData.open', mock_read_func)

    data_file_path = 'test_data/100_incidents.p'
    with open(data_file_path, 'rb') as file:
        incidents = pickle.load(file)
    incident_without_label = {'closeReason': '', 'emailbody': 'short text',
                              'created': '2020-05-10T18:39:04+03:00', 'attachment': []}
    no_label_idx = 50
    incidents = incidents[:no_label_idx] + [incident_without_label] + incidents[no_label_idx:]
    prof = cProfile.Profile()
    data = prof.runcall(extract_data_from_incidents, incidents=incidents)
    if debug:
        with open('output.txt', 'w') as file:
            json.dump(data, fp=file, indent=4)
        prof.print_stats(sort='cumtime')
    assert len(data['log']['exceptions']) == 0
    assert len(data['X']) == 100
    # check labels order kept as original excluding the short label
    assert Counter(x['closeReason'] for x in data['X']) == Counter(
        [inc['closeReason'] for i, inc in enumerate(incidents) if i != no_label_idx])
