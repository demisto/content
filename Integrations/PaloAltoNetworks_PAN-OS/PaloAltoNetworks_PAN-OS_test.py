from PaloAltoNetworks_PAN-OS import add_argument_list,


def test_add_argument_list():
    list_argument = ["foo","bar"]

    response_with_member = add_argument_list(list_argument, "test", True)
    expected_with_member = '<test><member><foo></member><member><bar></member></test>
    assert response_with_member == expected_with_member

    response_with_member_field_name = add_argument_list(list_argument, "member", True)
    expected_with_member_field_name = '<member><foo></member><member><bar></member>'
    assert response_with_member_field_name == expected_with_member_field_name


def test_prettify_upload():
    expected_upload_dict = dict({
        'MD5': "md5_hash", 'SHA256': "sha256_hash", 'FileType': "pdf", 'Size': 5, 'Status': "Pending"})
    prettify_upload_res = prettify_upload(
        {'md5': "md5_hash", 'sha256': "sha256_hash", 'filetype': "pdf", 'size': 5})
    assert expected_upload_dict == prettify_upload_res


def test_prettify_report_entry():
    expected_report_dict = dict({
        'MD5': "md5_hash", 'SHA256': "sha256_hash", 'FileType': "pdf", 'Size': 5, 'Status': "Completed"})
    prettify_report_entry_res = prettify_report_entry(
        {'md5': "md5_hash", 'sha256': "sha256_hash", 'filetype': "pdf", 'size': 5})
    assert expected_report_dict == prettify_report_entry_res


def test_prettify_verdict():
    expected_verdict_dict = dict({
        'MD5': "md5_hash", 'SHA256': "sha256_hash", 'Verdict': "1", 'VerdictDescription': 'malware'})
    prettify_verdict_res = prettify_verdict(
        {'md5': "md5_hash", 'sha256': "sha256_hash", 'verdict': "1"})
    assert expected_verdict_dict == prettify_verdict_res


def test_create_dbot_score_from_verdict():
    expected_dbot_score = dict({
        'Indicator': "sha256_hash", 'Type': "hash", 'Vendor': "WildFire", 'Score': 3})
    dbot_score_dict = create_dbot_score_from_verdict({'SHA256': "sha256_hash", 'Verdict': "1"})
    assert expected_dbot_score == dbot_score_dict


def test_prettify_verdicts():
    expected_verdicts_dict = [
        {'MD5': "md5_hash", 'SHA256': "sha256_hash", 'Verdict': "1", 'VerdictDescription': 'malware'}]
    prettify_verdicts_res = prettify_verdicts(
        [{'md5': "md5_hash", 'sha256': "sha256_hash", 'verdict': "1"}])
    assert expected_verdicts_dict == prettify_verdicts_res


def test_create_dbot_score_from_verdicts():
    expected_dbot_scores = [{'Indicator': "sha256_hash", 'Type': "hash", 'Vendor': "WildFire", 'Score': 3},
                            {'Indicator': "md5_hash", 'Type': "hash", 'Vendor': "WildFire", 'Score': 1}]
    dbot_score_dict = create_dbot_score_from_verdicts(
        [{'SHA256': "sha256_hash", 'Verdict': "1"}, {'MD5': "md5_hash", 'Verdict': "0"}])
    assert expected_dbot_scores == dbot_score_dict


def test_hash_args_handler():
    expected_hash_list = ['12345678901234567890123456789012']
    hash_list = hash_args_handler(md5='12345678901234567890123456789012')
    assert expected_hash_list == hash_list


def test_file_args_handler():
    expected_file_hash_list = ['12345678901234567890123456789012',
                               '1d457069cb511af47a587287d59817148d404a2a7f39e1032d16094811f648e3']
    file_hash_list = file_args_handler(
        file="12345678901234567890123456789012,1d457069cb511af47a587287d59817148d404a2a7f39e1032d16094811f648e3")
    assert expected_file_hash_list == file_hash_list
