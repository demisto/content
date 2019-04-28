from Palo_Alto_Networks_WildFire_v2 import prettify_upload, prettify_report_entry, prettify_verdict, \
    create_dbot_score_from_verdict, prettify_verdicts


def test_will_return_ok():
    assert 1 == 1


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
        'MD5': "md5_hash", 'SHA256': "sha256_hash", 'Verdict': "1", 'VerdictDescription': 'desc'})
    prettify_verdict_res = prettify_verdict(
        {'md5': "md5_hash", 'sha256': "sha256_hash", 'verdict': "1"})
    assert expected_verdict_dict == prettify_verdict_res


def test_create_dbot_score_from_verdict():
    expected_dbot_score = list(dict({
        'Indicator': "sha256_hash", 'Type': "hash", 'Vendor': "WildFire", 'Score': 3}))
    dbot_score_dict = create_dbot_score_from_verdict(list({'SHA256': "sha256_hash", 'Verdict': "1"}))
    assert expected_dbot_score == dbot_score_dict


def test_prettify_verdicts():
    expected_verdicts_dict = dict({
        'MD5': "md5_hash", 'SHA256': "sha256_hash", 'Verdict': "1", 'VerdictDescription': 'desc'})
    prettify_verdicts_res = prettify_verdicts(list(
        {'md5': "md5_hash", 'sha256': "sha256_hash", 'verdict': "1"}))
    assert expected_verdicts_dict == prettify_verdicts_res
