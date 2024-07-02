import unittest
from Defang import defang

class TestDefang(unittest.TestCase):
    def test_ip_addr(self):
        input_str = '192.168.1.1'
        expected_output = '192[.]168[.]1[.]1'
        actual_output, output = defang(input_str)
        assert actual_output == expected_output
        assert output == {'Defang': {'output': expected_output}}
        
    def test_mail_addr(self):
        input_str = 'demisto@demisto.com'
        expected_output = 'demisto[@]demisto[.]com'
        actual_output, output = defang(input_str)
        assert actual_output == expected_output
        assert output == {'Defang': {'output': expected_output}}
    
    def test_url_addr(self):
        input_str = 'https://xsoar.pan.dev/'
        expected_output = 'hxxps[://]xsoar[.]pan[.]dev/'
        actual_output, output = defang(input_str)
        assert actual_output == expected_output
        assert output == {'Defang': {'output': expected_output}}
        
    def test_all(self):
        input_str = 'Hello I am a automation script developed using https://xsoar.pan.dev/ having IP 56.54.25.56 and developed by dbot@demisto.com'
        expected_output = 'Hello I am a automation script developed using hxxps[://]xsoar[.]pan[.]dev/ having IP 56[.]54[.]25[.]56 and developed by dbot[@]demisto[.]com'
        actual_output, output = defang(input_str)
        assert actual_output == expected_output
        assert output == {'Defang': {'output': expected_output}}
