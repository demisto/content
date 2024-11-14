import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import subprocess
import os
import hashlib
import logging


class CustomHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.last_log_msg = None

    def emit(self, record):
        self.last_log_msg = record.msg

    def get_last_log_msg(self):
        return self.last_log_msg


custom_handler = CustomHandler()
root_logger = logging.getLogger()
root_logger.addHandler(custom_handler)
root_logger.setLevel(logging.DEBUG)

# should be imported after adding log handler to the root logger
from oletools import crypto, oleid  # noqa: E402
from oletools.olevba import VBA_Parser  # noqa: E402


class OleClient:
    def __init__(self, file_info, ole_command, password=None, decoded=False):
        self.name = file_info['name']
        self.file_path = file_info['path']
        self.password = password
        self.show_decoded = decoded
        self.decrypted_file_path = None
        self.processed_file_path = file_info['path']
        self.ole_command = ole_command
        self.hash = None

    def __del__(self):
        try:
            if self.password and self.decrypted_file_path:
                os.unlink(self.decrypted_file_path)
        except Exception:  # e.g. file does not exist or is None
            pass

    def decryption(self):
        if crypto.is_encrypted(self.file_path) and self.password:
            try:
                passwords = [self.password] + crypto.DEFAULT_PASSWORDS
                self.decrypted_file_path = crypto.decrypt(self.file_path, passwords)
                if not self.decrypted_file_path:
                    raise crypto.WrongEncryptionPassword(self.file_path)
            except Exception as e:
                raise DemistoException(f'The file decryption failed with the following message:\n {e}')

    @staticmethod
    def calc_hash(file_path: str):
        with open(file_path, "rb") as f:
            b = f.read()  # read entire file as bytes
            return hashlib.sha256(b).hexdigest()

    def run(self):

        self.decryption()

        if self.decrypted_file_path:
            self.processed_file_path = self.decrypted_file_path

        # calculate the file hash
        self.hash = self.calc_hash(self.processed_file_path)

        if self.ole_command == 'oleid':
            cr = self.oleid()
        elif self.ole_command == 'oleobj':
            cr = self.oleobj()
        elif self.ole_command == 'olevba':
            cr = self.olevba()
        else:
            raise NotImplementedError('Command "{}" is not implemented.'.format(self.ole_command))

        self.wrap_command_result(cr)
        return cr

    def wrap_command_result(self, cr: CommandResults):
        cr.outputs = {'sha256': self.hash, 'file_name': self.name, 'ole_command_result': cr.outputs}
        cr.outputs_key_field = 'sha256'

    @staticmethod
    def replace_space_with_underscore(indicator: str):
        return indicator.replace(' ', '_')

    def oleid(self):
        oid = oleid.OleID(self.processed_file_path)
        indicators = oid.check()
        indicators_list = []
        dbot_score = None
        indicators_dict = {}
        for i in indicators:
            indicators_list.append({'Indicator': str(i.name),
                                    'Value': str(i.value),
                                    'Ole Risk': str(i.risk),
                                    'Description': str(i.description)})

            if str(i.name):
                indicators_dict[self.replace_space_with_underscore(str(i.name))] = {
                    'Value': str(i.value),
                    'Ole_Risk': str(i.risk),
                    'Description': str(i.description)
                }

            if str(i.name) == 'VBA Macros' and str(i.risk) == 'HIGH':
                dbot_score = Common.DBotScore(self.hash,
                                              DBotScoreType.FILE,
                                              'Oletools',
                                              Common.DBotScore.BAD)

        indicator = Common.File(dbot_score, sha256=self.hash) if dbot_score else None
        cr = CommandResults(readable_output=tableToMarkdown(self.name, indicators_list,
                                                            headers=['Indicator', 'Value', 'Ole Risk',
                                                                     'Description']) + f'\n file hash: {self.hash}',
                            outputs=indicators_dict,
                            outputs_prefix='Oletools.Oleid',
                            indicator=indicator
                            )
        return cr

    def oleobj(self):
        import re

        args = []
        command = 'oleobj'
        file = self.processed_file_path
        args.append(command)
        args.append(file)

        output = subprocess.run(args, capture_output=True)

        regex = r"Found relationship 'hyperlink' with external link (.*?)\n"
        str_output = output.stdout.decode("utf-8")
        matches = re.findall(regex, str_output, re.MULTILINE)
        readable_md = '### Found the following relationship "hyperlink" with external links\n'
        hyperlink_list = []

        if not matches:
            readable_md = '### No "hyperlink" with external links were found'
        else:
            for match in matches:
                readable_md += f'- {match}\n'
                hyperlink_list.append(match)

        cr = CommandResults(readable_output=readable_md, outputs_prefix='Oletools.Oleobj',
                            outputs={'hyperlinks': hyperlink_list},
                            raw_response=str_output)
        return cr

    def olevba(self):
        file_data = open(self.processed_file_path, 'rb').read()
        vbaparser = VBA_Parser(self.processed_file_path, data=file_data, disable_pcode=True)

        if not vbaparser.detect_vba_macros():
            return CommandResults(readable_output='### No VBA Macros found\n')

        found = '### VBA Macros found\n'
        all_macros = vbaparser.extract_all_macros()
        macros_list = []

        for macro in all_macros:
            macros_list.append({
                'VBA Macro': macro[2],
                'Found in file': macro[0],
                'Ole stream': macro[1]
            })

        macros_list_md = tableToMarkdown('Macros found', macros_list,
                                         headers=['VBA Macro', 'Found in file', 'Ole stream'])

        macro_source_code = vbaparser.reveal()
        readable_macro = f'\n### Macro source code\n {macro_source_code}\n'

        results = vbaparser.analyze_macros(show_decoded_strings=self.show_decoded)
        results_list = []
        for result in results:
            results_list.append({
                'Type': result[0],
                'Keyword': result[1],
                'Description': result[2]
            })

        results_md = tableToMarkdown('Macro Analyze', results_list, headers=['Type', 'Keyword', 'Description'])
        vbaparser.close()

        readable_output = found + macros_list_md + readable_macro + results_md
        outputs = {
            'macro_list': macros_list,
            'macro_src_code': macro_source_code,
            'macro_analyze': results_list
        }
        cr = CommandResults(readable_output=readable_output, outputs_prefix='Oletools.Olevba', outputs=outputs)
        return cr


def handle_password(non_secret_password: str, password: str) -> str:
    if non_secret_password and not password:
        return non_secret_password
    elif password and non_secret_password:
        raise ValueError('Please insert a password or a non_secret_password not both')
    return password


def main():  # pragma: no cover
    args = demisto.args()
    ole_command = args.get('ole_command')
    attach_id = args.get('entryID', '')
    file_info = demisto.getFilePath(attach_id)
    show_decoded = argToBoolean(args.get('decode', False))
    password = args.get('password', '')
    non_secret_password = args.get('non_secret_password', '')

    try:
        password = handle_password(password=password, non_secret_password=non_secret_password)
        ole_client = OleClient(file_info, ole_command, password=password, decoded=show_decoded)
        return_results(ole_client.run())
    except Exception as e:
        return_error(f'The script failed with the following error:\n {e}'
                     f'\n Logs form oletools:\n {custom_handler.get_last_log_msg()}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
