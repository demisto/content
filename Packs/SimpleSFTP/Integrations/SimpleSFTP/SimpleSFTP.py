import demistomock as demisto
from CommonServerPython import *

import paramiko
import traceback


def main():
    HOST = demisto.params()["host"]
    USERNAME = demisto.params()['authentication']['identifier']
    PASSWORD = demisto.params()['authentication']['password']
    PORT = int(demisto.params()["port"])

    if demisto.command() == "test-module":
        try:
            client = paramiko.Transport(HOST, PORT)
            client.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(client)
            sftp.close()
            demisto.results("ok")
        except Exception as ex:
            demisto.error(traceback.format_exc())  # print the traceback
            return_error(f'Failed to connect Error: {str(ex)}')

    if demisto.command() == "sftp-listdir":
        try:
            client = paramiko.Transport(HOST, PORT)
            client.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(client)
            directory = demisto.args()["directory"]
            res = sftp.listdir(path=directory)
            entry = {
                'Type': entryTypes['note'],
                'ContentsFormat': formats['text'],
                'Contents': res,
                'ReadableContentsFormat': formats['text'],
                'HumanReadable': tableToMarkdown('The directory files:', res),
                'EntryContext': {"SFTP.ListDir": res}
            }
            demisto.results(entry)
            sftp.close()
        except Exception as ex:
            demisto.error(traceback.format_exc())  # print the traceback
            return_error(f'Error occurred - Error: {str(ex)}')

    elif demisto.command() == "sftp-copyfrom":
        try:
            client = paramiko.Transport(HOST, PORT)
            client.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(client)
            filePath = demisto.args()["filePath"]
            sftp.get(filePath, "/tmp/" + filePath[filePath.rindex("/") + 1:])
            sftp.close()
            with open("/tmp/" + filePath[filePath.rindex("/") + 1:], "r") as f:
                data = f.read()
                if demisto.args()["returnFile"] == "True":
                    demisto.results(fileResult(filename=filePath[filePath.rindex("/") + 1:], data=data))
                else:
                    entry = {
                        'Type': entryTypes['note'],
                        'ContentsFormat': formats['text'],
                        'Contents': data,
                        'ReadableContentsFormat': formats['text'],
                        'HumanReadable': data,
                        'EntryContext': {"SFTP.File.Content": data}
                    }
                    demisto.results(entry)
        except Exception as ex:
            demisto.error(traceback.format_exc())  # print the traceback
            return_error(f'Error occurred - Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
