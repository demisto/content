import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
""" IMPORT """

from ftplib import FTP

""" MAIN """


def main():
    HOST = demisto.params().get('host')
    USER = demisto.params().get('user')
    PASSWD = demisto.params().get('passwd')

    if demisto.command() == "test-module":
        try:
            with FTP(HOST) as ftp:
                ftp.login(user=USER, passwd=PASSWD)
                ftp.voidcmd('NOOP')

            demisto.results("ok")
        except Exception as excp:
            demisto.error(traceback.format_exc())
            return_error(f"Error occurred - Error: {str(excp)}")

    if demisto.command() == "ftp-ls":
        path = demisto.args().get('path')
        list_path = path if path else '~/'
        try:
            with FTP(HOST) as ftp:
                ftp.login(user=USER, passwd=PASSWD)
                demisto.results({
                    'ContentsFormat': formats["markdown"],
                    'Type': entryTypes["note"],
                    'ReadableContentsFormat': formats['markdown'],
                    'Contents': ftp.nlst(f"{list_path}"),
                    'HumanReadable': tableToMarkdown("Files and Folders", {'Files and Folders': ftp.nlst(f'{list_path}')})
                })

        except Exception as excp:
            demisto.error(traceback.format_exc())
            return_error(f"Error occurred - Error: {str(excp)}")

    if demisto.command() == "ftp-put":
        entry_id = demisto.args().get('entry_id')
        target = demisto.args().get('target')

        try:
            with FTP(HOST) as ftp:
                ftp.login(user=USER, passwd=PASSWD)
                fileObject = demisto.getFilePath(entry_id)
                with open(fileObject['path'], 'rb') as file:
                    ftp.storbinary(f'STOR {target}/{fileObject["name"]}', file)

            demisto.results(f'File uploaded to {target}/{fileObject["name"]} successfully')

        except Exception as excp:
            demisto.error(traceback.format_exc())
            return_error(f"Error occurred - Error: {str(excp)}")

    if demisto.command() == "ftp-get":
        file_path = demisto.args().get('file_path')
        file_name = demisto.args().get('file_name')

        try:
            with FTP(HOST) as ftp:
                ftp.login(user=USER, passwd=PASSWD)
                with open(f'/tmp/{file_name}', 'wb') as file:
                    ftp.retrbinary(f'RETR {file_path}/{file_name}', file.write)

                with open(f"/tmp/{file_name}", "r") as f:
                    data = f.read()
                    demisto.results(
                        fileResult(filename=file_name, data=data)
                    )

        except Exception as excp:
            demisto.error(traceback.format_exc())
            return_error(f"Error occurred - Error: {str(excp)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
