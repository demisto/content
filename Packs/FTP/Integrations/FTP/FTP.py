import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
""" IMPORT """

from ftplib import FTP

""" MAIN """


def main():
    HOST = demisto.params().get('host')
    PORT = demisto.params().get('port') if demisto.params().get('port') else '21'
    USER = demisto.params()['credentials']['identifier']
    PASSWD = demisto.params()['credentials']['password']

    if demisto.command() == "test-module":
        try:
            with FTP() as ftp:  # noqa: S321
                ftp.connect(host=HOST, port=int(PORT))
                ftp.login(user=USER, passwd=PASSWD)
                ftp.voidcmd('NOOP')

            demisto.results("ok")
        except Exception as excp:
            return_error(f"Error occurred - Error: {str(excp)}")

    if demisto.command() == "ftp-ls":
        path = demisto.args().get('path')
        list_path = path if path else '~/'
        try:
            with FTP() as ftp:  # noqa: S321
                ftp.connect(host=HOST, port=int(PORT))
                ftp.login(user=USER, passwd=PASSWD)
                outputs = CommandResults(
                    outputs_prefix='FTP.List',
                    outputs={
                        'Files': ftp.nlst(f"{list_path}")
                    }
                )
                return_results(outputs)

        except IndexError:
            return_results("There is no file or folder")
        except Exception as excp:
            return_error(f"Error occurred - Error: {str(excp)}")

    if demisto.command() == "ftp-put":
        entry_id = demisto.args().get('entry_id')
        target = demisto.args().get('target')

        try:
            with FTP() as ftp:  # noqa: S321
                ftp.connect(host=HOST, port=int(PORT))
                ftp.login(user=USER, passwd=PASSWD)
                fileObject = demisto.getFilePath(entry_id)
                with open(fileObject['path'], 'rb') as file:
                    ftp.storbinary(f'STOR {target}/{fileObject["name"]}', file)

            return_results(f'File uploaded to {target}/{fileObject["name"]} successfully')

        except Exception as excp:
            return_error(f"Error occurred - Error: {str(excp)}")

    if demisto.command() == "ftp-get":
        file_path = demisto.args().get('file_path')
        file_name = demisto.args().get('file_name')

        try:
            with FTP() as ftp:  # noqa: S321
                ftp.connect(host=HOST, port=int(PORT))
                ftp.login(user=USER, passwd=PASSWD)
                with open(f'/tmp/{file_name}', 'wb') as file:
                    ftp.retrbinary(f'RETR {file_path}/{file_name}', file.write)

                with open(f"/tmp/{file_name}") as f:
                    data = f.read()
                    return_results(
                        fileResult(filename=file_name, data=data)
                    )

        except Exception as excp:
            return_error(f"Error occurred - Error: {str(excp)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
