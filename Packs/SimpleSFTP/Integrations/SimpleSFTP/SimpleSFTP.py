import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


""" IMPORTS """


import traceback
import paramiko


def get_file_path(file_id):
    filepath_result = demisto.getFilePath(file_id)
    return filepath_result


""" MAIN FUNCTION """


def main():
    HOST = demisto.params()["host"]
    USERNAME = demisto.params()["authentication"]["identifier"]
    PASSWORD = demisto.params()["authentication"]["password"]
    PORT = int(demisto.params()["port"])

    if demisto.command() == "test-module":
        try:
            client = paramiko.Transport(HOST, PORT)
            client.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(client)
            sftp.close()  # type: ignore
            demisto.results("ok")
        except Exception as ex:
            demisto.error(traceback.format_exc())  # print the traceback
            return_error(f"Failed to connect Error: {str(ex)}")

    if demisto.command() == "sftp-listdir":
        try:
            client = paramiko.Transport(HOST, PORT)
            client.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(client)
            directory = demisto.args()["directory"]
            res = sftp.listdir(path=directory)  # type: ignore
            entry = {
                "Type": entryTypes["note"],
                "ContentsFormat": formats["text"],
                "Contents": res,
                "ReadableContentsFormat": formats["markdown"],
                "HumanReadable": tableToMarkdown(
                    "The directory files:", res, ["Directory Files"]
                ),
                "EntryContext": {"SFTP.ListDir": res},
            }
            demisto.results(entry)
            sftp.close()  # type: ignore
        except Exception as ex:
            demisto.error(traceback.format_exc())  # print the traceback
            return_error(
                f"Error occurred - Error: {str(ex)}. Please verify directory path to list files"
            )

    elif demisto.command() == "sftp-copyfrom":
        try:
            client = paramiko.Transport(HOST, PORT)
            client.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(client)
            file_path = demisto.args()["file_path"]
            sftp.get(file_path, "/tmp/" + file_path[file_path.rindex("/") + 1:])  # type: ignore
            sftp.close()  # type: ignore
            with open("/tmp/" + file_path[file_path.rindex("/") + 1:]) as f:
                data = f.read()
                if demisto.args()["return_file"] == "True":
                    demisto.results(
                        fileResult(
                            filename=file_path[file_path.rindex("/") + 1:], data=data
                        )
                    )
                else:
                    entry = {
                        "Type": entryTypes["note"],
                        "ContentsFormat": formats["text"],
                        "Contents": data,
                        "ReadableContentsFormat": formats["text"],
                        "HumanReadable": data,
                        "EntryContext": {"SFTP.File.Content": data},
                    }
                    demisto.results(entry)
        except Exception as ex:
            demisto.error(traceback.format_exc())  # print the traceback
            return_error(f"Error occurred - Error: {str(ex)}")

    elif demisto.command() == "sftp-upload-file":
        try:
            args = demisto.args()
            client = paramiko.Transport(HOST, PORT)
            client.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(client)
            file_path = get_file_path(args.get("file_entry_id"))
            sftp.put(file_path["path"], args.get("path") + "/" + file_path["name"])  # type: ignore
            sftp.close()  # type: ignore
            demisto.results("File uploaded successfully")
        except Exception as ex:
            demisto.error(traceback.format_exc())  # print the traceback
            return_error(f"Error occurred - Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
