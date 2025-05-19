import glob
import os
import shutil
import subprocess
import tempfile
import traceback
import hashlib

import demistomock as demisto
from CommonServerPython import *


def find_zombie_processes():
    """find zombie proceses

    Returns:
        ([process ids], raw ps output) -- return a tuple of zombie process ids and raw ps output
    """
    ps_out = subprocess.check_output(["ps", "-e", "-o", "pid,ppid,state,cmd"],  # pragma: no cover
                                     stderr=subprocess.STDOUT, universal_newlines=True)  # pragma: no cover
    lines = ps_out.splitlines()
    pid = str(os.getpid())
    zombies = []
    if len(lines) > 1:
        for line in lines[1:]:
            pinfo = line.split()
            if pinfo[2] == "Z" and pinfo[1] == pid:  # zombie process
                zombies.append(pinfo[0])
    return zombies, ps_out


def convert_file(file_path: str, out_format: str, all_files: bool, outdir: str, entry_id) -> list[str]:
    try:
        run_cmd = [
            "soffice",
            "--headless",
            "-env:UserInstallation=file:///tmp/convertfile/.config",
            "--convert-to",
            out_format,
            file_path,
            "--outdir",
            outdir,
        ]
        env = os.environ.copy()
        env["HOME"] = "/tmp/convertfile"
        res = subprocess.check_output(run_cmd, stderr=subprocess.STDOUT, universal_newlines=True, env=env)  # pragma: no cover
        demisto.debug(f"completed running: {run_cmd}. With result: {res}")
        if all_files:
            files = glob.glob(outdir + "/*")
        else:
            ext = out_format.split(":")[0]
            files = glob.glob(outdir + "/*." + ext)
        if not files:
            raise ValueError(f"Failed convert for output format: {out_format}. Convert process log: {res}")
        return files
    finally:
        # make sure we don't have zombie processes (seen when converting pdf to html)
        try:
            zombies, ps_out = find_zombie_processes()
            if zombies:  # pragma no cover
                demisto.info(f"Found zombie processes will waitpid: {ps_out}")
                for pid in zombies:
                    waitres = os.waitpid(int(pid), os.WNOHANG)
                    demisto.info(f"waitpid result: {waitres}")
            else:
                demisto.debug(f"No zombie processes found for ps output: {ps_out}")
        except Exception as ex:
            error = f"Failed checking for zombie processes: {ex}. Trace: {traceback.format_exc()}"
            return_results(CommandResults(outputs_prefix='ConvertedFile',
                                          outputs={'EntryID': entry_id, 'Convertable': 'no', "ERROR": error}))


def make_sha(file_path):
    with open(file_path, "rb") as file:
        file_data = file.read()
        hash_object = hashlib.sha256(file_data)
        sha256_hash = hash_object.hexdigest()
    return sha256_hash


def main():
    entry_id = demisto.args()["entry_id"]  # pragma: no cover
    out_format = demisto.args().get("format", "pdf")  # pragma: no cover
    all_files = demisto.args().get("all_files", "no") == "yes"  # pragma: no cover
    # URLS
    try:
        result = demisto.getFilePath(entry_id)  # pragma: no cover
        if not result:
            return_results(CommandResults(outputs_prefix='ConvertedFile',
                                          outputs={'EntryID': entry_id, 'Convertable': 'no',
                                                   "ERROR": f"Couldn't find entry id: {entry_id}"}))
        demisto.debug(f"going to convert: {result}")
        file_path = result["path"]
        file_path_name_only = os.path.splitext(os.path.basename(file_path))[0]
        file_name = result.get("name")
        if file_name:  # remove the extension
            file_name = os.path.splitext(file_name)[0]
        with tempfile.TemporaryDirectory() as outdir:
            files = convert_file(file_path, out_format, all_files, outdir, entry_id)
            if not files:
                return_results(CommandResults(outputs_prefix='ConvertedFile',
                                          outputs={'EntryID': entry_id, 'Convertable': 'no',
                                                   "ERROR": f"No file result returned for convert format: {out_format}"}))
                return
            for f in files:
                try:
                    temp = demisto.uniqueFile()
                    shutil.copy(f, demisto.investigation()["id"] + "_" + temp)  # pragma: no cover
                    name = os.path.basename(f)
                    if file_name:
                        name = name.replace(file_path_name_only, file_name)
                    demisto.results(
                        {"Contents": "",
                         "ContentsFormat": formats["text"],
                         "Type": entryTypes["file"],
                         "File": name, "FileID": temp}
                    )
                    sha256 = make_sha(f)
                    return_results(CommandResults(outputs_prefix='ConvertedFile',
                                                  outputs={'Name': name, 'FileSHA256': sha256, 'Convertable': 'yes'}))
                except Exception as e:
                    return_results(CommandResults(outputs_prefix='ConvertedFile',
                                                  outputs={'Name': name, 'EntryID': entry_id,
                                                           'Convertable': 'no', "ERROR": str(e)}))
    except subprocess.CalledProcessError as e:
        return_results(CommandResults(outputs_prefix='ConvertedFile',
                                      outputs={'EntryID': entry_id, 'Convertable': 'no', "ERROR": str(e)}))
    except Exception as e:
        return_results(CommandResults(outputs_prefix='ConvertedFile',
                                      outputs={'EntryID': entry_id, 'Convertable': 'no', "ERROR": str(e)}))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":  # pragma: no cover
    main()
