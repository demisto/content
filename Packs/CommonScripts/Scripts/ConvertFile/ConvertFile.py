import demistomock as demisto
from CommonServerPython import *

import subprocess
import glob
import os
import tempfile
import shutil
import traceback
from typing import List


def find_zombie_processes():
    """find zombie proceses

    Returns:
        ([process ids], raw ps output) -- return a tuple of zombie process ids and raw ps output
    """
    ps_out = subprocess.check_output(['ps', '-e', '-o', 'pid,ppid,state,cmd'],
                                     stderr=subprocess.STDOUT, universal_newlines=True)
    lines = ps_out.splitlines()
    pid = str(os.getpid())
    zombies = []
    if len(lines) > 1:
        for line in lines[1:]:
            pinfo = line.split()
            if pinfo[2] == 'Z' and pinfo[1] == pid:  # zombie process
                zombies.append(pinfo[0])
    return zombies, ps_out


def convert_file(file_path: str, out_format: str, all_files: bool, outdir: str) -> List[str]:
    try:
        run_cmd = ['soffice', '--headless', '-env:UserInstallation=file:///tmp/convertfile/.config',
                   '--convert-to', out_format, file_path, '--outdir', outdir]
        env = os.environ.copy()
        env['HOME'] = '/tmp/convertfile'
        res = subprocess.check_output(run_cmd, stderr=subprocess.STDOUT, universal_newlines=True, env=env)
        demisto.debug("completed running: {}. With result: {}".format(run_cmd, res))
        if all_files:
            files = glob.glob(outdir + '/*')
        else:
            ext = out_format.split(':')[0]
            files = glob.glob(outdir + '/*.' + ext)
        if not files:
            raise ValueError('Failed convert for output format: {}. Convert process log: {}'.format(out_format, res))
        return files
    finally:
        # make sure we don't have zombie processes (seen when converting pdf to html)
        try:
            zombies, ps_out = find_zombie_processes()
            if zombies:
                demisto.info("Found zombie processes will waitpid: {}".format(ps_out))
                for pid in zombies:
                    waitres = os.waitpid(int(pid), os.WNOHANG)
                    demisto.info("waitpid result: {}".format(waitres))
            else:
                demisto.debug("No zombie processes found for ps output: {}".format(ps_out))
        except Exception as ex:
            demisto.error("Failed checking for zombie processes: {}. Trace: {}".format(ex, traceback.format_exc()))


def main():
    entry_id = demisto.args()["entry_id"]
    out_format = demisto.args().get('format', 'pdf')
    all_files = demisto.args().get('all_files', 'no') == 'yes'
    # URLS
    try:
        result = demisto.getFilePath(entry_id)
        if not result:
            return_error("Couldn't find entry id: {}".format(entry_id))
        demisto.debug('going to convert: {}'.format(result))
        file_path = result['path']
        file_path_name_only = os.path.splitext(os.path.basename(file_path))[0]
        file_name = result.get('name')
        if file_name:  # remove the extension
            file_name = os.path.splitext(file_name)[0]
        with tempfile.TemporaryDirectory() as outdir:
            files = convert_file(file_path, out_format, all_files, outdir)
            if not files:
                return_error('No file result returned for convert format: {}'.format(out_format))
                return
            for f in files:
                temp = demisto.uniqueFile()
                shutil.copy(f, demisto.investigation()['id'] + '_' + temp)
                name = os.path.basename(f)
                if file_name:
                    name = name.replace(file_path_name_only, file_name)
                demisto.results({
                    'Contents': '',
                    'ContentsFormat': formats['text'],
                    'Type': entryTypes['file'],
                    'File': name,
                    'FileID': temp
                })
    except subprocess.CalledProcessError as e:
        return_error("Failed converting file. Output: {}. Error: {}".format(e.output, e))
    except Exception as e:
        return_error("Failed converting file. General exception: {}.\n\nTrace:\n{}".format(e, traceback.format_exc()))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
