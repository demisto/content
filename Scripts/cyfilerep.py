# Retrieve file entry reputation using Cylance
# First, get the file entry, check with Cylance if the file is known and if not, upload the file, wait 5 seconds and check again
import time

e = demisto.args()['entry']
fileEntry = demisto.executeCommand('getEntry', {'id': e})
if fileEntry and len(fileEntry) == 1 and fileEntry[0]['Type'] != entryTypes['error']:
    fe = fileEntry[0]
    if fe['File'] and demisto.get(fe, 'FileMetadata.md5'):
        rep = demisto.executeCommand('file', {'file': demisto.get(fe, 'FileMetadata.md5'), 'using-brand': brands['cy']})
        if rep and len(rep) == 1 and rep[0]['Type'] != entryTypes['error']:
            contents = demisto.get(rep[0], 'Contents')
            k = contents.keys()
            if k and len(k) > 0:
                v = contents[k[0]]
                if demisto.get(v, 'status') == 'NEEDFILE' and demisto.get(v, 'confirmcode'):
                    upload = demisto.executeCommand('cy-upload', {'entry': e, 'confirmCode': demisto.get(v, 'confirmcode')})
                    if upload and len(upload) == 1 and upload[0]['Type'] != entryTypes['error']:
                        contents = demisto.get(upload[0], 'Contents')
                        k = contents.keys()
                        if k and len(k) > 0:
                            v1 = contents[k[0]]
                            if demisto.get(v1, 'status') == 'ACCEPTED':
                                time.sleep(10)
                                rep = demisto.executeCommand('file', {'file': demisto.get(fe, 'FileMetadata.md5'), 'using-brand': brands['cy']})
                                if rep and len(rep) == 1 and rep[0]['Type'] != entryTypes['error']:
                                    demisto.results(shortFile(rep[0]))
                                else:
                                    demisto.results(rep)
                            else:
                                demisto.results(upload)
                    else:
                        demisto.results(upload)
                else:
                    demisto.results(shortFile(rep[0]))
        else:
            demisto.results(rep)
    else:
        demisto.results('Entry is not a file')
else:
    demisto.results('Unable to retrieve entry')
