from typing import Any, Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import PyPDF2



def check_PDF_encryption_and_validity(entry_id):
    
    file_path = demisto.getFilePath(entry_id).get("path")
    if not file_path:
        raise DemistoException("File not found. Please enter a valid entry ID.")
    
    is_valid = False
    is_encrypted = False
    try:
        demisto.debug("Trying to open file")
        
        with open(file_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            is_valid = True
            is_encrypted = reader.is_encrypted
            
        return CommandResults(outputs_prefix='File',
                    outputs_key_field='EntryID',
                    outputs={'EntryID': entry_id, 'IsValid': is_valid, 'IsEncrypted': is_encrypted})
    
    except Exception as ex:
        return CommandResults(outputs_prefix='File',
                    outputs_key_field='EntryID',
                    outputs={'EntryID': entry_id, 'IsValid': is_valid, 'IsEncrypted': is_encrypted, 'Error': str(ex)})
        
    
def main():  # pragma: no cover
    
    args = demisto.args()
    entry_id = args.get("EntryID")
    
    try:
        return_results(check_PDF_encryption_and_validity(entry_id))
    except Exception as ex:
        return_error(f"Failed to execute CheckPDFEncryptionAndValidity. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
