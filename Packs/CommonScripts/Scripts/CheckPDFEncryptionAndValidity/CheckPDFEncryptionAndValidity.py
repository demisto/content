from typing import Any, Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import PyPDF2



def check_PDF_encryption_and_validity(entry_id) -> CommandResults:
    """This function checks the encryption and validity of a PDF file based on the provided entry ID.

    Args:
        entry_id (str): The entry ID of the PDF file to be checked.

    Raises:
        DemistoException: _description_

    Returns:
        Returns a CommandResults object containing the following fields:
        outputs_prefix (str): The prefix for the outputs (always 'File').
        outputs_key_field (str): The key field for the outputs (always 'EntryID').
        outputs (dict): A dictionary containing the following key-value pairs:
        EntryID (str): The provided entry ID.
        IsValid (bool): Indicates whether the PDF file is valid or not.
        IsEncrypted (bool): Indicates whether the PDF file is encrypted or not.
        Error (str): If an error occurs during the process, it contains the error message.
    """
    is_valid = False
    is_encrypted = False
    try:
        
        file_path = demisto.getFilePath(entry_id).get("path")
        
        if not file_path:
            raise DemistoException("File not found. Please enter a valid entry ID.")
        
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
