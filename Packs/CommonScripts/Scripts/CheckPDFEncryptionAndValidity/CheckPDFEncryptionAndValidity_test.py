
from unittest.mock import MagicMock
from unittest.mock import patch
from CommonServerPython import *
from CheckPDFEncryptionAndValidity import check_PDF_encryption_and_validity


def test_file_openable():
    """
    Given: A readable pdf file that is not encrypted
    When: running check_PDF_encryption_and_validity
    Then: The function returns CommandResult with the file EntryID, IsValid==True and IsEncrypted == False
    """
    entry_id = "test_entry_id"
    with patch("builtins.open") as mock_open, patch("PyPDF2.PdfReader") as mock_PdfReader:
        mock_open.return_value.__enter__.return_value = MagicMock()
        mock_PdfReader.return_value.is_encrypted = False
        
        result = check_PDF_encryption_and_validity(entry_id)
        
        assert result.outputs_key_field == 'EntryID'
        assert result.outputs['EntryID'] == entry_id
        assert result.outputs['IsValid']
        assert not result.outputs['IsEncrypted']
        assert 'Error' not in str(result.outputs)
    
def test_file_not_openable():
    """
    Given: A not readable pdf file
    When: running check_PDF_encryption_and_validity
    Then: The function returns CommandResult with the file EntryID, IsValid==False and IsEncrypted == False
        and a error field in the outputs.
    """
    entry_id = "test_entry_id"
    with patch("builtins.open", side_effect=Exception("File could not be opened")) as mock_open,\
    patch("PyPDF2.PdfReader") as mock_PdfReader:
        mock_open.return_value.__enter__.return_value = MagicMock()
        mock_PdfReader.return_value.is_encrypted = False
    result = check_PDF_encryption_and_validity(entry_id)
        
    assert result.outputs_prefix == 'File'
    assert result.outputs_key_field == 'EntryID'
    assert result.outputs['EntryID'] == entry_id
    assert not result.outputs['IsValid']
    assert not result.outputs['IsEncrypted']
    assert 'Error' in str(result.outputs)