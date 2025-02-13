from IsPDFFileEncrypted import is_pdf_encrypted

def test_is_pdf_encrypted():
    encrypted_path = "./test_data/encrypted.pdf"
    unencrypted_path = "./test_data/text-only.pdf"
    assert is_pdf_encrypted(encrypted_path)
    assert not is_pdf_encrypted(unencrypted_path)