import zlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ImpervaIncapsulaCommunityEventCollector import (
    RateLimitError,
    decode_file,
    fetch_events,
    file_counter,
    is_valid_log_file_name,
)


# --------------------------------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------------------------------


@pytest.fixture()
def rsa_keypair():
    """Generates a throwaway RSA keypair at test time - never commit real or fixture key material."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return private_key, private_pem


def build_encrypted_file(content: bytes, private_key, public_key_id: str = "1") -> bytes:
    """Builds a file byte string in Imperva's encrypted-log format for a given RSA keypair."""
    import base64
    import hashlib

    compressor = zlib.compressobj()
    compressed = compressor.compress(content) + compressor.flush()
    aes_key = b"0123456789abcdef"  # 16-byte AES-128 key
    iv = b"\x00" * 16
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    # PKCS7 pad to the AES block size.
    pad_len = 16 - (len(compressed) % 16)
    padded = compressed + bytes([pad_len]) * pad_len
    encrypted_payload = encryptor.update(padded) + encryptor.finalize()

    public_key = private_key.public_key()
    encrypted_sym_key = public_key.encrypt(base64.b64encode(aes_key), padding.PKCS1v15())
    checksum = hashlib.md5(content).hexdigest()

    header = (
        f"key:{base64.b64encode(encrypted_sym_key).decode()}\n" f"publicKeyId:{public_key_id}\n" f"checksum:{checksum}\n"
    ).encode()
    return header + b"|==|\n" + encrypted_payload


# --------------------------------------------------------------------------------------------------
# is_valid_log_file_name / file_counter
# --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("123456_789.log", True),
        ("123456_789.log\r\n", False),  # caller is responsible for stripping line endings first
        ("123456_789.logxxx", False),  # unanchored re.match would have accepted this
        ("not_a_log_file", False),
        ("123456_789.log.bak", False),
        ("", False),
    ],
)
def test_is_valid_log_file_name(name, expected):
    assert is_valid_log_file_name(name) is expected


def test_file_counter():
    assert file_counter("123456_789.log") == 789
    assert file_counter("123456_10.log") < file_counter("123456_9999.log")
    assert file_counter("garbage") == -1


# --------------------------------------------------------------------------------------------------
# decode_file
# --------------------------------------------------------------------------------------------------


def test_decode_file_plaintext_no_header():
    """Formats without a '|==|' header (not CEF/LEEF/W3C) are returned unchanged."""
    content = b"some,plain,csv,content\nrow2\n"
    assert decode_file(content, "1_1.log", None, None) == content


def test_decode_file_compressed_not_encrypted():
    raw_lines = b"CEF:0|Incapsula|SIEMintegration|1|1|Normal|0|fileId=1 src=1.2.3.4\n"
    compressor = zlib.compressobj()
    compressed = compressor.compress(raw_lines) + compressor.flush()
    file_content = b"format:cef\n" + b"|==|\n" + compressed

    result = decode_file(file_content, "1_1.log", None, None)
    assert result == raw_lines


def test_decode_file_encrypted_and_compressed(rsa_keypair):
    private_key, private_pem = rsa_keypair
    raw_lines = b"CEF:0|Incapsula|SIEMintegration|1|1|Normal|0|fileId=2 src=5.6.7.8\n"
    file_content = build_encrypted_file(raw_lines, private_key, public_key_id="7")

    result = decode_file(file_content, "1_2.log", private_pem, "7")
    assert result == raw_lines


def test_decode_file_encrypted_without_configured_key_raises(rsa_keypair):
    private_key, _ = rsa_keypair
    file_content = build_encrypted_file(b"content", private_key)

    with pytest.raises(Exception, match="no log encryption private key is configured"):
        decode_file(file_content, "1_3.log", None, None)


def test_decode_file_encrypted_public_key_id_mismatch_raises(rsa_keypair):
    private_key, private_pem = rsa_keypair
    file_content = build_encrypted_file(b"content", private_key, public_key_id="1")

    with pytest.raises(Exception, match="does not match the configured public key ID"):
        decode_file(file_content, "1_4.log", private_pem, "2")


# --------------------------------------------------------------------------------------------------
# fetch_events
# --------------------------------------------------------------------------------------------------


class FakeClient:
    """Stand-in for Client, driven purely by an in-memory index and file map for fetch_events tests."""

    def __init__(self, index_entries, files, rate_limit_after=None):
        self.index_entries = index_entries
        self.files = files
        self.rate_limit_after = rate_limit_after
        self.requested_files = []

    def get_index(self):
        return list(self.index_entries)

    def get_log_file(self, file_name):
        self.requested_files.append(file_name)
        if self.rate_limit_after is not None and len(self.requested_files) > self.rate_limit_after:
            raise RateLimitError("rate limited")
        return self.files.get(file_name)


def _cef(file_id: str) -> bytes:
    return f"CEF:0|Incapsula|SIEMintegration|1|1|Normal|0|fileId={file_id}\n".encode()


def test_fetch_events_first_run_backfill_limits_history():
    index = [f"100_{i}.log" for i in range(1, 21)]  # 100_1.log .. 100_20.log
    files = {name: _cef(name) for name in index}
    client = FakeClient(index, files)

    events, next_run = fetch_events(
        client, last_run={}, private_key_pem=None, public_key_id=None, first_fetch_files=5, max_files_per_fetch=50
    )

    # Only the 5 most recent entries should have been downloaded...
    assert client.requested_files == index[-5:]
    assert len(events) == 5
    # ...but ALL 20 entries should now be marked processed, so older ones are never retried.
    assert set(next_run["processed"]) == set(index)


def test_fetch_events_subsequent_run_only_fetches_new_entries():
    index = [f"100_{i}.log" for i in range(1, 6)]
    files = {name: _cef(name) for name in index}
    client = FakeClient(index, files)
    last_run = {"processed": index[:3]}

    events, next_run = fetch_events(client, last_run, None, None, first_fetch_files=10, max_files_per_fetch=50)

    assert client.requested_files == index[3:]
    assert len(events) == 2
    assert set(next_run["processed"]) == set(index)


def test_fetch_events_respects_max_files_per_fetch():
    index = [f"100_{i}.log" for i in range(1, 11)]
    files = {name: _cef(name) for name in index}
    client = FakeClient(index, files)

    events, next_run = fetch_events(
        client, last_run={"processed": []}, private_key_pem=None, public_key_id=None, first_fetch_files=10, max_files_per_fetch=3
    )

    assert client.requested_files == index[:3]
    assert len(events) == 3
    # Files beyond the cap stay unprocessed for the next cycle.
    assert set(next_run["processed"]) == set(index[:3])


def test_fetch_events_aged_out_file_marked_processed_without_content():
    index = ["100_1.log", "100_2.log"]
    files = {"100_1.log": _cef("1")}  # 100_2.log deliberately missing -> simulates a 404
    client = FakeClient(index, files)

    events, next_run = fetch_events(
        client, last_run={"processed": []}, private_key_pem=None, public_key_id=None, first_fetch_files=10, max_files_per_fetch=50
    )

    assert len(events) == 1
    assert set(next_run["processed"]) == set(index)


def test_fetch_events_stops_cleanly_on_rate_limit():
    index = [f"100_{i}.log" for i in range(1, 6)]
    files = {name: _cef(name) for name in index}
    client = FakeClient(index, files, rate_limit_after=2)

    events, next_run = fetch_events(
        client, last_run={"processed": []}, private_key_pem=None, public_key_id=None, first_fetch_files=10, max_files_per_fetch=50
    )

    assert len(events) == 2
    # The file that triggered the rate limit, and everything after it, is left unprocessed.
    assert set(next_run["processed"]) == set(index[:2])


def test_fetch_events_processed_state_bounded_to_current_index():
    """Files that age out of the index entirely are dropped from `processed`, keeping it bounded."""
    old_index = [f"100_{i}.log" for i in range(1, 4)]
    new_index = [f"100_{i}.log" for i in range(4, 7)]
    files = {name: _cef(name) for name in new_index}
    client = FakeClient(new_index, files)
    last_run = {"processed": old_index}  # no longer present in the current index

    _, next_run = fetch_events(client, last_run, None, None, first_fetch_files=10, max_files_per_fetch=50)

    assert set(next_run["processed"]) == set(new_index)
    assert not set(next_run["processed"]) & set(old_index)


def test_fetch_events_invalid_index_entries_are_ignored():
    index = ["100_1.log", "not-a-log-file", "100_2.log.bak"]
    client = FakeClient(index, {"100_1.log": _cef("1")})

    events, next_run = fetch_events(
        client, last_run={"processed": []}, private_key_pem=None, public_key_id=None, first_fetch_files=10, max_files_per_fetch=50
    )

    assert client.requested_files == ["100_1.log"]
    assert len(events) == 1
