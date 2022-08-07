from pathlib import Path


class InvalidPackException(Exception):
    def __init__(self, pack_name: str, reason: str):
        self.message = f'invalid pack {pack_name}: {reason}'


class BlankPackNameException(InvalidPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Blank pack name')


class NonexistentPackException(InvalidPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Nonexistent pack name')


class UnsupportedPackException(InvalidPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'pack support level is not XSOAR')


class DeprecatedPackException(InvalidPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Pack is deprecated')


class SkippedPackException(InvalidPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Pack is skipped')


class NonDictException(Exception):
    def __init__(self, path: Path):
        self.message = path
        super().__init__(self.message)


class NoTestsConfiguredException(Exception):
    """ raised when an integration has no tests configured """

    def __init__(self, content_id: str):
        self.message = f'The content item with id {content_id} has `Tests: No Tests` configured. ' \
                       f'This is not an error! Tests for this integration are to be taken from the conf.json instead.'
        super().__init__(self.message)


class NotUnderPackException(Exception):
    def __init__(self, path: Path):
        self.message = f'Could not find a pack for {str(path)}'
        super().__init__(self.message)


class NothingToCollectException(Exception):
    def __init__(self, path: Path, reason: str):
        self.message = f'Not collecting tests or packs for {str(path)}: {reason}'
        super().__init__(self.message)


class InvalidTestException(Exception):
    def __init__(self, test_name: str, reason: str):
        self.message = f'invalid test {test_name}: {reason}'


class TestMissingFromIdSetException(Exception):
    def __init__(self, test_name: str):
        self.message = f'Test {test_name} is missing from the id-set'
        super().__init__(self.message)


class SkippedTestException(InvalidTestException):
    def __init__(self, test_name: str, skip_reason: str):
        super().__init__(test_name, f'Test {test_name} is skipped: {skip_reason}')


class PrivateTestException(InvalidTestException):
    def __init__(self, test_name: str):
        super().__init__(test_name, f'Test {test_name} is private')
