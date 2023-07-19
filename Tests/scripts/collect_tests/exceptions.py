from pathlib import Path
from typing import Optional

from demisto_sdk.commands.common.constants import MarketplaceVersions

from Tests.scripts.collect_tests.version_range import VersionRange


class UnsupportedPackException(Exception):
    def __init__(self, pack_name: str, reason: str):
        self.message = f'Unsupported pack {pack_name}: {reason}'

    def __str__(self):
        return self.message


class BlankPackNameException(UnsupportedPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Blank pack name')


class NonexistentPackException(UnsupportedPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Nonexistent pack name')


class NonXsoarSupportedPackException(UnsupportedPackException):
    def __init__(self, pack_name: str, support_level: str | None, content_version_range: Optional[VersionRange] = None):
        self.support_level = support_level
        self.content_version_range = content_version_range
        super().__init__(pack_name, f'pack support level is not XSOAR (it is {support_level})')


class DeprecatedPackException(UnsupportedPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Pack is deprecated')


class SkippedPackException(UnsupportedPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Pack is skipped')


class NonNightlyPackInNightlyBuildException(Exception):
    def __init__(self, pack_name: str):
        self.message = f'Skipping tests for pack {pack_name}: ' \
                       f'This is a nightly build, and the pack is not in the list of nightly packs'

    def __str__(self):
        return self.message


class NonDictException(Exception):
    def __init__(self, path: Optional[Path]):
        self.message = path
        super().__init__(self.message)

    def __str__(self):
        return self.message


class NoTestsConfiguredException(Exception):
    """ raised when an integration has no tests configured """

    def __init__(self, content_id: str):
        self.message = f'The content item with id {content_id} has `Tests: No Tests` configured. ' \
                       f'This is not an error! Tests for this integration are to be taken from the conf.json instead.'
        super().__init__(self.message)

    def __str__(self):
        return self.message


class NotUnderPackException(Exception):
    def __init__(self, path: Path | str):
        self.message = f'Could not find a pack for {str(path)}'
        super().__init__(self.message)

    def __str__(self):
        return self.message


class NothingToCollectException(Exception):
    def __init__(self, path: Path, reason: str):
        self.message = f'Nothing to collect for file {str(path)}: {reason}'
        super().__init__(self.message)

    def __str__(self):
        return self.message


class IncompatibleMarketplaceException(NothingToCollectException):
    def __init__(self, content_path: Path, expected_marketplace: MarketplaceVersions):
        super().__init__(content_path, f'is not compatible with expected marketplace {expected_marketplace.name}')


class InvalidTestException(Exception):
    def __init__(self, test_name: str, reason: str):
        self.message = f'invalid test {test_name}: {reason}'

    def __str__(self):
        return self.message


class TestMissingFromIdSetException(InvalidTestException):
    def __init__(self, test_name: str):
        super().__init__(test_name, 'missing from the id-set')


class SkippedTestException(InvalidTestException):
    def __init__(self, test_name: str, skip_place: str, skip_reason: Optional[str] = None):
        """
        :param test_name: the name of the test that was skipped
        :param skip_place: where the test was skipped (conf.json or pack_ignore)
        :param skip_reason: the reason the test was skipped (if available, mostly when skipped in conf.json)
        """
        skip_reason_suffix = f': {skip_reason}' if skip_reason else ''
        super().__init__(test_name, f'test is skipped in {skip_place}{skip_reason_suffix}')


class PrivateTestException(InvalidTestException):
    def __init__(self, test_name: str):
        super().__init__(test_name, 'test is private')
