from dataclasses import dataclass
from typing import Optional

from packaging import version
from packaging._structures import InfinityType, NegativeInfinityType
from packaging.version import Version


@dataclass
class VersionRange:
    min_version: Version | NegativeInfinityType
    max_version: Version | InfinityType

    def __contains__(self, item):
        return self.min_version <= item <= self.max_version

    def __repr__(self):
        return f'{self.min_version} -> {self.max_version}'

    def __or__(self, other: Optional['VersionRange']) -> 'VersionRange':
        if other is None or other.is_default or self.is_default:
            return self

        self.min_version = min(self.min_version, other.min_version)
        self.max_version = max(self.max_version, other.max_version)

        return self

    @property
    def is_default(self):
        """
        :return: whether the range is (-Infinity -> Infinity)
        """
        return self.min_version == version.NegativeInfinity and self.max_version == version.Infinity
