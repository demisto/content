from pathlib import Path


class InvalidPackException(Exception):
    def __init__(self, pack_name: str, reason: str):
        self.message = f'invalid pack {pack_name}: {reason}'


class InvalidPackNameException(InvalidPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Invalid pack name')


class InexistentPackException(InvalidPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Inexistent pack name')


class IgnoredPackException(InvalidPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Pack is ignored')


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


class EmptyMachineListException(Exception):
    pass


class InvalidVersionException(Exception):
    pass


class NoTestsConfiguredException(Exception):
    """ used when an integration has no tests configured """

    # todo log test collection reasons
    def __init__(self, content_id: str):
        self.id_ = content_id  # todo use or remove
