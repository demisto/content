class InvalidPackException(Exception):
    def __init__(self, pack_name: str, reason: str):
        self.message = f'invalid pack {pack_name}: {reason}'


class InvalidPackNameException(InvalidPackException):
    def __init__(self, pack_name: str):
        super().__init__(pack_name, 'Invalid pack name')


class InexistentException(InvalidPackException):
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
