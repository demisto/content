"""Configuring tests for the content suite
"""
import pytest
from _pytest.fixtures import FixtureRequest
from _pytest.tmpdir import TempPathFactory, _mk_tmp
from demisto_sdk.TestSuite.integration import Integration
from demisto_sdk.TestSuite.pack import Pack
from demisto_sdk.TestSuite.repo import Repo

# Helper Functions


def get_repo(request: FixtureRequest, tmp_path_factory: TempPathFactory) -> Repo:
    tmp_dir = _mk_tmp(request, tmp_path_factory)
    return Repo(tmp_dir)


def get_pack(request: FixtureRequest, tmp_path_factory: TempPathFactory) -> Pack:
    """Mocking tmp_path
    """
    return get_repo(request, tmp_path_factory).create_pack()


def get_integration(request: FixtureRequest, tmp_path_factory: TempPathFactory) -> Integration:
    """Mocking tmp_path
    """
    integration = get_pack(request, tmp_path_factory).create_integration()
    integration.create_default_integration()
    return integration


# Fixtures


@pytest.fixture
def pack(request: FixtureRequest, tmp_path_factory: TempPathFactory) -> Pack:
    """Mocking tmp_path
    """
    return get_pack(request, tmp_path_factory)


@pytest.fixture
def integration(request: FixtureRequest, tmp_path_factory: TempPathFactory) -> Integration:
    """Mocking tmp_path
    """
    return get_integration(request, tmp_path_factory)


@pytest.fixture
def repo(request: FixtureRequest, tmp_path_factory: TempPathFactory) -> Repo:
    """Mocking tmp_path
    """
    return get_repo(request, tmp_path_factory)
