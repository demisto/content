import os
import re
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv()

AUTH_FILE = Path("playwright/.auth/user.json")


@pytest.fixture(scope="session")
def base_url():
    return os.environ["XSOAR_BASE_URL"]


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    return {**browser_context_args, "ignore_https_errors": True}


@pytest.fixture(scope="session")
def _auth_state(browser):
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    context = browser.new_context(ignore_https_errors=True)
    page = context.new_page()

    page.goto(f"{os.environ['XSOAR_BASE_URL']}/#/login")
    page.locator('input[name="user"]').fill(os.environ["XSOAR_USERNAME"])
    page.locator('input[type="password"]').fill(os.environ["XSOAR_PASSWORD"])
    page.locator('button[type="submit"]').click()
    page.wait_for_url(re.compile(r"#/(home|incidents|dashboard|alerts)"))

    context.storage_state(path=str(AUTH_FILE))
    context.close()
    return str(AUTH_FILE)


@pytest.fixture
def auth_page(_auth_state, browser):
    context = browser.new_context(storage_state=_auth_state, ignore_https_errors=True)
    page = context.new_page()
    yield page
    context.close()
