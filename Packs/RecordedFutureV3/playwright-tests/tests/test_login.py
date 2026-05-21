import os
import re

from playwright.sync_api import Page, expect


def test_login_form_renders(page: Page, base_url: str):
    page.goto(f"{base_url}/#/login")
    expect(page.locator('input[name="user"]')).to_be_visible()
    expect(page.locator('input[type="password"]')).to_be_visible()
    expect(page.locator('button[type="submit"]')).to_be_enabled()


def test_login_with_valid_credentials(page: Page, base_url: str):
    page.goto(f"{base_url}/#/login")
    page.locator('input[name="user"]').fill(os.environ["XSOAR_USERNAME"])
    page.locator('input[type="password"]').fill(os.environ["XSOAR_PASSWORD"])
    page.locator('button[type="submit"]').click()

    page.wait_for_url(re.compile(r"#/(home|incidents|dashboard|alerts)"))
    assert "#/login" not in page.url


def test_login_with_invalid_credentials(page: Page, base_url: str):
    page.goto(f"{base_url}/#/login")
    page.locator('input[name="user"]').fill("invalid-user")
    page.locator('input[type="password"]').fill("wrong-password")
    page.locator('button[type="submit"]').click()

    error = page.get_by_text("Username and password do not match.")
    expect(error).to_be_visible(timeout=5000)
    assert "#/login" in page.url
