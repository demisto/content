import os
import re

from playwright.sync_api import Page, expect

INTEGRATION_NAME = "Recorded Future Alerts (Partner Contribution)"


def _open_integrations_page(page: Page, base_url: str):
    page.goto(f"{base_url}/#/settings")
    page.wait_for_selector(".integrations-settings", timeout=15000)


def _find_tile(page: Page):
    search = page.locator("input.search-bar")
    search.fill(INTEGRATION_NAME)
    page.wait_for_timeout(500)  # debounce
    tile = page.locator(".single-integration").filter(has_text=INTEGRATION_NAME).first
    expect(tile).to_be_visible(timeout=10000)
    return tile


def test_integration_tile_visible(auth_page: Page, base_url: str):
    _open_integrations_page(auth_page, base_url)
    tile = _find_tile(auth_page)
    expect(tile).to_be_visible()


def test_opens_add_instance_dialog(auth_page: Page, base_url: str):
    _open_integrations_page(auth_page, base_url)
    tile = _find_tile(auth_page)
    tile.locator(".add-integration-btn").click()

    dialog = auth_page.locator('.integration-instance-modal')
    expect(dialog).to_be_visible(timeout=10000)


def test_fills_required_fields_and_runs_test(auth_page: Page, base_url: str):
    _open_integrations_page(auth_page, base_url)
    tile = _find_tile(auth_page)
    tile.locator(".add-integration-btn").click()

    dialog = auth_page.locator('.integration-instance-modal')
    expect(dialog).to_be_visible(timeout=10000)

    server_url = os.environ.get("RF_SERVER_URL")
    if server_url:
        url_input = dialog.locator('[data-test-id="url"]')
        url_input.fill("")
        url_input.fill(server_url)

    dialog.locator('[data-test-id="password-input"]').fill(os.environ["RF_API_KEY"])

    dialog.locator(".test-btn").click()

    result = dialog.locator('.test-result-title').get_by_text("Success")
    expect(result).to_be_visible(timeout=30000)


def test_saves_new_instance(auth_page: Page, base_url: str):
    _open_integrations_page(auth_page, base_url)
    tile = _find_tile(auth_page)
    tile.locator(".add-integration-btn").click()

    dialog = auth_page.locator('.integration-instance-modal')
    expect(dialog).to_be_visible(timeout=10000)

    dialog.locator(
        'input[name="credentials_password"], input[placeholder*="API KEY"]'
    ).fill(os.environ["RF_API_KEY"])

    dialog.get_by_role("button", name=re.compile(r"save", re.IGNORECASE)).click()
    expect(dialog).not_to_be_visible(timeout=10000)
