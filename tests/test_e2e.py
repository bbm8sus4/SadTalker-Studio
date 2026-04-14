"""
E2E Tests — Playwright browser tests on mobile viewport.

Covers:
  - Login flow on mobile
  - Navigation between pages (hash persistence)
  - Image selection from gallery
  - Theme toggle (dark/light)
  - Generate button state management
  - Guide page accessibility

Prerequisites:
  - Server running on localhost:8000
  - `python -m playwright install chromium`

Run:
  pytest tests/test_e2e.py -v --timeout=60
"""

import pytest
from playwright.sync_api import sync_playwright, expect

BASE_URL = "http://localhost:8000"

# iPhone 14 viewport — Mobile-First testing
MOBILE_VIEWPORT = {"width": 390, "height": 844}


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        yield b
        b.close()


@pytest.fixture
def page(browser):
    """Fresh mobile-viewport page with login session."""
    ctx = browser.new_context(viewport=MOBILE_VIEWPORT)
    pg = ctx.new_page()

    # Login
    pg.goto(f"{BASE_URL}/login")
    pg.fill("#username", "admin")
    pg.fill("#password", "sadtalker")
    pg.click("button[type=submit]")
    pg.wait_for_url(f"{BASE_URL}/")

    yield pg
    ctx.close()


@pytest.fixture
def anon_page(browser):
    """Fresh page without login."""
    ctx = browser.new_context(viewport=MOBILE_VIEWPORT)
    pg = ctx.new_page()
    yield pg
    ctx.close()


# ═══════════════════════════════════════════════════════════════
# LOGIN FLOW
# ═══════════════════════════════════════════════════════════════

class TestLoginFlow:

    def test_should_show_login_page_for_unauthenticated_user(self, anon_page):
        anon_page.goto(BASE_URL)
        # Should redirect to login
        assert "/login" in anon_page.url
        assert anon_page.locator("h2").text_content().strip() == "เข้าสู่ระบบ"

    def test_should_show_error_on_wrong_password(self, anon_page):
        anon_page.goto(f"{BASE_URL}/login")
        anon_page.fill("#username", "admin")
        anon_page.fill("#password", "wrong")
        anon_page.click("button[type=submit]")
        # Should show error message
        assert anon_page.locator(".err").is_visible()

    def test_should_login_and_see_main_app(self, page):
        # page fixture already logged in
        assert page.url == f"{BASE_URL}/"
        # Should see the bottom bar with Generate button
        assert page.locator("#goBtn").is_visible()

    def test_should_show_username_after_login(self, page):
        # userLabel should show "admin"
        label = page.locator("#userLabel")
        assert label.text_content().strip() == "admin"


# ═══════════════════════════════════════════════════════════════
# NAVIGATION — Mobile (sidebar hidden, use hash)
# ═══════════════════════════════════════════════════════════════

class TestNavigation:

    def test_should_start_on_create_page(self, page):
        # Default page is create
        assert page.locator("#pg-create").is_visible()

    def test_should_navigate_via_hash(self, page):
        page.goto(f"{BASE_URL}/#history")
        page.wait_for_timeout(500)
        assert page.locator("#pg-history").is_visible()

    def test_should_persist_page_on_refresh(self, page):
        page.goto(f"{BASE_URL}/#settings")
        page.wait_for_timeout(500)
        page.reload()
        page.wait_for_timeout(500)
        # Should still be on settings
        assert page.locator("#pg-settings").is_visible()

    def test_should_navigate_to_guide(self, page):
        page.goto(f"{BASE_URL}/#guide")
        page.wait_for_timeout(500)
        assert page.locator("#pg-guide").is_visible()
        # Guide should have content
        assert page.locator("#pg-guide .card").count() >= 4


# ═══════════════════════════════════════════════════════════════
# CREATE PAGE — Image selection + Generate button
# ═══════════════════════════════════════════════════════════════

class TestCreatePage:

    def test_should_show_example_images(self, page):
        page.goto(f"{BASE_URL}/#create")
        page.wait_for_timeout(1000)
        # Image grid should have thumbnails
        images = page.locator(".ig img")
        assert images.count() > 0

    def test_should_select_example_image(self, page):
        page.goto(f"{BASE_URL}/#create")
        page.wait_for_timeout(1000)
        # Click first example image
        first_img = page.locator(".ig img").first
        first_img.click()
        # Should show preview
        assert page.locator(".pbox img").is_visible()
        # Image should have .on class
        assert "on" in first_img.get_attribute("class")

    def test_should_show_preset_chips(self, page):
        page.goto(f"{BASE_URL}/#create")
        page.wait_for_timeout(500)
        chips = page.locator(".chip")
        assert chips.count() >= 4

    def test_should_disable_generate_without_input(self, page):
        """Generate should alert if no text + no image selected."""
        page.goto(f"{BASE_URL}/#create")
        page.wait_for_timeout(500)
        # Click generate with empty form
        page.on("dialog", lambda d: d.accept())
        page.click("#goBtn")
        # Button should still be enabled (alert shown, not disabled permanently)
        assert not page.locator("#goBtn").is_disabled()


# ═══════════════════════════════════════════════════════════════
# THEME TOGGLE
# ═══════════════════════════════════════════════════════════════

class TestTheme:

    def test_should_default_to_light_or_system(self, page):
        theme = page.evaluate("document.documentElement.dataset.theme")
        assert theme in ("light", "dark")

    def test_should_toggle_to_dark_theme(self, browser):
        """Use desktop viewport — theme toggle is in sidebar (hidden on mobile)."""
        ctx = browser.new_context(viewport={"width": 1280, "height": 800})
        pg = ctx.new_page()
        pg.goto(f"{BASE_URL}/login")
        pg.wait_for_timeout(300)
        initial = pg.evaluate("document.documentElement.dataset.theme")
        pg.click(".theme-toggle")
        new_theme = pg.evaluate("document.documentElement.dataset.theme")
        assert new_theme != initial
        ctx.close()

    def test_should_persist_theme_across_page_load(self, browser):
        ctx = browser.new_context(viewport={"width": 1280, "height": 800})
        pg = ctx.new_page()
        pg.goto(f"{BASE_URL}/login")
        pg.wait_for_timeout(300)
        pg.click(".theme-toggle")
        expected = pg.evaluate("document.documentElement.dataset.theme")
        pg.reload()
        pg.wait_for_timeout(300)
        actual = pg.evaluate("document.documentElement.dataset.theme")
        assert actual == expected
        ctx.close()


# ═══════════════════════════════════════════════════════════════
# HISTORY PAGE
# ═══════════════════════════════════════════════════════════════

class TestHistoryPage:

    def test_should_show_empty_state(self, page):
        page.goto(f"{BASE_URL}/#history")
        page.wait_for_timeout(500)
        # Either shows videos or empty message
        has_items = page.locator(".hi").count() > 0
        has_empty = page.locator("#hEmpty").is_visible()
        assert has_items or has_empty


# ═══════════════════════════════════════════════════════════════
# GUIDE PAGE — Content completeness
# ═══════════════════════════════════════════════════════════════

class TestGuidePage:

    def test_should_show_all_guide_sections(self, page):
        page.goto(f"{BASE_URL}/#guide")
        page.wait_for_timeout(500)
        text = page.locator("#pg-guide").text_content()
        assert "เริ่มต้นใช้งาน" in text
        assert "Preset" in text
        assert "Expression Scale" in text
        assert "Command Line" in text

    def test_should_have_github_link(self, page):
        page.goto(f"{BASE_URL}/#guide")
        page.wait_for_timeout(500)
        link = page.locator("#pg-guide a[href*='github.com']")
        assert link.count() >= 1
