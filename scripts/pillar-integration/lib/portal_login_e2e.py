#!/usr/bin/env python3
"""portal_login_e2e.py — drive the Yew/HTML portal LOGIN end to end through a
REAL headless browser (Chromium via Selenium WebDriver), against a REAL
running pillar node's web surface.

This is the browser-automation half of the pillar-integration
`portal-cli-parity` scenario: unlike the raw HTTP `driver_http_post` login the
other scenarios use, this loads the actual portal HTML (`GET /`), types the
identifier + password into the real `#identifier` / `#password` form fields,
submits the form, and asserts the browser transitions into the authenticated
portal view (`#portal` becomes visible) — proving the SAME login a human
operator performs in a real browser works end to end, driven by a real
`navigator`/DOM automation engine, not a hand-crafted request.

Exit 0 = the browser reached the authenticated portal view; non-zero (with a
diagnostic on stderr) = it did not. Usage:

    portal_login_e2e.py <base-url> <identifier> <password>

e.g. portal_login_e2e.py http://127.0.0.1:8642 alice 'alice-pass-1!'
"""

import sys
import time

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
except Exception as e:  # pragma: no cover - import guard
    sys.stderr.write("portal-login-e2e: selenium unavailable: %s\n" % e)
    sys.exit(3)


def _chromedriver_service():
    # Prefer an explicit chromedriver on PATH (the CI sandbox installs
    # /usr/bin/chromedriver); fall back to Selenium Manager if absent.
    import shutil

    path = shutil.which("chromedriver")
    return Service(executable_path=path) if path else Service()


def main():
    if len(sys.argv) != 4:
        sys.stderr.write(
            "usage: portal_login_e2e.py <base-url> <identifier> <password>\n"
        )
        return 2
    base_url, identifier, password = sys.argv[1], sys.argv[2], sys.argv[3]

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")

    import shutil

    for cand in ("chromium", "chromium-browser", "google-chrome", "chrome"):
        p = shutil.which(cand)
        if p:
            opts.binary_location = p
            break

    driver = None
    try:
        driver = webdriver.Chrome(service=_chromedriver_service(), options=opts)
        driver.set_page_load_timeout(30)
        driver.get(base_url + "/")

        wait = WebDriverWait(driver, 20)
        # The real login form fields the portal HTML renders.
        ident_el = wait.until(
            EC.presence_of_element_located((By.ID, "identifier"))
        )
        pass_el = driver.find_element(By.ID, "password")
        ident_el.clear()
        ident_el.send_keys(identifier)
        pass_el.clear()
        pass_el.send_keys(password)

        submit = driver.find_element(By.ID, "submit")
        submit.click()

        # On success the portal SPA reveals the authenticated view: the
        # #portal <section> loses its `hidden` class and becomes displayed.
        portal = wait.until(EC.presence_of_element_located((By.ID, "portal")))
        deadline = time.time() + 20
        while time.time() < deadline:
            classes = portal.get_attribute("class") or ""
            if "hidden" not in classes and portal.is_displayed():
                print(
                    "oracle-observed: portal-login-e2e user=%s reached the "
                    "authenticated portal view (real headless-Chromium DOM "
                    "transition)" % identifier
                )
                return 0
            time.sleep(0.5)

        # Surface whatever the portal told the user, for diagnostics.
        try:
            msg = driver.find_element(By.ID, "msg").text
        except Exception:
            msg = "(no #msg)"
        sys.stderr.write(
            "portal-login-e2e: #portal never became visible after login "
            "(login message: %s)\n" % msg
        )
        return 1
    except Exception as e:
        sys.stderr.write("portal-login-e2e: browser automation failed: %s\n" % e)
        return 1
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
