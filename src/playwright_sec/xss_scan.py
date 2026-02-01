from playwright.sync_api import sync_playwright

def test_xss_vulnerability(url, payload):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url)
        
        # Próba wstrzyknięcia w pole wyszukiwania
        page.fill('input[name="search"]', payload)
        page.click('button[type="submit"]')
        
        # Sprawdzenie czy wyzwolono alert (klasyczny dowód XSS)
        page.on("dialog", lambda dialog: print(f"XSS Triggered: {dialog.message}"))
        browser.close()