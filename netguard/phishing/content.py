import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# List of popular brands targets for phishing
BRAND_KEYWORDS = ["paypal", "google", "netflix", "amazon", "apple", "facebook", "microsoft", "steam", "chase", "bank"]

# Official domains for brands to detect domain spoofing
OFFICIAL_DOMAINS = {
    "paypal": ["paypal.com", "paypal.co.uk"],
    "google": ["google.com", "google.co.in", "google.co.uk", "google.ca"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.in"],
    "apple": ["apple.com"],
    "facebook": ["facebook.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "chase": ["chase.com"]
}

def analyze_content(html: str, current_url: str) -> dict:
    """
    Parse page content using BeautifulSoup to extract indicators of phishing.
    
    Returns:
        dict: {
            "has_password_field": bool,
            "off_domain_forms_count": int,
            "brand_mismatch": bool,
            "obfuscated_js_detected": bool,
            "off_domain_favicon": bool
        }
    """
    result = {
        "has_password_field": False,
        "off_domain_forms_count": 0,
        "brand_mismatch": False,
        "obfuscated_js_detected": False,
        "off_domain_favicon": False
    }
    
    if not html:
        return result
        
    soup = BeautifulSoup(html, "html.parser")
    parsed_url = urlparse(current_url)
    current_domain = parsed_url.hostname or ""
    if current_domain.startswith("www."):
        current_domain = current_domain[4:]
        
    # 1. Password field check
    password_inputs = soup.find_all("input", type="password")
    if password_inputs:
        result["has_password_field"] = True
        
    # 2. Form action checks (off-domain submissions)
    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action")
        if action:
            action_url = urlparse(action)
            action_domain = action_url.hostname
            
            if action_domain:
                if action_domain.startswith("www."):
                    action_domain = action_domain[4:]
                if action_domain != current_domain:
                    result["off_domain_forms_count"] += 1
                    
    # 3. Brand mismatch check
    # Check text content of the page for brand keywords
    page_text = soup.get_text().lower()
    detected_brands = [brand for brand in BRAND_KEYWORDS if brand in page_text]
    
    # Check URL path / queries for brand names
    url_contains_brand = any(brand in current_url.lower() for brand in BRAND_KEYWORDS)
    
    # If a brand is mentioned or in the URL, verify if it's the official domain
    if detected_brands or url_contains_brand:
        all_brands = set(detected_brands)
        for b in BRAND_KEYWORDS:
            if b in current_url.lower():
                all_brands.add(b)
                
        for brand in all_brands:
            # If the brand name is present in the domain name (e.g. "paypal-login.com")
            # we must verify it is the official domain of that brand.
            if brand in current_domain.lower():
                officials = OFFICIAL_DOMAINS.get(brand, [])
                is_official = False
                for official in officials:
                    if current_domain == official or current_domain.endswith("." + official):
                        is_official = True
                        break
                if not is_official:
                    result["brand_mismatch"] = True
                    break
            else:
                # If brand is in page text, but domain name doesn't even mention the brand (e.g. mentions Paypal but domain is secure-xyz.com)
                # and the brand has official domains, it's a mismatch
                if brand in OFFICIAL_DOMAINS:
                    result["brand_mismatch"] = True
                    break

                
    # 4. Favicon off-domain check
    icon_links = soup.find_all("link", rel=lambda x: x and any(rel in x.lower() for rel in ["icon", "shortcut"]))
    for link in icon_links:
        href = link.get("href")
        if href:
            href_url = urlparse(href)
            href_domain = href_url.hostname
            if href_domain:
                if href_domain.startswith("www."):
                    href_domain = href_domain[4:]
                if href_domain != current_domain:
                    result["off_domain_favicon"] = True
                    break
                    
    # 5. Obfuscated Inline Javascript
    scripts = soup.find_all("script")
    for script in scripts:
        content = script.string
        if content and len(content) > 100:
            # Check density of non-alphanumeric chars (often high in obfuscated payloads)
            total_chars = len(content)
            non_alphanumeric = len(re.findall(r"[^a-zA-Z0-9\s]", content))
            ratio = non_alphanumeric / total_chars
            
            # Check for suspicious functions
            has_obfuscation_funcs = any(f in content for f in ["eval(", "unescape(", "atob(", "btoa("])
            
            if ratio > 0.4 or (ratio > 0.25 and has_obfuscation_funcs):
                result["obfuscated_js_detected"] = True
                break
                
    return result
