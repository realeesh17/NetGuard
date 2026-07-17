import requests

def fetch_url(url: str, timeout: float = 5.0) -> dict:
    """
    Perform a GET request to the URL, tracking redirects and returning page content.
    
    Returns:
        dict: {
            "html": str,
            "status_code": int,
            "redirect_chain": list[str],
            "error": str | None
        }
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    try:
        # User-agent header to mimic a standard browser request
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        
        # Build redirect chain including the final landing page
        redirect_chain = [r.url for r in response.history]
        redirect_chain.append(response.url)
        
        return {
            "html": response.text,
            "status_code": response.status_code,
            "redirect_chain": redirect_chain,
            "error": None
        }
    except requests.exceptions.RequestException as e:
        return {
            "html": "",
            "status_code": 0,
            "redirect_chain": [],
            "error": str(e)
        }
