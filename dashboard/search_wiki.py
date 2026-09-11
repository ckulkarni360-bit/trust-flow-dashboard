"""
search_wiki.py

Queries the Wikimedia Commons MediaWiki API to find video files matching
cybersecurity and matrix rain search queries.
"""

import urllib.request
import json
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

api_url = "https://commons.wikimedia.org/w/api.php?action=query&format=json&generator=search&gsrnamespace=6&gsrsearch=matrix%20rain%20filetype:video&gsrlimit=10&prop=imageinfo&iiprop=url|mime|size"

headers = {
    'User-Agent': 'TrustFL-App/1.0 (academic research test; mailto:admin@trustfl.org)'
}

try:
    req = urllib.request.Request(api_url, headers=headers)
    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        pages = data.get('query', {}).get('pages', {})
        for pid, pinfo in pages.items():
            title = pinfo.get('title')
            ii = pinfo.get('imageinfo', [{}])[0]
            print(title)
            print("  URL:", ii.get('url'))
            print("  MIME:", ii.get('mime'))
            print("  SIZE:", ii.get('size'))
except Exception as e:
    print("Error:", e)
