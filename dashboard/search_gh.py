"""
search_gh.py

Searches GitHub repository git trees via GitHub REST API for candidate video
and animation assets (.mp4, .webm, .gif).
"""

import urllib.request
import json
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
}

repos = [
    "muki01/Cyber_Security_Website_Template",
    "RyuzakiRyuga/rebeta"
]

for r in repos:
    try:
        url = f"https://api.github.com/repos/{r}/git/trees/main?recursive=1"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            for f in data.get('tree', []):
                p = f.get('path', '')
                if any(p.lower().endswith(ext) for ext in ['.mp4', '.webm', '.gif']):
                    print(f"FOUND IN {r}: {p}")
    except Exception as e:
        print(f"Error {r}: {e}")
