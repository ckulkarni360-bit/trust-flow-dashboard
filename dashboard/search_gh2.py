"""
search_gh2.py

Searches GitHub repositories for cybersecurity video keywords and inspects
git trees for MP4 video assets.
"""

import urllib.request
import json
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

headers = {'User-Agent': 'Mozilla/5.0'}

queries = [
    "cyber+security+video+mp4",
    "cybersecurity+landing+page+mp4",
    "matrix+rain+mp4",
    "cyber+network+video"
]

for q in queries:
    url = f"https://api.github.com/search/repositories?q={q}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            for item in data.get('items', [])[:4]:
                repo = item.get('full_name')
                branch = item.get('default_branch', 'main')
                tree_url = f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
                try:
                    treq = urllib.request.Request(tree_url, headers=headers)
                    with urllib.request.urlopen(treq, timeout=5, context=ctx) as tresp:
                        tdata = json.loads(tresp.read().decode('utf-8'))
                        for f in tdata.get('tree', []):
                            p = f.get('path', '')
                            if p.lower().endswith('.mp4'):
                                print(f"MATCH: {repo}/{branch}/{p} ({f.get('size')} bytes)")
                except Exception:
                    pass
    except Exception as e:
        print("Search error:", e)
