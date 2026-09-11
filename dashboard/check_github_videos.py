"""
check_github_videos.py

Utility script to test accessibility and content headers of candidate
background video URLs hosted on GitHub and public CDNs.
"""

import urllib.request
import json
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Let's search GitHub code or repos or files for background cyber/security videos
# Common sample video CDNs or GitHub raw mp4 files
sample_candidates = [
    # Public domain cyber videos / Github repos
    "https://raw.githubusercontent.com/vedant-j/portfolio-assets/main/cyber.mp4",
    "https://raw.githubusercontent.com/bradtraversy/html_css_landing_page/master/video.mp4",
    "https://github.com/intel-iot-devkit/sample-videos/raw/master/face-demographics-walking.mp4",
    "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4",
    "https://static.videezy.com/system/resources/previews/000/043/101/original/C0025.mp4",
]

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

for url in sample_candidates:
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            print("OK:", url, r.headers.get('content-type'), r.headers.get('content-length'))
    except Exception as e:
        print("FAIL:", url, e)
