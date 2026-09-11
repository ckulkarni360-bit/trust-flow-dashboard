"""
check_video.py

Utility script to verify HTTP status codes and content types for background
video sources from Wikimedia, CodePen, Pixabay, and Archive.org.
"""

import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

urls = [
    ("wikimedia_matrix", "https://upload.wikimedia.org/wikipedia/commons/transcoded/8/8c/Digital_rain_animation_medium_matrix.webm/Digital_rain_animation_medium_matrix.webm.480p.vp9.webm"),
    ("codepen_cyber", "https://assets.codepen.io/3364143/7btrrd.mp4"),
    ("pixabay_sample", "https://cdn.pixabay.com/video/2020/05/25/40149-425121408_large.mp4"),
    ("wikimedia_earth", "https://upload.wikimedia.org/wikipedia/commons/transcoded/4/4b/Rotating_earth_mesh_480p.webm/Rotating_earth_mesh_480p.webm.480p.vp9.webm"),
    ("archive_cyber", "https://ia800501.us.archive.org/24/items/CyberSecurityMotionGraphics/CyberSecurityMotionGraphics.mp4"),
]

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

for name, u in urls:
    try:
        req = urllib.request.Request(u, headers=headers)
        with urllib.request.urlopen(req, timeout=10, context=ctx) as res:
            ct = res.headers.get('content-type', '')
            cl = res.headers.get('content-length', 'unknown')
            print(f"SUCCESS: {name} -> {res.status} | {ct} | {cl} bytes")
    except Exception as e:
        print(f"FAIL: {name} -> {e}")
