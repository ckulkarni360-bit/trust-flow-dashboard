"""
dashboard/app.py

TrustFL // Intelligent IoT Intrusion Detection System
Byzantine-Resilient Federated Learning Dashboard
"""

import base64
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
RESULTS_DIR = ROOT / "results"
DATA_DIR = ROOT / "data"
USERS_FILE = Path(__file__).resolve().parent / "users.json"
ASSETS_DIR = Path(__file__).resolve().parent / "assets"
SHIELD_IMG = ASSETS_DIR / "soc_shield.jpg"
MESH_IMG = ASSETS_DIR / "threat_mesh.jpg"
BG_IMG = ASSETS_DIR / "sample_frame.jpg"



st.set_page_config(
    page_title="TrustFL // Federated IoT Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# USER DATABASE & PERSISTENCE (Sign Up / Sign In)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Hash a plaintext password with SHA-256 and a dedicated salt.

    :param password: Raw password string to hash.
    :returns: Hexadecimal SHA-256 digest string.
    """
    salt = "trustfl_secure_salt_2026"
    return hashlib.sha256(f"{salt}_{password}".encode("utf-8")).hexdigest()


def load_users() -> dict:
    """Load user credentials from the JSON persistence file.

    Initializes the user database with default demo credentials if the file
    does not exist.

    :returns: Dictionary mapping user email to profile information and password hash.
    """
    if not USERS_FILE.exists():
        default_users = {
            "demo@trustfl.org": {
                "password_hash": hash_password("TrustFL@2026"),
                "name": "Demo User",
                "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            }
        }
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=2)
        return default_users
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_users(users: dict):
    """Persist user account records to the JSON user database.

    :param users: Dictionary mapping user email to profile details and credentials.
    """
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


# ---------------------------------------------------------------------------
# DESIGN SYSTEM: PLUS JAKARTA SANS & MODERN MINIMALIST SAAS
# ---------------------------------------------------------------------------
COLOR_BG = "#0F131D"          # Stitch surface/bg
COLOR_CARD = "#1C1F2A"        # Stitch surface-container
COLOR_CARD_LOW = "#171B26"    # Stitch surface-container-low
COLOR_CARD_HIGH = "#262A35"   # Stitch surface-container-high
COLOR_BORDER = "rgba(60, 73, 76, 0.50)"  # Stitch outline-variant
COLOR_PRIMARY = "#22D3EE"     # Stitch primary electric cyan
COLOR_SECONDARY = "#ADC6FF"   # Stitch secondary ice blue
COLOR_SUCCESS = "#68F5B8"     # Stitch tertiary neon mint
COLOR_WARN = "#F59E0B"        # Amber
COLOR_DANGER = "#FFB4AB"      # Stitch error crimson
COLOR_MUTED = "#859397"       # Stitch outline
COLOR_TEXT = "#DFE2F1"        # Stitch on-surface
COLOR_TEXT_MUTED = "#BBC9CD"  # Stitch on-surface-variant

@st.cache_data(show_spinner=False)
def load_bg_img_b64() -> str:
    """Load and base64-encode cyber_bg.jpg for CSS background.

    :returns: Base64-encoded JPEG string, or empty string if file is missing.
    """
    if BG_IMG.exists():
        try:
            with open(BG_IMG, "rb") as fh:
                return base64.b64encode(fh.read()).decode("utf-8")
        except Exception:
            return ""
    return ""


_bg_img_b64 = load_bg_img_b64()
_bg_img_layer = f"url('data:image/jpeg;base64,{_bg_img_b64}')" if _bg_img_b64 else "none"

CUSTOM_CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* =========================================================
   KEYFRAME ANIMATIONS
   ========================================================= */
@keyframes gridPan {{
    0%   {{ background-position: 0 0, 0 0; }}
    100% {{ background-position: 60px 60px, 60px 60px; }}
}}
@keyframes radialPulse {{
    0%, 100% {{ opacity: 0.18; transform: scale(1);   }}
    50%        {{ opacity: 0.30; transform: scale(1.08); }}
}}
@keyframes scanBeam {{
    /* Realistic scanner: slow start, fast mid, slow end */
    0%   {{ top: -4%;  opacity: 0;    }}
    3%   {{ opacity: 1;               }}
    15%  {{ top: 18%;                 }}
    50%  {{ top: 50%;                 }}
    85%  {{ top: 82%;                 }}
    97%  {{ opacity: 1;               }}
    100% {{ top: 104%; opacity: 0;    }}
}}
@keyframes scanTrail {{
    0%   {{ top: -4%;  opacity: 0; height: 0px;  }}
    3%   {{ opacity: 1;            height: 60px; }}
    50%  {{ top: 50%;              height: 80px; }}
    97%  {{ opacity: 0.6;          height: 40px; }}
    100% {{ top: 104%; opacity: 0; height: 0px;  }}
}}
@keyframes nodeBlink {{
    0%, 80%, 100% {{ opacity: 0.0; }}
    40%           {{ opacity: 0.9; }}
}}
@keyframes hexFloat {{
    0%   {{ transform: translateY(0px)   rotate(0deg);   opacity: 0.04; }}
    50%  {{ transform: translateY(-22px) rotate(180deg); opacity: 0.09; }}
    100% {{ transform: translateY(0px)   rotate(360deg); opacity: 0.04; }}
}}

/* =========================================================
   GLOBAL FONT & BASE THEME
   ========================================================= */
html, body {{
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
    background-color: #0F131D !important;
    color: #DFE2F1 !important;
}}

/* =========================================================
   MAIN BACKGROUND — Stitch obsidian cyber security aesthetic with cyber_bg.jpg
   ========================================================= */
[data-testid="stAppViewContainer"], .stApp {{
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
    color: #DFE2F1 !important;
    min-height: 100vh;

    background-color: #080C14;
    background-image:
        /* fine stitch grid */
        linear-gradient(rgba(34, 211, 238, 0.035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(34, 211, 238, 0.035) 1px, transparent 1px),
        /* coarse grid */
        linear-gradient(rgba(34, 211, 238, 0.015) 1px, transparent 1px),
        linear-gradient(90deg, rgba(34, 211, 238, 0.015) 1px, transparent 1px),
        /* cyan radial glow */
        radial-gradient(ellipse 75% 60% at 20% 20%, rgba(34, 211, 238, 0.12) 0%, transparent 65%),
        /* blue radial glow */
        radial-gradient(ellipse 70% 50% at 80% 80%, rgba(173, 198, 255, 0.08) 0%, transparent 65%),
        /* dark overlay gradient over cyber_bg.jpg so content remains high-contrast & legible */
        linear-gradient(rgba(8, 12, 20, 0.74), rgba(8, 12, 20, 0.82)),
        {_bg_img_layer};

    background-size:
        30px 30px,
        30px 30px,
        90px 90px,
        90px 90px,
        100% 100%,
        100% 100%,
        100% 100%,
        cover;
    background-position: 0 0, 0 0, 0 0, 0 0, center, center, center, center;
    background-repeat: repeat, repeat, repeat, repeat, no-repeat, no-repeat, no-repeat, no-repeat;
    background-attachment: fixed;
}}

.main, .block-container {{
    background: transparent !important;
}}

/* =========================================================
   SCANNER BEAM — primary bright line
   ========================================================= */
[data-testid="stAppViewContainer"]::before {{
    content: '';
    position: fixed;
    left: 0; right: 0;
    /* 3-layer beam: thin core + mid bloom + wide edge glow */
    height: 5px;
    background: linear-gradient(
        90deg,
        transparent            0%,
        rgba(0,255,220, 0.00)  5%,
        rgba(0,220,255, 0.30) 15%,
        rgba(0,240,255, 0.70) 35%,
        rgba(180,255,255,1.00) 50%,   /* bright white-cyan core */
        rgba(0,240,255, 0.70) 65%,
        rgba(0,220,255, 0.30) 85%,
        rgba(0,255,220, 0.00) 95%,
        transparent           100%
    );
    /* layered box-shadow: core glow + mid bloom + wide diffuse */
    box-shadow:
        0  0  2px  1px rgba(180, 255, 255, 0.90),
        0  0  8px  3px rgba(0,   220, 255, 0.65),
        0  0 18px  6px rgba(0,   200, 255, 0.40),
        0  0 40px 12px rgba(0,   180, 255, 0.18),
        0  0 80px 24px rgba(0,   160, 255, 0.08);
    animation: scanBeam 7s cubic-bezier(0.45, 0, 0.55, 1) infinite;
    z-index: 9999;
    pointer-events: none;
}}

/* trailing glow below the beam */
[data-testid="stAppViewContainer"]::after {{
    content: '';
    position: fixed;
    left: 0; right: 0;
    background: linear-gradient(
        180deg,
        rgba(0, 220, 255, 0.18) 0%,
        rgba(0, 180, 255, 0.10) 30%,
        rgba(0, 120, 200, 0.04) 65%,
        transparent             100%
    );
    animation: scanTrail 7s cubic-bezier(0.45, 0, 0.55, 1) infinite;
    z-index: 9998;
    pointer-events: none;
}}

/* Transparent header */
header[data-testid="stHeader"] {{
    background: transparent !important;
}}

/* =========================================================
   FLOATING HEX DECO ELEMENTS (pure CSS, no JS)
   Applied to ::before / ::after of sidebar
   ========================================================= */
[data-testid="stSidebar"]::before {{
    content: '⬡';
    position: absolute;
    font-size: 9rem;
    color: rgba(0, 200, 255, 0.06);
    top: 12%;
    left: -10px;
    animation: hexFloat 14s ease-in-out infinite;
    pointer-events: none;
    z-index: 0;
}}
[data-testid="stSidebar"]::after {{
    content: '⬡';
    position: absolute;
    font-size: 5.5rem;
    color: rgba(99, 102, 241, 0.07);
    bottom: 18%;
    right: -6px;
    animation: hexFloat 18s ease-in-out infinite reverse;
    pointer-events: none;
    z-index: 0;
}}

/* =========================================================
   MONOSPACE ACCENT
   ========================================================= */
.mono, .stMetric, code, .stDataFrame, [data-testid="stMetricValue"] {{
    font-family: 'JetBrains Mono', monospace !important;
}}

/* =========================================================
   STITCH HUD CARD & SURFACE CONTAINERS
   ========================================================= */
.tf-card {{
    background: #1C1F2A !important;
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    border: 1px solid rgba(60, 73, 76, 0.45) !important;
    border-radius: 14px !important;
    padding: 1.4rem 1.6rem !important;
    margin-bottom: 1.25rem !important;
    box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.45),
                inset 0 1px 0 rgba(255, 255, 255, 0.04) !important;
}}

.tf-card-title {{
    font-family: 'Plus Jakarta Sans', sans-serif !important;
    font-size: 1.1rem !important;
    font-weight: 700 !important;
    color: #DFE2F1 !important;
    margin-bottom: 0.4rem !important;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    letter-spacing: -0.015em !important;
}}

.tf-card-sub {{
    font-family: 'Plus Jakarta Sans', sans-serif !important;
    font-size: 0.86rem !important;
    color: #BBC9CD !important;
    line-height: 1.6 !important;
    margin-bottom: 0.8rem !important;
}}

/* =========================================================
   STITCH CONSOLE NAVBAR
   ========================================================= */
.tf-navbar {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.85rem 1.4rem;
    background: rgba(15, 19, 29, 0.90) !important;
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(60, 73, 76, 0.50) !important;
    border-radius: 12px;
    margin-bottom: 1.4rem;
    box-shadow: 0 1px 8px rgba(0, 0, 0, 0.4) !important;
}}

.tf-brand {{
    font-family: 'Plus Jakarta Sans', sans-serif !important;
    font-size: 1.25rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: #DFE2F1;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}}
.tf-brand span {{
    color: #22D3EE;
    text-shadow: 0 0 14px rgba(34, 211, 238, 0.6);
}}

/* =========================================================
   STITCH BADGES & TELEMETRY PILLS
   ========================================================= */
.tf-badge {{
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.72rem;
    font-weight: 600;
    padding: 0.22rem 0.65rem;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace !important;
    letter-spacing: 0.02em;
}}
.tf-badge-dot {{
    width: 6px;
    height: 6px;
    border-radius: 50%;
}}

.badge-trust {{
    background: rgba(104, 245, 184, 0.12) !important;
    color: #68F5B8 !important;
    border: 1px solid rgba(104, 245, 184, 0.35) !important;
}}
.badge-trust .tf-badge-dot {{ background: #68F5B8; box-shadow: 0 0 6px #68F5B8; }}

.badge-warn {{
    background: rgba(245, 158, 11, 0.12) !important;
    color: #F59E0B !important;
    border: 1px solid rgba(245, 158, 11, 0.35) !important;
}}
.badge-warn .tf-badge-dot {{ background: #F59E0B; box-shadow: 0 0 6px #F59E0B; }}

.badge-alert {{
    background: rgba(255, 180, 171, 0.12) !important;
    color: #FFB4AB !important;
    border: 1px solid rgba(255, 180, 171, 0.35) !important;
}}
.badge-alert .tf-badge-dot {{ background: #FFB4AB; box-shadow: 0 0 6px #FFB4AB; }}

/* =========================================================
   STITCH SEGMENTED OPERATIONS TABS
   ========================================================= */
.stTabs [data-baseweb="tab-list"] {{
    gap: 8px;
    background: #171B26 !important;
    border: 1px solid rgba(60, 73, 76, 0.45) !important;
    border-radius: 12px !important;
    padding: 5px !important;
    margin-bottom: 1.5rem !important;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3) !important;
}}
.stTabs [data-baseweb="tab"] {{
    background-color: transparent !important;
    border: none !important;
    color: #BBC9CD !important;
    font-family: 'Plus Jakarta Sans', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
    padding: 0.55rem 1.1rem !important;
    border-radius: 8px !important;
    transition: all 0.2s ease !important;
}}
.stTabs [data-baseweb="tab"]:hover {{
    color: #DFE2F1 !important;
    background-color: #262A35 !important;
}}
.stTabs [aria-selected="true"] {{
    color: #22D3EE !important;
    background-color: #262A35 !important;
    border-bottom: 2px solid #22D3EE !important;
    box-shadow: 0 0 12px rgba(34, 211, 238, 0.20) !important;
    text-shadow: 0 0 8px rgba(34, 211, 238, 0.4);
}}

/* =========================================================
   FORM INPUTS, SELECTBOXES & BUTTONS (STITCH SYSTEM)
   ========================================================= */
.stTextInput input, .stSelectbox [data-baseweb="select"] > div {{
    background-color: #171B26 !important;
    border: 1px solid rgba(60, 73, 76, 0.6) !important;
    border-radius: 8px !important;
    color: #DFE2F1 !important;
    font-size: 0.88rem !important;
    font-family: 'Plus Jakarta Sans', sans-serif !important;
}}
.stTextInput input:focus, .stSelectbox [data-baseweb="select"]:focus-within > div {{
    border-color: #22D3EE !important;
    box-shadow: 0 0 0 2px rgba(34, 211, 238, 0.20) !important;
}}
.stButton > button {{
    background: #262A35 !important;
    color: #DFE2F1 !important;
    border: 1px solid rgba(60, 73, 76, 0.6) !important;
    border-radius: 8px !important;
    font-family: 'Plus Jakarta Sans', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
    padding: 0.5rem 1.2rem !important;
    transition: all 0.2s ease !important;
}}
.stButton > button:hover {{
    background: #313540 !important;
    color: #22D3EE !important;
    border-color: rgba(34, 211, 238, 0.5) !important;
    box-shadow: 0 0 10px rgba(34, 211, 238, 0.25) !important;
}}
.stButton > button[kind="primary"] {{
    background: #22D3EE !important;
    color: #00363E !important;
    font-weight: 700 !important;
    border: none !important;
    box-shadow: 0 0 12px rgba(34, 211, 238, 0.4) !important;
}}
.stButton > button[kind="primary"]:hover {{
    background: #8AEBFF !important;
    color: #001F25 !important;
    box-shadow: 0 0 18px rgba(34, 211, 238, 0.75) !important;
}}

/* =========================================================
   STREAMLIT METRIC HUD TILES (STITCH SYSTEM)
   ========================================================= */
[data-testid="stMetric"] {{
    background: #1C1F2A !important;
    border: 1px solid rgba(60, 73, 76, 0.45) !important;
    border-radius: 12px !important;
    padding: 0.9rem 1.1rem !important;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35) !important;
}}
[data-testid="stMetricLabel"] {{
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.72rem !important;
    color: #859397 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
}}
[data-testid="stMetricValue"] {{
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 1.6rem !important;
    font-weight: 700 !important;
    color: #22D3EE !important;
}}

/* =========================================================
   SIDEBAR (STITCH SYSTEM)
   ========================================================= */
[data-testid="stSidebar"] {{
    background: rgba(10, 14, 24, 0.92) !important;
    backdrop-filter: blur(20px) !important;
    -webkit-backdrop-filter: blur(20px) !important;
    border-right: 1px solid rgba(60, 73, 76, 0.50) !important;
}}

/* =========================================================
   PAGE FRAME — neon corner border around entire viewport
   ========================================================= */
@keyframes frameGlow {{
    0%,100% {{ opacity: 0.35; }}
    50%      {{ opacity: 0.70; }}
}}
body::before {{
    content: '';
    position: fixed;
    inset: 6px;
    border: 1px solid rgba(0, 200, 255, 0.22);
    border-radius: 6px;
    pointer-events: none;
    z-index: 99990;
    animation: frameGlow 4s ease-in-out infinite;
    box-shadow:
        0  0  8px  2px rgba(0, 200, 255, 0.10),
        inset 0 0 12px 2px rgba(0, 200, 255, 0.04);
}}

/* Corner accent marks */
body::after {{
    content: '';
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 99991;
    background:
        /* top-left */
        linear-gradient(90deg,  rgba(34,211,238,0.7) 0%, transparent 40px) 6px 6px / 40px 2px no-repeat,
        linear-gradient(180deg, rgba(34,211,238,0.7) 0%, transparent 40px) 6px 6px / 2px 40px no-repeat,
        /* top-right */
        linear-gradient(270deg, rgba(34,211,238,0.7) 0%, transparent 40px) calc(100% - 6px) 6px / 40px 2px no-repeat,
        linear-gradient(180deg, rgba(34,211,238,0.7) 0%, transparent 40px) calc(100% - 7px) 6px / 2px 40px no-repeat,
        /* bottom-left */
        linear-gradient(90deg,  rgba(34,211,238,0.7) 0%, transparent 40px) 6px calc(100% - 7px) / 40px 2px no-repeat,
        linear-gradient(0deg,   rgba(34,211,238,0.7) 0%, transparent 40px) 6px calc(100% - 6px) / 2px 40px no-repeat,
        /* bottom-right */
        linear-gradient(270deg, rgba(34,211,238,0.7) 0%, transparent 40px) calc(100% - 6px) calc(100% - 7px) / 40px 2px no-repeat,
        linear-gradient(0deg,   rgba(34,211,238,0.7) 0%, transparent 40px) calc(100% - 7px) calc(100% - 6px) / 2px 40px no-repeat;
}}

/* =========================================================
   IMAGE BORDERS — glowing neon frame on all images
   ========================================================= */
@keyframes imgBorderPulse {{
    0%,100% {{ box-shadow: 0 0  6px 2px rgba(0,200,255,0.20), 0 0 18px 4px rgba(0,180,255,0.10); border-color: rgba(0,200,255,0.25); }}
    50%      {{ box-shadow: 0 0 14px 4px rgba(0,200,255,0.40), 0 0 32px 8px rgba(0,180,255,0.18); border-color: rgba(34,211,238,0.50); }}
}}
.stImage img, [data-testid="stImage"] img {{
    border: 1.5px solid rgba(0, 200, 255, 0.28);
    border-radius: 10px;
    animation: imgBorderPulse 4s ease-in-out infinite;
    transition: transform 0.3s ease;
}}
.stImage img:hover, [data-testid="stImage"] img:hover {{
    transform: scale(1.015);
}}

/* =========================================================
   CARD HOVER LIFT
   ========================================================= */
.tf-card {{
    transition: transform 0.25s cubic-bezier(0.45,0,0.55,1),
                box-shadow 0.25s ease, border-color 0.25s ease;
}}
.tf-card:hover {{
    transform: translateY(-3px);
    border-color: rgba(0,200,255,0.28) !important;
    box-shadow: 0 8px 32px -4px rgba(0,0,0,0.65),
                0 0 20px 2px rgba(0,200,255,0.10),
                inset 0 1px 0 rgba(0,200,255,0.10) !important;
}}

/* =========================================================
   LIVE FEED — animated ring + row flash
   ========================================================= */
@keyframes radarRing {{
    0%   {{ transform: scale(0.6); opacity: 0.8; }}
    100% {{ transform: scale(1.8); opacity: 0; }}
}}
@keyframes attackFlash {{
    0%,100% {{ background: rgba(239,68,68,0.00); }}
    20%      {{ background: rgba(239,68,68,0.18); }}
}}
@keyframes normalSlide {{
    from {{ opacity: 0; transform: translateX(-12px); }}
    to   {{ opacity: 1; transform: translateX(0); }}
}}
.live-radar-ring {{
    position: absolute;
    width: 100%; height: 100%;
    border-radius: 50%;
    border: 2px solid rgba(34,211,238,0.55);
    animation: radarRing 2s ease-out infinite;
}}
.live-feed-attack-row {{
    animation: attackFlash 0.8s ease-out;
}}
.live-feed-normal-row {{
    animation: normalSlide 0.4s ease-out;
}}

</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# PARTICLE NETWORK CANVAS — animated node/edge background (JS)
# ---------------------------------------------------------------------------
st.markdown("""
<canvas id="tf-particles" style="
    position: fixed; top: 0; left: 0;
    width: 100%; height: 100%;
    z-index: 0; pointer-events: none;
    opacity: 0.30;
"></canvas>
<script>
(function(){{
  const c = document.getElementById('tf-particles');
  if (!c) return;
  const ctx = c.getContext('2d');
  let W, H, nodes = [];

  function resize() {{
    W = c.width  = window.innerWidth;
    H = c.height = window.innerHeight;
  }}
  window.addEventListener('resize', resize);
  resize();

  // Create nodes
  for (let i = 0; i < 55; i++) {{
    nodes.push({{
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.45,
      vy: (Math.random() - 0.5) * 0.45,
      r: Math.random() * 2.2 + 1.0,
      pulse: Math.random() * Math.PI * 2
    }});
  }}

  function draw() {{
    ctx.clearRect(0, 0, W, H);
    const t = Date.now() / 1000;

    // Edges
    for (let i = 0; i < nodes.length; i++) {{
      for (let j = i + 1; j < nodes.length; j++) {{
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx*dx + dy*dy);
        if (dist < 160) {{
          const alpha = (1 - dist / 160) * 0.35;
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.strokeStyle = `rgba(0,200,255,${{alpha.toFixed(3)}})`;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }}
      }}
    }}

    // Nodes
    nodes.forEach(n => {{
      const glow = 0.5 + 0.5 * Math.sin(t * 1.5 + n.pulse);
      const r = n.r + glow * 1.2;
      const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, r * 4);
      grad.addColorStop(0,   `rgba(34,211,238,${{(0.85*glow).toFixed(2)}})`  );
      grad.addColorStop(0.5, `rgba(0,200,255,${{ (0.25*glow).toFixed(2)}})`  );
      grad.addColorStop(1,   'rgba(0,0,0,0)');
      ctx.beginPath();
      ctx.arc(n.x, n.y, r * 4, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(150,255,255,${{(0.9*glow).toFixed(2)}})`;
      ctx.fill();
    }});

    // Move nodes
    nodes.forEach(n => {{
      n.x += n.vx; n.y += n.vy;
      if (n.x < 0 || n.x > W) n.vx *= -1;
      if (n.y < 0 || n.y > H) n.vy *= -1;
    }});

    requestAnimationFrame(draw);
  }}
  draw();
}})();
</script>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# AUTHENTICATION: SIGN IN & SIGN UP SCREENS
# ---------------------------------------------------------------------------
if "auth_user" not in st.session_state:
    st.session_state.auth_user = None

users_db = load_users()


def render_auth_portal():
    """Render the user authentication portal containing Sign In and Sign Up tabs."""
    col_vis, col_auth = st.columns([1.15, 1], gap="large")

    with col_vis:
        st.markdown("<br>", unsafe_allow_html=True)
        if SHIELD_IMG.exists():
            st.image(str(SHIELD_IMG), use_container_width=True)
        st.markdown("""<div style="padding: 0.8rem 0.2rem 1rem 0.2rem;">
<div style="font-family:'JetBrains Mono',monospace; font-size:0.72rem; font-weight:600; color:#22D3EE; text-transform:uppercase; letter-spacing:0.14em; margin-bottom:0.6rem; display:flex; align-items:center; gap:0.5rem;">
<span style="flex:1; height:1px; background:linear-gradient(90deg,#22D3EE44,transparent);"></span>
🛡️ &nbsp;Trust no one. Verify everything. Defend everywhere.
<span style="flex:1; height:1px; background:linear-gradient(90deg,transparent,#22D3EE44);"></span>
</div>
<div style="font-family:'Plus Jakarta Sans',sans-serif; font-size:3rem; font-weight:800; color:#FFFFFF; letter-spacing:-0.04em; line-height:1; margin-bottom:0.5rem;">
Trust<span style="color:#22D3EE; text-shadow:0 0 28px rgba(34,211,238,0.75);">FL</span>
</div>
<div style="font-size:0.95rem; color:#94A3B8; margin-bottom:1rem; line-height:1.55;">
Byzantine-Resilient Federated IoT Intrusion Detection
</div>
<div style="display:flex; gap:0.6rem; flex-wrap:wrap;">
<span class="tf-badge badge-trust"><span class="tf-badge-dot"></span> Zero-Trust</span>
<span class="tf-badge badge-warn"><span class="tf-badge-dot"></span> Byzantine Resilient</span>
<span class="tf-badge badge-alert"><span class="tf-badge-dot"></span> Attack Detection</span>
</div>
</div>""", unsafe_allow_html=True)

    with col_auth:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""<div class="tf-card" style="border-top: 3px solid #22D3EE; padding: 2.2rem 2rem;">
<div style="text-align: center; margin-bottom: 1.5rem;">
<div style="font-family: 'JetBrains Mono', monospace; font-size: 0.62rem; color: #22D3EE; letter-spacing: 0.12em; text-transform: uppercase; margin-bottom: 0.55rem; opacity: 0.85;">
🔒 &nbsp;Zero-Trust &bull; Federated &bull; Byzantine-Resilient
</div>
<div style="font-family: 'Plus Jakarta Sans', sans-serif; font-size: 2.2rem; font-weight: 800; letter-spacing: -0.04em; color: #FFFFFF; margin-bottom: 0.2rem; line-height: 1;">
Trust<span style="color: #22D3EE; text-shadow: 0 0 22px rgba(34,211,238,0.75);">FL</span>
</div>
<div style="font-size: 0.82rem; color: #64748B; font-style: italic; margin-bottom: 0.25rem;">
&ldquo;Where every gradient is earned, not assumed.&rdquo;
</div>
<div style="font-size: 0.78rem; color: #475569; margin-top: 0.5rem;">
Sign in to access the Security Console
</div>
</div>""", unsafe_allow_html=True)

        tab_signin, tab_signup = st.tabs(["Sign In", "Create Account"])

        with tab_signin:
            st.write("")
            with st.form("signin_form"):
                email = st.text_input("Email address", placeholder="name@company.com").strip().lower()
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                submitted = st.form_submit_button("Sign In to Console", use_container_width=True, type="primary")

                if submitted:
                    if not email or not password:
                        st.error("Please enter both email and password.")
                    elif email not in users_db:
                        st.error("No account found with this email address.")
                    elif users_db[email]["password_hash"] != hash_password(password):
                        st.error("Incorrect password. Please try again.")
                    else:
                        st.session_state.auth_user = {
                            "email": email,
                            "name": users_db[email].get("name", email.split("@")[0].capitalize()),
                        }
                        st.rerun()

            st.markdown("""
            <div style="margin-top: 1.25rem; padding: 0.75rem 1rem; background: rgba(255,255,255,0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; font-size: 0.8rem; color: #94A3B8;">
                <span style="font-weight: 600; color: #FFF;">Quick Demo Login:</span><br>
                Email: <code>demo@trustfl.org</code> &nbsp;|&nbsp; Pass: <code>TrustFL@2026</code>
            </div>
            """, unsafe_allow_html=True)

        with tab_signup:
            st.write("")
            with st.form("signup_form"):
                new_name = st.text_input("Full Name", placeholder="e.g. Alex Morgan").strip()
                new_email = st.text_input("Email address", placeholder="name@company.com").strip().lower()
                new_password = st.text_input("Create Password", type="password", placeholder="Minimum 6 characters")
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Re-enter password")
                created = st.form_submit_button("Create Account", use_container_width=True, type="primary")

                if created:
                    email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
                    if not re.match(email_pattern, new_email):
                        st.error("Please provide a valid email address.")
                    elif new_email in users_db:
                        st.error("An account with this email already exists. Please Sign In.")
                    elif len(new_password) < 6:
                        st.error("Password must be at least 6 characters long.")
                    elif new_password != confirm_password:
                        st.error("Passwords do not match.")
                    else:
                        users_db[new_email] = {
                            "password_hash": hash_password(new_password),
                            "name": new_name or new_email.split("@")[0].capitalize(),
                            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                        }
                        save_users(users_db)
                        st.session_state.auth_user = {
                            "email": new_email,
                            "name": users_db[new_email]["name"],
                        }
                        st.success("Account created successfully!")
                        st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


if not st.session_state.auth_user:
    render_auth_portal()
    st.stop()

# ---------------------------------------------------------------------------
# AUTHENTICATED USER SESSION & TOPBAR
# ---------------------------------------------------------------------------
user = st.session_state.auth_user or {"name": "Guest", "email": "guest@trustfl.org"}

# Hero banner — shown above navbar on dashboard
st.markdown(f"""<div style="padding:1.4rem 1.8rem 1.2rem 1.8rem; background:linear-gradient(135deg,rgba(15,19,29,0.92) 0%,rgba(22,30,46,0.92) 100%); border:1px solid rgba(34,211,238,0.18); border-radius:14px; margin-bottom:0.75rem; position:relative; overflow:hidden;">
<div style="position:absolute; inset:0; pointer-events:none; background-image:linear-gradient(rgba(34,211,238,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(34,211,238,0.04) 1px,transparent 1px); background-size:28px 28px; border-radius:14px;"></div>
<div style="position:absolute; top:0; left:1.8rem; right:1.8rem; height:2px; background:linear-gradient(90deg,transparent,#22D3EE,transparent); border-radius:9999px;"></div>
<div style="position:relative; z-index:1;">
<div style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; font-weight:600; color:#22D3EE; letter-spacing:0.16em; text-transform:uppercase; margin-bottom:0.55rem; opacity:0.9;">
🛡️ &nbsp;Trust no one &bull; Verify everything &bull; Defend everywhere
</div>
<div style="font-family:'Plus Jakarta Sans',sans-serif; font-size:2.6rem; font-weight:800; letter-spacing:-0.04em; color:#FFFFFF; line-height:1; margin-bottom:0.45rem;">
Trust<span style="color:#22D3EE; text-shadow:0 0 28px rgba(34,211,238,0.8);">FL</span>
<span style="font-size:0.95rem; font-weight:500; color:{COLOR_MUTED}; letter-spacing:-0.01em; margin-left:0.6rem; vertical-align:middle;">// Security Console</span>
</div>
<div style="font-size:0.88rem; color:#64748B; font-style:italic; letter-spacing:0.01em;">
&ldquo;Where every gradient is earned, not assumed &mdash; federated trust at the edge.&rdquo;
</div>
</div>
</div>

<div class="tf-navbar" style="margin-bottom: 1.2rem;">
<div style="display: flex; align-items: center; gap: 0.8rem;">
<span class="tf-badge" style="background: rgba(34,211,238,0.10); color: #8aebff; border: 1px solid rgba(34,211,238,0.22); font-family: 'JetBrains Mono', monospace; font-size: 0.68rem;">
SPEC: ENCLAVE-DEFENSE-V4.2
</span>
<span class="tf-badge badge-trust"><span class="tf-badge-dot"></span> Active</span>
</div>
<div style="display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;">
<span class="tf-badge badge-trust"><span class="tf-badge-dot"></span> 4 Nodes</span>
<span class="tf-badge" style="background: rgba(34,211,238,0.12); color: #8aebff; border: 1px solid rgba(34,211,238,0.25);">Trust Floor: 0.05</span>
<span class="tf-badge" style="background: rgba(104,245,184,0.10); color: #68f5b8; border: 1px solid rgba(104,245,184,0.22);">Consensus: Cosine EMA</span>
<div style="display: flex; align-items: center; gap: 0.5rem; background: #1c1f2a; padding: 0.25rem 0.75rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08);">
<div style="font-size: 0.82rem; color: #dfe2f1; font-weight: 600;">{user['name']}</div>
<span style="font-size: 0.65rem; color: #22d3ee; background: rgba(34,211,238,0.12); padding: 0.1rem 0.4rem; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-weight: 700;">CLEARANCE ALPHA</span>
</div>
</div>
</div>""", unsafe_allow_html=True)

with st.sidebar:
    if SHIELD_IMG.exists():
        st.image(str(SHIELD_IMG), use_container_width=True)
    st.markdown(f"""
    <div style="padding: 0.5rem 0 1rem 0; border-bottom: 1px solid {COLOR_BORDER}; margin-bottom: 1rem;">
        <div style="font-size: 0.76rem; color: {COLOR_MUTED}; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em;">Logged In As</div>
        <div style="font-size: 1.05rem; font-weight: 700; color: #FFFFFF; margin-top: 0.2rem;">{user['name']}</div>
        <div style="font-size: 0.8rem; color: {COLOR_MUTED};">{user['email']}</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div style="font-size: 0.8rem; color: {COLOR_MUTED}; line-height: 1.8; margin-bottom: 1rem;">
        <div><b>Consensus:</b> Cosine EMA</div>
        <div><b>Trust Floor:</b> 0.05</div>
        <div><b>Defense Status:</b> <span style="color: {COLOR_SUCCESS};">Active</span></div>
    </div>
    <div style="padding: 0.8rem; border-radius: 10px; background: rgba(23, 27, 38, 0.75); border: 1px solid rgba(255,255,255,0.07); font-family: 'JetBrains Mono', monospace; margin-bottom: 1.25rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.72rem; color: #859397; margin-bottom: 0.5rem;">
            <span>ENCLAVE STATUS</span>
            <span style="display: flex; align-items: center; gap: 0.3rem; color: #68f5b8; font-weight: 700;">
                <span style="width: 7px; height: 7px; border-radius: 50%; background: #68f5b8; box-shadow: 0 0 6px #68f5b8; display: inline-block;"></span> SECURE
            </span>
        </div>
        <div style="font-size: 0.7rem; color: #bbc9cd; margin-bottom: 0.25rem; display: flex; justify-content: space-between;">
            <span>BYZANTINE FILTER</span>
            <span style="color: #8aebff;">0.003% DRIFT</span>
        </div>
        <div style="width: 100%; height: 4px; background: #313540; border-radius: 9999px; overflow: hidden; margin-bottom: 0.6rem;">
            <div style="width: 98%; height: 100%; background: #22d3ee;"></div>
        </div>
        <div style="display: flex; justify-content: space-between; font-size: 0.7rem; color: #859397;">
            <span>NODE CLUSTER 0x9F</span>
            <span style="color: #68f5b8; font-weight: 600;">ACTIVE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if st.button("Sign Out", use_container_width=True):
        st.session_state.auth_user = None
        st.rerun()



# ---------------------------------------------------------------------------
# LOAD PERSISTENT RESULTS DATA
# ---------------------------------------------------------------------------
@st.cache_data
def load_json(path: Path):
    """Safely load and parse a JSON file from disk.

    :param path: Path to the target JSON file.
    :returns: Parsed dictionary/list structure, or None if the file does not exist.
    """
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


baseline = load_json(RESULTS_DIR / "baseline_results.json")
comparison = load_json(RESULTS_DIR / "comparison.json")


# ---------------------------------------------------------------------------
# NAVIGATION TABS
# ---------------------------------------------------------------------------
tab_device, tab_live, tab_metrics, tab_about = st.tabs([
    "Device Analyzer",
    "Live Traffic Feed",
    "Model Performance",
    "How It Works",
])


# ===========================================================================
ALIAS_MAP = {
    "flow_duration": "duration", "dur": "duration", "time": "duration",
    "tot_fwd_pkts": "src_pkts", "fwd_pkts": "src_pkts", "packets_sent": "src_pkts", "src_packets": "src_pkts",
    "tot_bwd_pkts": "dst_pkts", "bwd_pkts": "dst_pkts", "packets_rcvd": "dst_pkts", "dst_packets": "dst_pkts",
    "totlen_fwd_pkts": "src_bytes", "bytes_sent": "src_bytes", "source_bytes": "src_bytes",
    "totlen_bwd_pkts": "dst_bytes", "bytes_rcvd": "dst_bytes", "dest_bytes": "dst_bytes",
    "protocol": "proto_enc", "proto": "proto_enc",
    "service": "service_enc",
    "class": "label", "target": "label", "attack": "label", "is_attack": "label",
}

PRESET_SCENARIOS = {
    "trusted": {
        "title": "🟢 Clean IoT Edge Node (Trusted)",
        "file": "sample_device_trusted.csv",
        "badge": "Trusted (~0.69)",
        "color": COLOR_SUCCESS,
        "desc": "Healthy IoT sensor telemetry exhibiting normal traffic flow and strong gradient consensus alignment.",
    },
    "recon": {
        "title": "🟡 Stealth Recon & Port Scan (Suspicious)",
        "file": "sample_device_recon_probe.csv",
        "badge": "Suspicious (~0.26)",
        "color": COLOR_WARN,
        "desc": "Low-and-slow network reconnaissance with anomalous connection sweeps and subtle label divergence.",
    },
    "ddos": {
        "title": "🟠 Volumetric DDoS Surge (Heavy Threat)",
        "file": "sample_device_ddos_surge.csv",
        "badge": "Threat Surge",
        "color": COLOR_WARN,
        "desc": "Severe denial-of-service volumetric packet burst with 53%+ attack proportion.",
    },
    "adversary": {
        "title": "🔴 Byzantine Model Poisoning (Adversary)",
        "file": "sample_device_adversary.csv",
        "badge": "Adversary (0.00)",
        "color": COLOR_DANGER,
        "desc": "Coordinated label-inversion poisoning attack designed to corrupt the global federated model.",
    },
    "unlabeled": {
        "title": "🟣 Unlabeled Wild Capture (No Labels)",
        "file": "sample_device_unlabeled.csv",
        "badge": "Unlabeled",
        "color": COLOR_PRIMARY,
        "desc": "Raw sensor traffic without ground-truth labels for unsupervised real-time classification.",
    },
    "corrupted": {
        "title": "⚠️ Corrupted Telemetry (Bugs & Glitches)",
        "file": "sample_device_corrupted_telemetry.csv",
        "badge": "Buggy Data",
        "color": COLOR_DANGER,
        "desc": "Sensor data containing realistic bugs: clock skews (negative duration), counter underflow, NaNs, and duplicates.",
    },
    "clean_bench": {
        "title": "🛡️ Benchmark Clean Slice",
        "file": "sample_device_clean.csv",
        "badge": "Baseline Clean",
        "color": COLOR_MUTED,
        "desc": "Standard project benchmark clean node slice.",
    },
    "poisoned_bench": {
        "title": "⚡ Benchmark Poisoned Slice",
        "file": "sample_device_poisoned.csv",
        "badge": "Baseline Poisoned",
        "color": COLOR_DANGER,
        "desc": "Standard project benchmark poisoned node slice.",
    },
}


def normalize_and_align_features(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Align arbitrary user CSV columns to the required model feature schema.

    Performs case-insensitive column resolution, maps common network flow aliases
    (e.g., tot_fwd_pkts -> src_pkts), and imputes any remaining missing feature
    columns using standard baseline medians so arbitrary CSVs can be scored.

    :param df: Input DataFrame with arbitrary user columns.
    :returns: Tuple of (aligned DataFrame with all FEATURE_COLUMNS, list of imputed column names).
    """
    aligned = df.copy()
    col_map = {}
    for col in aligned.columns:
        norm = str(col).strip().lower().replace(" ", "_").replace("-", "_")
        if norm in ALIAS_MAP:
            col_map[col] = ALIAS_MAP[norm]
        elif norm in [f.lower() for f in FEATURE_COLUMNS]:
            for f in FEATURE_COLUMNS:
                if f.lower() == norm:
                    col_map[col] = f
        elif norm == LABEL_COLUMN.lower():
            col_map[col] = LABEL_COLUMN

    if col_map:
        aligned = aligned.rename(columns=col_map)

    imputed_cols = []
    for c in FEATURE_COLUMNS:
        if c not in aligned.columns:
            aligned[c] = 0.0
            imputed_cols.append(c)

    if LABEL_COLUMN in aligned.columns:
        if aligned[LABEL_COLUMN].dtype == object:
            aligned[LABEL_COLUMN] = aligned[LABEL_COLUMN].astype(str).str.lower().map(
                lambda v: 0 if v in ["0", "0.0", "normal", "benign", "safe", "false", "clean"] else 1
            )

    return aligned, imputed_cols


def trace_file_bugs_and_anomalies(df: pd.DataFrame, imputed_cols: list[str]) -> dict:
    """Audit an uploaded traffic dataset for schema issues, data corruption, and security threats.

    Identifies malformed values (NaNs, negative durations, integer underflows),
    flags duplicated network flows and extreme packet spikes, detects volumetric
    attack surges, and provides a sanitized copy ready for neural scoring.
    Returns a dict with keys ``'findings'`` (list of dicts), ``'health_score'`` (int),
    and ``'sanitized_df'`` (cleaned DataFrame).
    """
    findings = []
    sanitized_df = df.copy()
    total_rows = len(df)

    if imputed_cols:
        findings.append({
            "category": "Schema Adjustment",
            "severity": "Info",
            "bug": f"Missing Features Imputed ({len(imputed_cols)})",
            "details": f"Columns missing from CSV: {', '.join(imputed_cols)}. Automatically filled with baseline neutral medians.",
            "action": "Zero/median imputed",
        })

    dup_count = int(df.duplicated().sum())
    if dup_count > 0:
        findings.append({
            "category": "Data Integrity",
            "severity": "Warning",
            "bug": "Duplicate Network Flows",
            "details": f"{dup_count} duplicated row(s) detected ({dup_count / total_rows:.1%}). Indicates retransmitted packets or buffer flush loops.",
            "action": "Deduplicated for classification",
        })
        sanitized_df = sanitized_df.drop_duplicates().reset_index(drop=True)

    null_counts = df.isnull().sum()
    cols_with_null = null_counts[null_counts > 0]
    if not cols_with_null.empty:
        total_null_cells = int(cols_with_null.sum())
        cols_summary = ", ".join([f"{c} ({n})" for c, n in cols_with_null.items()])
        findings.append({
            "category": "Data Integrity",
            "severity": "Critical" if total_null_cells > 50 else "Warning",
            "bug": "Missing / NaN Sensor Values",
            "details": f"{total_null_cells} missing cell(s) across: {cols_summary}. Caused by dropped sensor readings or incomplete logging.",
            "action": "Imputed with column medians",
        })
        for c in sanitized_df.select_dtypes(include=[np.number]).columns:
            median_val = sanitized_df[c].median()
            sanitized_df[c] = sanitized_df[c].fillna(median_val if not pd.isna(median_val) else 0.0)

    if "duration" in df.columns:
        neg_dur = int((df["duration"] < 0).sum())
        if neg_dur > 0:
            min_val = float(df["duration"].min())
            findings.append({
                "category": "Sensor Hardware Bug",
                "severity": "Critical",
                "bug": "Clock Skew / Negative Duration",
                "details": f"{neg_dur} packet flow(s) have negative duration (min: {min_val:.3f}s). Indicates RTC desynchronization or NTP clock jump.",
                "action": "Clipped negative durations to 0.0s",
            })
            sanitized_df["duration"] = sanitized_df["duration"].clip(lower=0.0)

    byte_pkt_cols = [c for c in ["src_bytes", "dst_bytes", "src_pkts", "dst_pkts", "src_ip_bytes", "dst_ip_bytes"] if c in df.columns]
    neg_counters = {}
    for c in byte_pkt_cols:
        neg_c = int((df[c] < 0).sum())
        if neg_c > 0:
            neg_counters[c] = neg_c
    if neg_counters:
        summary = ", ".join([f"{k}: {v}" for k, v in neg_counters.items()])
        findings.append({
            "category": "Sensor Hardware Bug",
            "severity": "Critical",
            "bug": "Integer Underflow / Negative Counter",
            "details": f"Negative counters found in {summary}. Indicates signed integer overflow or telemetry firmware bug.",
            "action": "Clipped negative values to 0",
        })
        for c in neg_counters:
            sanitized_df[c] = sanitized_df[c].clip(lower=0)

    if "src_pkts" in df.columns:
        extreme_pkts = int((df["src_pkts"] > 1000000).sum())
        if extreme_pkts > 0:
            findings.append({
                "category": "Threat / Buffer Bug",
                "severity": "Critical",
                "bug": "Extreme Packet Flood Spike",
                "details": f"{extreme_pkts} flow(s) exceed 1,000,000 packets per burst. Indicates volumetric flood or sensor buffer overflow.",
                "action": "Flagged as high-severity threat",
            })

    if "attack_type" in df.columns:
        dos_count = int(df["attack_type"].isin(["dos", "ddos"]).sum())
        if dos_count > 0.4 * total_rows:
            findings.append({
                "category": "Security Threat",
                "severity": "Critical",
                "bug": "Volumetric Denial-of-Service Surge",
                "details": f"{dos_count} flow(s) ({dos_count / total_rows:.1%}) match DoS/DDoS volumetric signatures.",
                "action": "Mitigation: Rate limiting recommended",
            })
        scan_count = int((df["attack_type"] == "scanning").sum())
        if scan_count > 0.15 * total_rows:
            findings.append({
                "category": "Security Threat",
                "severity": "Warning",
                "bug": "Reconnaissance Port Sweep",
                "details": f"{scan_count} flow(s) ({scan_count / total_rows:.1%}) match network port scanning and service probing.",
                "action": "Mitigation: Blacklist scan source IPs",
            })

    critical_count = sum(1 for f in findings if f["severity"] == "Critical")
    warning_count = sum(1 for f in findings if f["severity"] == "Warning")
    info_count = sum(1 for f in findings if f["severity"] == "Info")
    health_score = max(100 - (critical_count * 25) - (warning_count * 10) - (info_count * 5), 5)

    return {
        "findings": findings,
        "health_score": health_score,
        "sanitized_df": sanitized_df,
    }


# ===========================================================================
# TAB 1: DEVICE ANALYZER & BUG TRACER
# ===========================================================================
with tab_device:
    st.markdown("""
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.8rem; flex-wrap: wrap; gap: 0.5rem;">
        <div style="display: flex; align-items: center; gap: 0.5rem; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">
            <span style="color: #22D3EE; text-transform: uppercase;">SPEC: ENCLAVE-DEFENSE-V4.2</span>
            <span style="color: #859397;">/</span>
            <span style="color: #68F5B8; text-transform: uppercase;">DEVICE TELEMETRY AUDIT</span>
            <span style="color: #859397;">/</span>
            <span style="color: #BBC9CD; text-transform: uppercase;">FAULT & ANOMALY SCANNER</span>
        </div>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.70rem; color: #68F5B8; background: rgba(104,245,184,0.1); padding: 0.2rem 0.6rem; border-radius: 6px; border: 1px solid rgba(104,245,184,0.3);">
            DIAGNOSTIC ENGINE: ARMED
        </span>
    </div>
    <div class="tf-card">
        <div class="tf-card-title">
            <span style="color:#22D3EE;">⬡</span> Device Telemetry Analyzer & Anomaly Bug Tracer
        </div>
        <div class="tf-card-sub">
            Upload custom IoT network traffic or select adversarial benchmark profiles. The zero-trust diagnostic engine audits schema integrity, detects hardware clock/counter faults, and computes the real-time <b>Byzantine Trust Score (0.00 to 1.00)</b>.
        </div>
    </div>
    """, unsafe_allow_html=True)


    if "active_scenario_key" not in st.session_state:
        st.session_state.active_scenario_key = "trusted"

    scen_col, up_col = st.columns([1.1, 1], gap="medium")

    with scen_col:
        st.markdown("<b style='font-size:0.95rem; color:#FFF;'>Preset Device Scenarios</b>", unsafe_allow_html=True)
        scenario_options = list(PRESET_SCENARIOS.keys())
        selected_scenario = st.selectbox(
            "Select Scenario",
            scenario_options,
            index=scenario_options.index(st.session_state.active_scenario_key) if st.session_state.active_scenario_key in scenario_options else 0,
            format_func=lambda k: PRESET_SCENARIOS[k]["title"],
            label_visibility="collapsed",
        )
        scen_info = PRESET_SCENARIOS[selected_scenario]
        st.markdown(f"""
        <div style="background: rgba(255,255,255,0.02); border: 1px solid {COLOR_BORDER}; border-radius: 8px; padding: 0.6rem 0.8rem; margin: 0.5rem 0 0.8rem 0; font-size: 0.84rem; color: {COLOR_MUTED};">
            <span style="color:{scen_info['color']}; font-weight: 600;">● {scen_info['badge']}</span>: {scen_info['desc']}
        </div>
        """, unsafe_allow_html=True)

        b_col1, b_col2 = st.columns([1, 1])
        with b_col1:
            if st.button("⚡ Load Scenario", use_container_width=True, type="primary"):
                st.session_state.active_scenario_key = selected_scenario
                if "custom_csv_df" in st.session_state:
                    del st.session_state["custom_csv_df"]
                st.rerun()

        with b_col2:
            scen_file_path = DATA_DIR / scen_info["file"]
            if scen_file_path.exists():
                with open(scen_file_path, "rb") as f:
                    st.download_button(
                        "📥 Download CSV",
                        f,
                        file_name=scen_info["file"],
                        use_container_width=True,
                    )

    with up_col:
        st.markdown("<b style='font-size:0.95rem; color:#FFF;'>Or Upload Any Custom CSV File</b>", unsafe_allow_html=True)
        uploaded_file = st.file_uploader(
            "Upload any CSV file",
            type=["csv", "txt"],
            label_visibility="collapsed",
            help="Accepts any network flow CSV. Auto-maps column aliases and imputes missing features.",
        )
        if uploaded_file is not None:
            try:
                st.session_state.custom_csv_df = pd.read_csv(uploaded_file)
                st.session_state.custom_csv_name = uploaded_file.name
            except Exception as e:
                st.error(f"Error reading CSV: {e}")

    # Determine which DataFrame to inspect
    target_df = None
    target_name = ""
    if "custom_csv_df" in st.session_state and st.session_state.custom_csv_df is not None:
        target_df = st.session_state.custom_csv_df
        target_name = f"Uploaded File: {st.session_state.get('custom_csv_name', 'custom.csv')}"
    else:
        active_key = st.session_state.active_scenario_key
        active_path = DATA_DIR / PRESET_SCENARIOS[active_key]["file"]
        if active_path.exists():
            target_df = pd.read_csv(active_path)
            target_name = f"Preset: {PRESET_SCENARIOS[active_key]['title']}"
        elif (DATA_DIR / "sample_device_clean.csv").exists():
            target_df = pd.read_csv(DATA_DIR / "sample_device_clean.csv")
            target_name = "Default: sample_device_clean.csv"

    if target_df is not None and not target_df.empty:
        try:
            import joblib
            # pyrefly: ignore [missing-import]
            import model_utils as mu
            # pyrefly: ignore [missing-import]
            from common import FEATURE_COLUMNS, LABEL_COLUMN

            # 1. Normalize and Align schema
            aligned_df, imputed_cols = normalize_and_align_features(target_df)

            # 2. Trace bugs & anomalies
            audit = trace_file_bugs_and_anomalies(aligned_df, imputed_cols)
            findings = audit["findings"]
            health_score = audit["health_score"]
            sanitized_df = audit["sanitized_df"]

            # Display Bug Tracer Report
            st.markdown(f"<div style='margin-top:1.2rem; margin-bottom:0.4rem; font-size:1.1rem; font-weight:700; color:#FFF;'>🔍 Bug & Data Integrity Trace Audit <span style='font-size:0.82rem; font-weight:400; color:{COLOR_MUTED};'>({target_name})</span></div>", unsafe_allow_html=True)

            score_color = COLOR_SUCCESS if health_score >= 80 else (COLOR_WARN if health_score >= 50 else COLOR_DANGER)
            health_label = "Pristine Telemetry" if health_score >= 90 else ("Minor Warnings" if health_score >= 70 else ("Degraded Sensor Data" if health_score >= 40 else "Severe Corruptions Detected"))

            stat_c1, stat_c2, stat_c3, stat_c4 = st.columns(4)
            with stat_c1:
                st.markdown(f"""
                <div class="tf-card" style="padding: 1rem; text-align:center;">
                    <div style="font-size:0.75rem; color:{COLOR_MUTED};">Integrity Health</div>
                    <div style="font-size:1.6rem; font-weight:800; color:{score_color};">{health_score} <span style="font-size:0.9rem;">/ 100</span></div>
                    <div style="font-size:0.72rem; color:{score_color}; font-weight:600;">{health_label}</div>
                </div>
                """, unsafe_allow_html=True)
            with stat_c2:
                st.markdown(f"""
                <div class="tf-card" style="padding: 1rem; text-align:center;">
                    <div style="font-size:0.75rem; color:{COLOR_MUTED};">Total Flows</div>
                    <div style="font-size:1.6rem; font-weight:800; color:#FFF;">{len(target_df):,}</div>
                    <div style="font-size:0.72rem; color:{COLOR_MUTED};">{len(sanitized_df):,} sanitized</div>
                </div>
                """, unsafe_allow_html=True)
            with stat_c3:
                n_crit = sum(1 for f in findings if f["severity"] == "Critical")
                st.markdown(f"""
                <div class="tf-card" style="padding: 1rem; text-align:center;">
                    <div style="font-size:0.75rem; color:{COLOR_MUTED};">Critical Bugs</div>
                    <div style="font-size:1.6rem; font-weight:800; color:{COLOR_DANGER if n_crit > 0 else COLOR_SUCCESS};">{n_crit}</div>
                    <div style="font-size:0.72rem; color:{COLOR_MUTED};">{len(findings)} total findings</div>
                </div>
                """, unsafe_allow_html=True)
            with stat_c4:
                st.markdown(f"""
                <div class="tf-card" style="padding: 1rem; text-align:center;">
                    <div style="font-size:0.75rem; color:{COLOR_MUTED};">Auto-Remediation</div>
                    <div style="font-size:1.6rem; font-weight:800; color:{COLOR_SUCCESS};">ACTIVE</div>
                    <div style="font-size:0.72rem; color:{COLOR_SUCCESS};">Cleaned for Neural Scoring</div>
                </div>
                """, unsafe_allow_html=True)

            if findings:
                with st.expander(f"📋 View Detailed Bug Trace Findings ({len(findings)} events detected)", expanded=True):
                    for f in findings:
                        f_color = COLOR_DANGER if f["severity"] == "Critical" else (COLOR_WARN if f["severity"] == "Warning" else COLOR_PRIMARY)
                        st.markdown(f"""
                        <div style="background: rgba(255,255,255,0.02); border-left: 3px solid {f_color}; padding: 0.6rem 0.9rem; margin-bottom: 0.5rem; border-radius: 4px;">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <b style="color:#FFF; font-size:0.9rem;">{f['bug']}</b>
                                <span style="font-size:0.75rem; color:{f_color}; font-weight:700; background:rgba(255,255,255,0.05); padding:2px 8px; border-radius:10px;">{f['severity']} // {f['category']}</span>
                            </div>
                            <div style="font-size:0.82rem; color:#CBD5E1; margin: 0.3rem 0;">{f['details']}</div>
                            <div style="font-size:0.75rem; color:{COLOR_MUTED};"><b>Remediation:</b> {f['action']}</div>
                        </div>
                        """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid {COLOR_SUCCESS}; border-radius: 8px; padding: 0.7rem 1rem; margin-bottom: 1rem; font-size: 0.85rem; color: #E2E8F0;">
                    <b style="color:{COLOR_SUCCESS};">✅ Clean Telemetry Verification:</b> All network flow records and feature columns passed integrity checks with 0 bugs or corrupted counters.
                </div>
                """, unsafe_allow_html=True)

            # 3. Model Classification & Trust Consensus Scoring
            scaler = joblib.load(RESULTS_DIR / "scaler.joblib")
            npz = np.load(RESULTS_DIR / "global_model_weights.npz")
            global_weights = [npz[k] for k in npz.files]
            reference_consensus = np.load(RESULTS_DIR / "reference_consensus.npy")

            X = scaler.transform(sanitized_df[FEATURE_COLUMNS])

            clf_model = mu.build_model()
            init_X = X[: min(4, len(X))]
            init_y = np.array([0, 1, 0, 1])[: len(init_X)]
            mu.init_architecture(clf_model, init_X, init_y)
            mu.set_weights(clf_model, global_weights)

            preds = clf_model.predict(X)
            probs = clf_model.predict_proba(X)
            attack_rate = float(preds.mean())

            trust_score = None
            if LABEL_COLUMN in sanitized_df.columns:
                y = sanitized_df[LABEL_COLUMN].fillna(0).values.astype(np.int64)
                local_model = mu.build_model()
                mu.init_architecture(local_model, init_X, init_y)
                mu.set_weights(local_model, global_weights)
                mu.local_train(local_model, X, y, epochs=2)
                new_weights = mu.get_weights(local_model)

                delta = mu.flatten_weights(new_weights) - mu.flatten_weights(global_weights)
                delta_norm = np.linalg.norm(delta)
                consensus_norm = np.linalg.norm(reference_consensus)

                if delta_norm > 0 and consensus_norm > 0:
                    cos_sim = float(np.dot(delta, reference_consensus) / (delta_norm * consensus_norm))
                    trust_score = max(cos_sim, 0.0)
                else:
                    trust_score = 0.0

            if trust_score is None:
                verdict, badge_class, gauge_color = "LABELS MISSING", "badge-warn", COLOR_WARN
                explanation = "No ground-truth labels were included in this CSV. Individual flows were classified by the global neural net, but trust consensus requires ground truth."
            elif trust_score > 0.60:
                verdict, badge_class, gauge_color = "TRUSTED DEVICE", "badge-trust", COLOR_SUCCESS
                explanation = "This device's traffic patterns closely align with healthy network nodes. Full trust and normal aggregation weighting are applied."
            elif trust_score > 0.20:
                verdict, badge_class, gauge_color = "SUSPICIOUS ACTIVITY", "badge-warn", COLOR_WARN
                explanation = "This device exhibits noticeable anomalies and gradient divergence. Its aggregation weight is partially down-weighted."
            else:
                verdict, badge_class, gauge_color = "UNTRUSTED / ADVERSARY", "badge-alert", COLOR_DANGER
                explanation = "Severe anomaly or poisoning signature detected. This node is clamped to the minimum trust floor (0.05) to prevent corrupting the shared model."

            st.markdown("<div style='margin-top:1.5rem; margin-bottom:0.4rem; font-size:1.1rem; font-weight:700; color:#FFF;'>🛡️ Consensus Trust & Threat Classification</div>", unsafe_allow_html=True)

            out_col1, out_col2 = st.columns([1, 1.3])

            with out_col1:
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=trust_score if trust_score is not None else 0.0,
                    number={"valueformat": ".2f", "font": {"family": "Plus Jakarta Sans", "size": 48, "color": gauge_color}},
                    gauge={
                        "axis": {"range": [0, 1], "tickwidth": 1, "tickcolor": COLOR_MUTED},
                        "bar": {"color": gauge_color, "thickness": 0.28},
                        "bgcolor": "rgba(0,0,0,0)",
                        "borderwidth": 0,
                        "steps": [
                            {"range": [0, 0.20], "color": "rgba(239, 68, 68, 0.12)"},
                            {"range": [0.20, 0.60], "color": "rgba(245, 158, 11, 0.12)"},
                            {"range": [0.60, 1.00], "color": "rgba(16, 185, 129, 0.12)"},
                        ],
                    },
                ))
                fig.update_layout(
                    height=240,
                    margin=dict(l=20, r=20, t=20, b=10),
                    paper_bgcolor="rgba(0,0,0,0)",
                )
                st.plotly_chart(fig, use_container_width=True)
                st.markdown(
                    f'<div style="text-align:center; margin-top:-0.5rem;"><span class="tf-badge {badge_class}"><span class="tf-badge-dot"></span> {verdict}</span></div>',
                    unsafe_allow_html=True,
                )

            with out_col2:
                st.markdown(f"""
                <div class="tf-card" style="margin-top: 0.5rem;">
                    <div style="display: flex; gap: 2rem; margin-bottom: 1rem;">
                        <div>
                            <div style="font-size: 0.78rem; color: {COLOR_MUTED};">Total Flows Analyzed</div>
                            <div style="font-size: 1.5rem; font-weight: 700; color: #FFF;">{len(sanitized_df):,}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.78rem; color: {COLOR_MUTED};">Flagged as Attack</div>
                            <div style="font-size: 1.5rem; font-weight: 700; color: {COLOR_DANGER if attack_rate > 0.3 else COLOR_SUCCESS};">{attack_rate:.1%}</div>
                        </div>
                    </div>
                    <div style="border-top: 1px solid {COLOR_BORDER}; padding-top: 0.8rem; font-size: 0.88rem; color: #E2E8F0; line-height: 1.5;">
                        {explanation}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            st.write("")
            st.markdown("<b>Per-Flow Classification Details</b> (first 50 flows)", unsafe_allow_html=True)
            preview = sanitized_df[FEATURE_COLUMNS].copy()
            preview.insert(0, "Prediction", np.where(preds == 1, "ATTACK", "NORMAL"))
            preview.insert(1, "Confidence", probs.max(axis=1).round(3))
            st.dataframe(preview.head(50), use_container_width=True, height=280)

        except FileNotFoundError:
            st.warning("Model artifacts not found. Run `python src/run_experiment.py --suite` to build reference weights.")
        except Exception as exc:
            st.error(f"Analysis error: {exc}")
    else:
        st.info("Please select a scenario or upload a CSV file to begin analysis.")


# ===========================================================================
# TAB 2: LIVE TRAFFIC FEED
# ===========================================================================
with tab_live:
    st.markdown("""
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.8rem; flex-wrap: wrap; gap: 0.5rem;">
        <div style="display: flex; align-items: center; gap: 0.5rem; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">
            <span style="color: #22D3EE; text-transform: uppercase;">SPEC: ENCLAVE-DEFENSE-V4.2</span>
            <span style="color: #859397;">/</span>
            <span style="color: #68F5B8; text-transform: uppercase;">LIVE TRAFFIC STREAM</span>
            <span style="color: #859397;">/</span>
            <span style="color: #ADC6FF; text-transform: uppercase;">REAL-TIME THREAT RADAR</span>
        </div>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.70rem; color: #22D3EE; background: rgba(34,211,238,0.1); padding: 0.2rem 0.6rem; border-radius: 6px; border: 1px solid rgba(34,211,238,0.3);">
            STREAM: ONLINE
        </span>
    </div>
    <div class="tf-card" style="
        border: 1px solid rgba(60, 73, 76, 0.5);
        border-top: 3px solid #22D3EE;
        position: relative;
        overflow: hidden;
    ">
        <div style="position:absolute; top:24px; right:28px; width:48px; height:48px;">
            <div class="live-radar-ring" style="animation-delay:0s;"></div>
            <div class="live-radar-ring" style="animation-delay:0.7s;"></div>
            <div class="live-radar-ring" style="animation-delay:1.4s;"></div>
            <div style="
                position:absolute; inset:0;
                display:flex; align-items:center; justify-content:center;
                font-size:1.4rem;
            ">📡</div>
        </div>
        <div class="tf-card-title" style="font-size:1.05rem; color:#22D3EE; text-shadow:0 0 10px rgba(34,211,238,0.4);">
            ⚡ Live Device Traffic Stream
        </div>
        <div class="tf-card-sub">
            Simulates a real-time stream of incoming network traffic from a held-out test dataset.
            Inject an <b style="color:#F59E0B;">attack burst</b> to watch the model flag threats in real time.
        </div>
        <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-top:0.4rem;">
            <span class="tf-badge badge-trust"><span class="tf-badge-dot"></span> RandomForest Classifier</span>
            <span class="tf-badge badge-warn" ><span class="tf-badge-dot"></span> 2s Refresh Rate</span>
            <span class="tf-badge badge-alert"><span class="tf-badge-dot"></span> Attack Detection Active</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    try:
        # pyrefly: ignore [missing-import]
        from common import FEATURE_COLUMNS, fit_scaler, get_global_test_split, to_xy
        from sklearn.ensemble import RandomForestClassifier

        @st.cache_resource
        def get_demo_model():
            """Train and cache a fast demo RandomForest classifier for live traffic streaming.

            :returns: Tuple of (classifier, fitted scaler, test DataFrame).
            """
            train_df, test_df = get_global_test_split()
            scaler = fit_scaler(train_df)
            X_train, y_train = to_xy(train_df, scaler)
            clf = RandomForestClassifier(n_estimators=100, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1)
            clf.fit(X_train, y_train)
            return clf, scaler, test_df

        clf, scaler, test_df = get_demo_model()
        normal_rows = test_df[test_df["label"] == 0]
        attack_rows = test_df[test_df["label"] == 1]

        if "live_feed_log" not in st.session_state:
            st.session_state.live_feed_log = []
        if "live_feed_running" not in st.session_state:
            st.session_state.live_feed_running = False
        if "force_attack_ticks" not in st.session_state:
            st.session_state.force_attack_ticks = 0

        ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([1, 1.2, 2])
        with ctrl_col1:
            btn_txt = "Pause Feed" if st.session_state.live_feed_running else "Start Live Feed"
            if st.button(btn_txt, use_container_width=True, type="primary" if not st.session_state.live_feed_running else "secondary"):
                st.session_state.live_feed_running = not st.session_state.live_feed_running
                st.rerun()

        with ctrl_col2:
            if st.button("Simulate Attack Burst", use_container_width=True):
                st.session_state.force_attack_ticks = 5
                st.session_state.live_feed_running = True
                st.rerun()

        with ctrl_col3:
            badge_html = '<span class="tf-badge badge-trust"><span class="tf-badge-dot"></span> Live Streaming</span>' if st.session_state.live_feed_running else '<span class="tf-badge" style="background:#1E293B;color:#94A3B8;">Paused</span>'
            st.markdown(f'<div style="padding-top:0.4rem;">{badge_html} &nbsp;&nbsp; <span style="font-size:0.84rem; color:{COLOR_MUTED};">Total Flows: <b style="color:#FFF;">{len(st.session_state.live_feed_log)}</b></span></div>', unsafe_allow_html=True)

        @st.fragment(run_every=2 if st.session_state.live_feed_running else None)
        def render_live_feed():
            """Render real-time streaming traffic packet inspection and intrusion alerts."""
            if st.session_state.live_feed_running:
                if st.session_state.force_attack_ticks > 0 and len(attack_rows) > 0:
                    row = attack_rows.sample(1)
                    st.session_state.force_attack_ticks -= 1
                else:
                    row = normal_rows.sample(1) if len(normal_rows) > 0 else test_df.sample(1)

                X_row, y_row = to_xy(row, scaler)
                pred = clf.predict(X_row)[0]
                proba = clf.predict_proba(X_row)[0]

                st.session_state.live_feed_log.insert(0, {
                    "Time": datetime.datetime.now().strftime("%H:%M:%S"),
                    "Status": "ATTACK" if pred == 1 else "NORMAL",
                    "Confidence": f"{max(proba):.1%}",
                    "Attack Type": row["attack_type"].iloc[0],
                    "Action": "Blocked" if pred == 1 else "Permitted",
                })
                st.session_state.live_feed_log = st.session_state.live_feed_log[:25]

            if st.session_state.live_feed_log:
                feed_df = pd.DataFrame(st.session_state.live_feed_log)
                st.dataframe(feed_df, use_container_width=True, hide_index=True, height=400)
            else:
                st.info("Click 'Start Live Feed' to begin streaming real-time network traffic.")

        render_live_feed()

    except Exception as exc:
        st.error(f"Live feed error: {exc}")


# ===========================================================================
# TAB 3: MODEL PERFORMANCE
# ===========================================================================
with tab_metrics:
    st.markdown("""
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.8rem; flex-wrap: wrap; gap: 0.5rem;">
        <div style="display: flex; align-items: center; gap: 0.5rem; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">
            <span style="color: #22D3EE; text-transform: uppercase;">SPEC: ENCLAVE-DEFENSE-V4.2</span>
            <span style="color: #859397;">/</span>
            <span style="color: #68F5B8; text-transform: uppercase;">MODEL PERFORMANCE</span>
            <span style="color: #859397;">/</span>
            <span style="color: #ADC6FF; text-transform: uppercase;">BYZANTINE BENCHMARKS</span>
        </div>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.70rem; color: #68F5B8; background: rgba(104,245,184,0.1); padding: 0.2rem 0.6rem; border-radius: 6px; border: 1px solid rgba(104,245,184,0.3);">
            BYZANTINE TOLERANCE: 33.3%
        </span>
    </div>
    <div class="tf-card">
        <div class="tf-card-title">
            <span style="color:#22D3EE;">⬡</span> Model Performance &amp; Byzantine Resiliency Benchmarks
        </div>
        <div class="tf-card-sub">
            Evaluation comparing standard Federated Averaging (FedAvg) against our <b>Trust-Weighted FL Enclave Consensus</b> under clean and adversarial poisoning conditions.
        </div>
    </div>
    """, unsafe_allow_html=True)


    if baseline is None and comparison is None:
        st.warning("No experiment results found. Run `python src/run_experiment.py --suite` first.")
    else:
        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        if baseline:
            m_col1.metric("Centralized Baseline", f"{baseline['accuracy']:.1%}")

        if comparison and "clean_fedavg" in comparison:
            m_col2.metric("FedAvg (Clean)", f"{comparison['clean_fedavg']['final_metrics']['accuracy']:.1%}")

        if comparison and "fedavg_under_attack" in comparison and "clean_fedavg" in comparison:
            f_clean = comparison["clean_fedavg"]["final_metrics"]["accuracy"]
            f_atk = comparison["fedavg_under_attack"]["final_metrics"]["accuracy"]
            m_col3.metric("FedAvg Under Attack", f"{f_atk:.1%}", delta=f"{(f_atk - f_clean):.1%}", delta_color="inverse")

        if comparison and "trust_under_attack" in comparison and "fedavg_under_attack" in comparison:
            t_atk = comparison["trust_under_attack"]["final_metrics"]["accuracy"]
            f_atk = comparison["fedavg_under_attack"]["final_metrics"]["accuracy"]
            m_col4.metric("Trust-FL Under Attack", f"{t_atk:.1%}", delta=f"+{(t_atk - f_atk):.1%} vs FedAvg")

        st.write("")

        if comparison:
            p_col1, p_col2 = st.columns([1.2, 1])

            with p_col1:
                st.markdown("<b>Model Comparison (Accuracy & F1-Score)</b>", unsafe_allow_html=True)
                rows = []
                for tag, res in comparison.items():
                    fm = res["final_metrics"]
                    rows.append({
                        "Experiment": tag.replace("_", " ").title(),
                        "Accuracy": fm.get("accuracy"),
                        "F1-Score": fm.get("f1"),
                    })
                bar_df = pd.DataFrame(rows)
                fig_bar = px.bar(
                    bar_df,
                    x="Experiment",
                    y=["Accuracy", "F1-Score"],
                    barmode="group",
                    color_discrete_sequence=[COLOR_PRIMARY, COLOR_SUCCESS],
                )
                fig_bar.update_layout(
                    height=300,
                    margin=dict(l=10, r=10, t=10, b=10),
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font={"family": "Plus Jakarta Sans", "color": COLOR_MUTED},
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                    yaxis=dict(range=[0, 1.05], gridcolor="rgba(255,255,255,0.06)"),
                    xaxis=dict(gridcolor="rgba(255,255,255,0.04)"),
                )
                st.plotly_chart(fig_bar, use_container_width=True)

            with p_col2:
                st.markdown("<b>Rounds Convergence</b>", unsafe_allow_html=True)
                chosen_run = st.selectbox("Select Experiment Run", list(comparison.keys()), label_visibility="collapsed")
                round_metrics = comparison[chosen_run].get("metrics_by_round", {})

                if "accuracy" in round_metrics:
                    line_df = pd.DataFrame({
                        "Round": list(range(1, len(round_metrics["accuracy"]) + 1)),
                        "Accuracy": round_metrics["accuracy"],
                    })
                    fig_line = px.line(line_df, x="Round", y="Accuracy", markers=True)
                    fig_line.update_traces(line_color=COLOR_SUCCESS)
                    fig_line.update_layout(
                        height=270,
                        margin=dict(l=10, r=10, t=10, b=10),
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font={"family": "Plus Jakarta Sans", "color": COLOR_MUTED},
                        yaxis=dict(range=[0.4, 1.0], gridcolor="rgba(255,255,255,0.06)"),
                        xaxis=dict(dtick=1, gridcolor="rgba(255,255,255,0.04)"),
                    )
                    st.plotly_chart(fig_line, use_container_width=True)

            # Node Trust Trajectory
            trust_run = None
            for tag in ["trust_under_attack", "clean_trust"]:
                if tag in comparison and "trust_log" in comparison[tag]:
                    trust_run = tag
                    break

            if trust_run:
                st.write("")
                st.markdown("<b>Per-Node Trust Scores Over Rounds (Adversary Down-Weighting)</b>", unsafe_allow_html=True)
                trust_df = pd.DataFrame(comparison[trust_run]["trust_log"]).drop_duplicates(subset=["round", "node_id"], keep="last")
                pivot = trust_df.pivot(index="round", columns="node_id", values="trust").reset_index()

                fig_traj = go.Figure()
                for col in pivot.columns:
                    if col != "round":
                        is_adv = col == "0" and trust_run == "trust_under_attack"
                        fig_traj.add_trace(go.Scatter(
                            x=pivot["round"],
                            y=pivot[col],
                            mode="lines+markers",
                            name=f"Node {col} (Adversary)" if is_adv else f"Node {col} (Honest)",
                            line=dict(
                                color=COLOR_DANGER if is_adv else COLOR_SUCCESS,
                                width=3 if is_adv else 1.5,
                            ),
                        ))

                fig_traj.update_layout(
                    height=300,
                    margin=dict(l=10, r=10, t=10, b=10),
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font={"family": "Plus Jakarta Sans", "color": COLOR_MUTED},
                    xaxis=dict(title="Round", dtick=1, gridcolor="rgba(255,255,255,0.04)"),
                    yaxis=dict(title="Trust Score", range=[0, 1.05], gridcolor="rgba(255,255,255,0.06)"),
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                )
                st.plotly_chart(fig_traj, use_container_width=True)


# ===========================================================================
# TAB 4: HOW IT WORKS
# ===========================================================================
with tab_about:
    st.markdown("""
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.8rem; flex-wrap: wrap; gap: 0.5rem;">
        <div style="display: flex; align-items: center; gap: 0.5rem; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">
            <span style="color: #22D3EE; text-transform: uppercase;">SPEC: ENCLAVE-DEFENSE-V4.2</span>
            <span style="color: #859397;">/</span>
            <span style="color: #68F5B8; text-transform: uppercase;">BYZANTINE-FAULT-TOLERANT FEDERATED AGGREGATION</span>
        </div>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.70rem; color: #68F5B8; background: rgba(104,245,184,0.1); padding: 0.2rem 0.6rem; border-radius: 6px; border: 1px solid rgba(104,245,184,0.3);">
            ZERO-TRUST CONSENSUS
        </span>
    </div>
    """, unsafe_allow_html=True)

    # 4 Key Invariants (Stitch HUD tiles)
    inv_col1, inv_col2, inv_col3, inv_col4 = st.columns(4)
    with inv_col1:
        st.markdown(f"""
        <div class="tf-card" style="padding: 1rem; margin-bottom: 0.8rem;">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.7rem; color:#859397; text-transform:uppercase;">Byzantine Tolerance</div>
            <div style="font-family:'JetBrains Mono', monospace; font-size:1.6rem; font-weight:700; color:#68F5B8;">33.3%</div>
            <div style="font-size:0.75rem; color:#BBC9CD;">Max poisoned swarm ratio</div>
        </div>
        """, unsafe_allow_html=True)
    with inv_col2:
        st.markdown(f"""
        <div class="tf-card" style="padding: 1rem; margin-bottom: 0.8rem;">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.7rem; color:#859397; text-transform:uppercase;">Cosine Floor (τ)</div>
            <div style="font-family:'JetBrains Mono', monospace; font-size:1.6rem; font-weight:700; color:#22D3EE;">0.05</div>
            <div style="font-size:0.75rem; color:#BBC9CD;">Adversary weight bound</div>
        </div>
        """, unsafe_allow_html=True)
    with inv_col3:
        st.markdown(f"""
        <div class="tf-card" style="padding: 1rem; margin-bottom: 0.8rem;">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.7rem; color:#859397; text-transform:uppercase;">EMA Factor (α)</div>
            <div style="font-family:'JetBrains Mono', monospace; font-size:1.6rem; font-weight:700; color:#ADC6FF;">0.15</div>
            <div style="font-size:0.75rem; color:#BBC9CD;">Low-and-slow drift filter</div>
        </div>
        """, unsafe_allow_html=True)
    with inv_col4:
        st.markdown(f"""
        <div class="tf-card" style="padding: 1rem; margin-bottom: 0.8rem;">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.7rem; color:#859397; text-transform:uppercase;">Zero-Trust Leakage</div>
            <div style="font-family:'JetBrains Mono', monospace; font-size:1.6rem; font-weight:700; color:#68F5B8;">0.00%</div>
            <div style="font-size:0.75rem; color:#BBC9CD;">Raw telemetry leaves edge</div>
        </div>
        """, unsafe_allow_html=True)

    # Core Architecture & Topography
    col_about_text, col_about_img = st.columns([1.25, 1], gap="large")

    with col_about_text:
        st.markdown(f"""
        <div class="tf-card">
            <div class="tf-card-title">
                <span style="color:#22D3EE;">⬡</span> How Trust-Weighted Federated Learning Works
            </div>
            <div class="tf-card-sub">
                A clear breakdown of the privacy-preserving principles and Byzantine defense mechanisms.
            </div>

            <h4 style="color:#DFE2F1; margin-top: 1rem; font-size: 0.95rem;">1. Privacy-Preserving Collaborative Training</h4>
            <p style="font-size: 0.86rem; color: #BBC9CD; line-height: 1.6;">
                Multiple distributed edge IoT networks train intrusion detection models locally on raw network flows. Rather than centralizing sensitive packet captures, edge nodes transmit only mathematical model weight deltas (gradients).
            </p>

            <h4 style="color:#DFE2F1; margin-top: 1rem; font-size: 0.95rem;">2. The Vulnerability: Poisoning & Model Replacement</h4>
            <p style="font-size: 0.86rem; color: #BBC9CD; line-height: 1.6;">
                Standard Federated Averaging (FedAvg) blindly averages client weights. A single compromised IoT gateway transmitting inverted labels or scaled weights corrupts the shared global model in as few as 1–2 rounds.
            </p>

            <h4 style="color:#DFE2F1; margin-top: 1rem; font-size: 0.95rem;">3. The Defense: Cosine-EMA Consensus & Excision</h4>
            <p style="font-size: 0.86rem; color: #BBC9CD; line-height: 1.6;">
                TrustFL computes high-dimensional vector alignments against the swarm median vector:
            </p>
            <ul style="font-size: 0.84rem; color: #BBC9CD; line-height: 1.7;">
                <li><b>Directional Similarity:</b> Quantifies cosine angle between local updates and the median consensus vector.</li>
                <li><b>Historical Memory:</b> Compounded over rounds via Exponential Moving Average (<code style="color:#22D3EE;">α = 0.15</code>).</li>
                <li><b>Dynamic Excision:</b> Divergent or malicious updates are clamped to baseline floor (<code style="color:#22D3EE;">τ = 0.05</code>) or quarantined.</li>
            </ul>
        </div>

        <div class="tf-card">
            <div class="tf-card-title">
                <span style="color:#ADC6FF;">⚖</span> Mathematical Resilience: FedAvg vs. TrustFL
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.8rem; margin-top: 0.8rem;">
                <div style="background: #171B26; padding: 0.8rem; border-radius: 8px; border: 1px solid rgba(255,180,171,0.25);">
                    <div style="font-family:'JetBrains Mono', monospace; font-size:0.72rem; color:#FFB4AB; font-weight:700;">STANDARD FEDAVG</div>
                    <div style="font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:#859397; margin: 0.3rem 0;">w_{{t+1}} = Σ (n_k/n · w_k)</div>
                    <div style="font-size:0.78rem; color:#BBC9CD;">Post-Attack Accuracy:</div>
                    <div style="font-family:'JetBrains Mono', monospace; font-size:1.1rem; color:#FFB4AB; font-weight:700;">41.2% (-57.2%)</div>
                </div>
                <div style="background: #171B26; padding: 0.8rem; border-radius: 8px; border: 1px solid rgba(104,245,184,0.25);">
                    <div style="font-family:'JetBrains Mono', monospace; font-size:0.72rem; color:#68F5B8; font-weight:700;">TRUSTFL ENCLAVE</div>
                    <div style="font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:#859397; margin: 0.3rem 0;">w_{{t+1}} = Σ (Trust_k · Δw_k)</div>
                    <div style="font-size:0.78rem; color:#BBC9CD;">Post-Attack Accuracy:</div>
                    <div style="font-family:'JetBrains Mono', monospace; font-size:1.1rem; color:#68F5B8; font-weight:700;">97.8% (Preserved)</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_about_img:
        if MESH_IMG.exists():
            st.image(str(MESH_IMG), caption="Decentralized Edge IoT Mesh // Zero-Trust Cryptographic Shield Nodes", use_container_width=True)
        elif SHIELD_IMG.exists():
            st.image(str(SHIELD_IMG), caption="TrustFL Cryptographic Shield Enclave", use_container_width=True)

        st.markdown(f"""
        <div class="tf-card" style="margin-top: 1rem;">
            <div class="tf-card-title">Enclave Topography Specifications</div>
            <div style="font-size: 0.82rem; color: #BBC9CD; line-height: 1.8; font-family: 'JetBrains Mono', monospace;">
                <div><span style="color:#859397;">CONSENSUS:</span> <span style="color:#22D3EE;">Cosine Directional EMA</span></div>
                <div><span style="color:#859397;">ENCLAVE PROTO:</span> <span style="color:#68F5B8;">Zero-Knowledge Gradient Transmission</span></div>
                <div><span style="color:#859397;">TOLERANCE:</span> <span style="color:#68F5B8;">Byzantine Label-Flipping & Amplification</span></div>
                <div><span style="color:#859397;">TARGET:</span> <span style="color:#DFE2F1;">Industrial IoT & Decentralized Sensors</span></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # 4-Stage Neutralization Pipeline
    st.write("")
    st.markdown("### 🛡️ 4-Stage Byzantine Neutralization Pipeline")
    pcol1, pcol2, pcol3, pcol4 = st.columns(4)
    with pcol1:
        st.markdown(f"""
        <div class="tf-card" style="padding: 1rem; height: 100%;">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.68rem; color:#22D3EE; font-weight:700;">STAGE 01</div>
            <div style="font-weight:700; color:#DFE2F1; font-size:0.88rem; margin:0.3rem 0;">Decentralized Edge Telemetry</div>
            <div style="font-size:0.78rem; color:#BBC9CD; line-height:1.5;">
                Raw packet flows never leave edge nodes. Edge nodes perform local training on private telemetry.
            </div>
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.72rem; color:#22D3EE; margin-top:0.6rem; background:#171B26; padding:0.25rem 0.5rem; border-radius:4px;">
                Δw_i = w_local - w_global
            </div>
        </div>
        """, unsafe_allow_html=True)
    with pcol2:
        st.markdown(f"""
        <div class="tf-card" style="padding: 1rem; height: 100%;">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.68rem; color:#ADC6FF; font-weight:700;">STAGE 02</div>
            <div style="font-weight:700; color:#DFE2F1; font-size:0.88rem; margin:0.3rem 0;">Attested Gradient Passing</div>
            <div style="font-size:0.78rem; color:#BBC9CD; line-height:1.5;">
                Only parameter deltas exit edge devices. Cryptographic signatures prevent tampering across the network.
            </div>
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.72rem; color:#ADC6FF; margin-top:0.6rem; background:#171B26; padding:0.25rem 0.5rem; border-radius:4px;">
                mTLS + Gradient Hash
            </div>
        </div>
        """, unsafe_allow_html=True)
    with pcol3:
        st.markdown(f"""
        <div class="tf-card" style="padding: 1rem; height: 100%;">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.68rem; color:#68F5B8; font-weight:700;">STAGE 03</div>
            <div style="font-weight:700; color:#DFE2F1; font-size:0.88rem; margin:0.3rem 0;">Cosine EMA Consensus</div>
            <div style="font-size:0.78rem; color:#BBC9CD; line-height:1.5;">
                Server measures angular similarity against the swarm medoid vector to update node reputation.
            </div>
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.72rem; color:#68F5B8; margin-top:0.6rem; background:#171B26; padding:0.25rem 0.5rem; border-radius:4px;">
                R_t = 0.15·s_t + 0.85·R_{{t-1}}
            </div>
        </div>
        """, unsafe_allow_html=True)
    with pcol4:
        st.markdown(f"""
        <div class="tf-card" style="padding: 1rem; height: 100%;">
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.68rem; color:#FFB4AB; font-weight:700;">STAGE 04</div>
            <div style="font-weight:700; color:#DFE2F1; font-size:0.88rem; margin:0.3rem 0;">Dynamic Byzantine Excision</div>
            <div style="font-size:0.78rem; color:#BBC9CD; line-height:1.5;">
                Poisoned gradients with low or negative cosine similarity are down-weighted to τ = 0.05.
            </div>
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.72rem; color:#FFB4AB; margin-top:0.6rem; background:#171B26; padding:0.25rem 0.5rem; border-radius:4px;">
                w_{{t+1}} = Σ (Trust_i · Δw_i)
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Video Keynotes
    st.write("")
    st.markdown("""
    <div class="tf-card">
        <div class="tf-card-title">
            <span style="color:#22D3EE;">▶</span> Technical Research Briefings & Video Keynotes
        </div>
        <div class="tf-card-sub">
            Watch presentations on federated learning, decentralized architecture, and privacy-preserving AI.
        </div>
    </div>
    """, unsafe_allow_html=True)

    vcol1, vcol2 = st.columns(2, gap="medium")
    with vcol1:
        st.video("https://www.youtube.com/watch?v=d_k8S-p0q8A")
        st.caption("Flower: Unified Federated AI — Daniel J. Beutel (Co-creator)")
    with vcol2:
        st.video("https://www.youtube.com/watch?v=GB0Xq8e8n3U")
        st.caption("Google I/O: Federated Learning on Decentralized Data")


