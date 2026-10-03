"""End-to-end check against a real OpenID Connect provider (Keycloak).

Signs in to the Aegis dashboard in a headless browser through Keycloak (authorization code
flow with PKCE, password then a TOTP code), and then checks what Aegis does with the IdP's
token: it verifies the RS256 signature against the JWKS, the issuer and audience, matches
the user by email, counts the token's ``amr`` as MFA for step-up, and refuses tampered tokens.

Run Keycloak with ``deploy/keycloak/aegis-realm.json`` imported and Aegis in oidc mode
(see docs/DEPLOY.md), then:

    pip install playwright && playwright install chromium
    python scripts/oidc_e2e.py
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import time
import urllib.error
import urllib.request

from playwright.sync_api import expect, sync_playwright

AEGIS = os.getenv("AEGIS_URL", "http://localhost:8001")
ISSUER = os.getenv("AEGIS_OIDC_ISSUER", "http://localhost:8080/realms/aegis")
# The demo realm's shared authenticator key (raw bytes, as Keycloak stores it). Demo only.
DEMO_TOTP_KEY = os.getenv("DEMO_TOTP_KEY", "aegis-demo-totp-key!").encode()
PASSWORD = os.getenv("DEMO_PASSWORD", "aegis-demo")


def check(condition: object, detail: object) -> None:
    if not condition:
        raise SystemExit(f"oidc e2e failed: {detail}")


def totp(key: bytes, at: float | None = None) -> str:
    counter = int((time.time() if at is None else at) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return str((struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


def claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def http(method: str, path: str, token: str | None = None, body: dict | None = None) -> tuple[int, dict]:
    check(AEGIS.startswith(("http://", "https://")), f"AEGIS_URL must be http(s): {AEGIS}")
    request = urllib.request.Request(  # noqa: S310 - fixed http(s) base URL from the environment
        AEGIS + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json", **({"authorization": f"Bearer {token}"} if token else {})},
    )
    try:
        with urllib.request.urlopen(request) as resp:  # noqa: S310  # nosec B310
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"null")


def sign_in(page, username: str) -> str:
    page.goto(f"{AEGIS}/ui/")
    page.click("#login-sso")
    page.wait_for_url(f"{ISSUER}/**")
    page.fill("#username", username)
    page.fill("#password", PASSWORD)
    page.click("#kc-login")
    # Wait until the start of a fresh 30 s window if this one is nearly over.
    if 30 - time.time() % 30 < 3:
        time.sleep(30 - time.time() % 30 + 0.5)
    page.fill("#otp", totp(DEMO_TOTP_KEY))
    page.click("#kc-login")
    page.wait_for_url(f"{AEGIS}/ui/")
    expect(page.locator("#app")).to_be_visible()
    return page.evaluate("sessionStorage.getItem('aegis-token')")


def main() -> None:
    status, meta = http("GET", "/meta")
    check(status == 200 and meta["auth_mode"] == "oidc" and meta["oidc"]["issuer"] == ISSUER, meta)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=os.getenv("CHROMIUM") or None)
        page = browser.new_page()
        token = sign_in(page, "bob.martinez")
        c = claims(token)
        check(c["iss"] == ISSUER and "aegis-jit" in (c["aud"] if isinstance(c["aud"], list) else [c["aud"]]), c)
        check(c["email"] == "bob.martinez@aegis.example" and {"pwd", "otp"} <= set(c.get("amr", [])), c)
        print(f"signed in through Keycloak: amr={c['amr']} acr={c.get('acr')}")

        # A restricted request goes through: the IdP's amr counts as a fresh second factor.
        page.fill("#request-text", "Need admin on prod-k8s-cluster for 2 hours to roll back a bad deploy")
        page.click("#request-form button[type=submit]")
        expect(page.locator("main")).to_contain_text("awaiting a second approver")
        print("restricted request accepted with the IdP's MFA: pending approval")

        page.click("#logout")
        page.wait_for_url(f"{AEGIS}/ui/")
        expect(page.locator("#login")).to_be_visible()
        browser.close()

    status, me = http("GET", "/me", token)
    check(status == 200 and me["email"] == "bob.martinez@aegis.example", me)
    head, body, sig = token.split(".")
    forged = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    forged["email"] = "iris.novak@aegis.example"
    forged_body = base64.urlsafe_b64encode(json.dumps(forged).encode()).decode().rstrip("=")
    check(http("GET", "/me", f"{head}.{forged_body}.{sig}")[0] == 401, "a token with edited claims must fail")
    check(http("POST", "/auth/dev-token", body={"email": "bob.martinez@aegis.example"})[0] == 404, "dev issuer is on")
    print("API: IdP token accepted; edited token rejected; dev issuer disabled")
    print("oidc e2e ok")


if __name__ == "__main__":
    main()
