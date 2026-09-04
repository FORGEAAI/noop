#!/usr/bin/env python3
"""Fork-only: App Store Connect helper for .github/workflows/testflight.yml.

After `xcodebuild -exportArchive` has uploaded a build, this script:
  1. finds the app by bundle id,
  2. waits until App Store Connect has finished processing that exact build (version + build number),
  3. makes sure an INTERNAL beta group exists (created with access to all builds, so every future
     upload reaches it without another API call),
  4. adds TESTER_EMAIL to that group (idempotent), and
  5. clears a "Missing Compliance" hold if one appears despite ITSAppUsesNonExemptEncryption.

Auth: an App Store Connect API key (ASC_KEY_ID / ASC_ISSUER_ID / ASC_KEY_P8 as base64) from the
environment. Nothing secret is ever printed; the tester e-mail is only printed masked.

    python Tools/testflight_invite.py --bundle-id com.example.noop --version 11.1.1 --build 400
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import jwt  # PyJWT with the [crypto] extra (ES256)

API_BASE = "https://api.appstoreconnect.apple.com/v1"
# Apple caps API tokens at 20 minutes; refresh well inside that.
TOKEN_TTL_SEC = 15 * 60
TOKEN_REFRESH_MARGIN_SEC = 2 * 60
POLL_INTERVAL_SEC = 60
HTTP_TIMEOUT_SEC = 60

PROCESSING_TERMINAL_BAD = {"FAILED", "INVALID"}


class ApiError(RuntimeError):
    def __init__(self, status: int, payload: dict | str):
        self.status = status
        self.payload = payload
        super().__init__(f"HTTP {status}: {summarize_errors(payload)}")


def summarize_errors(payload: dict | str) -> str:
    if isinstance(payload, dict) and "errors" in payload:
        return "; ".join(
            f"{e.get('code', '?')} — {e.get('title', '')}: {e.get('detail', '')}".strip()
            for e in payload["errors"]
        )
    return str(payload)[:500]


def mask_email(email: str) -> str:
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    return f"{local[:1]}***@{domain}"


def require_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        sys.exit(f"::error::environment variable {name} is required")
    return value


class Client:
    def __init__(self, key_id: str, issuer_id: str, private_key_pem: str):
        self.key_id = key_id
        self.issuer_id = issuer_id
        self.private_key_pem = private_key_pem
        self._token = ""
        self._token_expires_at = 0.0

    def _token_value(self) -> str:
        now = time.time()
        if not self._token or now > self._token_expires_at - TOKEN_REFRESH_MARGIN_SEC:
            issued = int(now)
            self._token = jwt.encode(
                {
                    "iss": self.issuer_id,
                    "iat": issued,
                    "exp": issued + TOKEN_TTL_SEC,
                    "aud": "appstoreconnect-v1",
                },
                self.private_key_pem,
                algorithm="ES256",
                headers={"kid": self.key_id, "typ": "JWT"},
            )
            self._token_expires_at = issued + TOKEN_TTL_SEC
        return self._token

    def request(self, method: str, path: str, params: dict | None = None, body: dict | None = None) -> dict:
        url = path if path.startswith("http") else f"{API_BASE}{path}"
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._token_value()}")
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as err:
            raw = err.read()
            try:
                payload = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                payload = raw.decode(errors="replace")
            raise ApiError(err.code, payload) from None

    def get(self, path: str, **params) -> dict:
        return self.request("GET", path, params=params or None)

    def post(self, path: str, body: dict) -> dict:
        return self.request("POST", path, body=body)

    def patch(self, path: str, body: dict) -> dict:
        return self.request("PATCH", path, body=body)


def find_app(client: Client, bundle_id: str) -> dict:
    apps = client.get("/apps", **{"filter[bundleId]": bundle_id, "fields[apps]": "name,bundleId"}).get("data", [])
    if not apps:
        sys.exit(
            f"::error::No App Store Connect app record has bundle id {bundle_id}. "
            "Create the app record (My Apps → +) for this bundle id, or fix the bundle id in project.yml."
        )
    app = apps[0]
    print(f"App: {app['attributes']['name']} ({bundle_id}) id={app['id']}")
    return app


def fetch_build(client: Client, app_id: str, version: str, build_number: str) -> tuple[dict | None, dict | None]:
    """Return (build, buildBetaDetail) for the exact version/build, or (None, None) if not visible yet."""
    resp = client.get(
        "/builds",
        **{
            "filter[app]": app_id,
            "filter[version]": build_number,
            "filter[preReleaseVersion.version]": version,
            "fields[builds]": "version,processingState,uploadedDate,usesNonExemptEncryption,expired",
            "include": "buildBetaDetail",
            "fields[buildBetaDetails]": "internalBuildState,externalBuildState",
            "limit": 5,
        },
    )
    builds = [b for b in resp.get("data", []) if not b["attributes"].get("expired")]
    if not builds:
        return None, None
    build = builds[0]
    detail = next((i for i in resp.get("included", []) if i["type"] == "buildBetaDetails"), None)
    return build, detail


def wait_for_build(client: Client, app_id: str, version: str, build_number: str, wait_minutes: int) -> tuple[dict, dict | None]:
    deadline = time.time() + wait_minutes * 60
    seen = False
    while True:
        build, detail = fetch_build(client, app_id, version, build_number)
        if build is None:
            print(f"Build {version} ({build_number}) not visible in App Store Connect yet — waiting…")
        else:
            state = build["attributes"]["processingState"]
            if not seen:
                print(f"Build {version} ({build_number}) found, id={build['id']}, uploaded {build['attributes'].get('uploadedDate')}")
                seen = True
            if state == "VALID":
                print("Processing complete (VALID).")
                return build, detail
            if state in PROCESSING_TERMINAL_BAD:
                sys.exit(
                    f"::error::App Store Connect reports processingState={state} for build {build_number}. "
                    "Check the App Store Connect e-mail for the processing failure reason."
                )
            print(f"processingState={state} — waiting…")
        if time.time() > deadline:
            sys.exit(
                f"::error::Gave up after {wait_minutes} min waiting for build {version} ({build_number}) to finish processing. "
                "Re-run this job later with the same version/build; the upload itself succeeded."
            )
        time.sleep(POLL_INTERVAL_SEC)


def ensure_internal_group(client: Client, app_id: str, name: str) -> dict:
    groups = client.get(
        "/betaGroups",
        **{
            "filter[app]": app_id,
            "filter[isInternalGroup]": "true",
            "fields[betaGroups]": "name,isInternalGroup,hasAccessToAllBuilds",
            "limit": 50,
        },
    ).get("data", [])
    for group in groups:
        if group["attributes"]["name"] == name:
            print(f"Internal group '{name}' exists (id={group['id']}, allBuilds={group['attributes'].get('hasAccessToAllBuilds')})")
            return group
    created = client.post(
        "/betaGroups",
        {
            "data": {
                "type": "betaGroups",
                "attributes": {"name": name, "isInternalGroup": True, "hasAccessToAllBuilds": True},
                "relationships": {"app": {"data": {"type": "apps", "id": app_id}}},
            }
        },
    )["data"]
    print(f"Created internal group '{name}' (id={created['id']}) with access to all builds")
    return created


def ensure_build_in_group(client: Client, group: dict, build_id: str) -> None:
    if group["attributes"].get("hasAccessToAllBuilds"):
        return  # every build is already visible to this group
    try:
        client.post(
            f"/betaGroups/{group['id']}/relationships/builds",
            {"data": [{"type": "builds", "id": build_id}]},
        )
        print("Added the build to the group.")
    except ApiError as err:
        # 409 = already added; anything else is real.
        if err.status != 409:
            raise
        print("Build was already in the group.")


def ensure_tester(client: Client, group: dict, email: str) -> None:
    masked = mask_email(email)
    in_group = client.get(
        "/betaTesters",
        **{"filter[email]": email, "filter[betaGroups]": group["id"], "fields[betaTesters]": "email", "limit": 1},
    ).get("data", [])
    if in_group:
        print(f"Tester {masked} is already in the group.")
        return
    try:
        client.post(
            "/betaTesters",
            {
                "data": {
                    "type": "betaTesters",
                    "attributes": {"email": email},
                    "relationships": {"betaGroups": {"data": [{"type": "betaGroups", "id": group["id"]}]}},
                }
            },
        )
        print(f"Added tester {masked} to the group — TestFlight sends the invite e-mail now.")
        return
    except ApiError as err:
        print(f"Direct add returned {err}; trying to link an existing tester record instead.")
        existing = client.get("/betaTesters", **{"filter[email]": email, "fields[betaTesters]": "email", "limit": 1}).get("data", [])
        if not existing:
            sys.exit(
                "::error::Could not add the tester to the INTERNAL group. Internal testers must be users of your "
                "App Store Connect team with TestFlight access: Users and Access → the user → enable "
                "'Internal Testing' / the app, then re-run this job."
            )
        client.post(
            f"/betaGroups/{group['id']}/relationships/betaTesters",
            {"data": [{"type": "betaTesters", "id": existing[0]["id"]}]},
        )
        print(f"Linked existing tester {masked} to the group.")


def clear_export_compliance_hold(client: Client, build: dict, detail: dict | None) -> None:
    state = (detail or {}).get("attributes", {}).get("internalBuildState")
    print(f"internalBuildState={state}")
    if state != "MISSING_EXPORT_COMPLIANCE":
        return
    # ITSAppUsesNonExemptEncryption=false should pre-answer this; if App Store Connect still asks,
    # answer through the API so the build becomes testable without a web-UI visit.
    client.patch(
        f"/builds/{build['id']}",
        {"data": {"type": "builds", "id": build["id"], "attributes": {"usesNonExemptEncryption": False}}},
    )
    print("Answered export compliance (uses only exempt encryption) via the API.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--version", required=True, help="CFBundleShortVersionString, e.g. 11.1.1")
    parser.add_argument("--build", required=True, help="CFBundleVersion, e.g. 400")
    parser.add_argument("--group", default="Internal", help="internal beta group name (created if missing)")
    parser.add_argument("--wait-minutes", type=int, default=60)
    parser.add_argument("--tester-email", default=os.environ.get("TESTER_EMAIL", ""),
                        help="defaults to $TESTER_EMAIL; skipped with a warning when empty")
    args = parser.parse_args()

    key_id = require_env("ASC_KEY_ID")
    issuer_id = require_env("ASC_ISSUER_ID")
    try:
        private_key_pem = base64.b64decode(require_env("ASC_KEY_P8")).decode()
    except Exception:
        sys.exit("::error::ASC_KEY_P8 is not valid base64 of the .p8 file")
    if "PRIVATE KEY" not in private_key_pem:
        sys.exit("::error::ASC_KEY_P8 decoded, but it does not look like a PEM private key")

    client = Client(key_id, issuer_id, private_key_pem)

    app = find_app(client, args.bundle_id)
    build, detail = wait_for_build(client, app["id"], args.version, args.build, args.wait_minutes)
    group = ensure_internal_group(client, app["id"], args.group)
    ensure_build_in_group(client, group, build["id"])
    clear_export_compliance_hold(client, build, detail)

    if args.tester_email:
        ensure_tester(client, group, args.tester_email)
    else:
        print("::warning::TESTER_EMAIL not set — group is ready, but nobody was invited.")

    print(f"Done: {args.bundle_id} {args.version} ({args.build}) is in internal group '{args.group}'.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ApiError as err:
        sys.exit(f"::error::App Store Connect API error — {err}")
