#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
import zipfile
from urllib.parse import unquote, urlsplit

SO_PATH_IN_APK = "lib/arm64-v8a/libapjni.so"
DEFAULT_API = "https://folk.mysqil.com/api"
GH_PROXY_PREFIX = "https://cdn.gh-proxy.org/"

_TOKEN_RE = re.compile(rb"[\x20-\x7e]{8,}")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def _entropy_score(s: str) -> int:
    return (
        len(s)
        + (10 if any(c.islower() for c in s) else 0)
        + (10 if any(c.isupper() for c in s) else 0)
        + (10 if any(c.isdigit() for c in s) else 0)
    )


def _is_token_candidate(s: str) -> bool:
    if not (20 <= len(s) <= 48):
        return False
    if not _TOKENISH_RE.match(s):
        return False
    if _HEX64_RE.match(s):
        return False
    if not (
        any(c.islower() for c in s)
        and any(c.isupper() for c in s)
        and any(c.isdigit() for c in s)
    ):
        return False
    return True


def extract_token_candidates(apk_path: str) -> list[str]:
    with zipfile.ZipFile(apk_path) as z:
        with z.open(SO_PATH_IN_APK) as f:
            blob = f.read()
    strings = {m.group().decode("ascii") for m in _TOKEN_RE.finditer(blob)}
    return sorted({s for s in strings if _is_token_candidate(s)}, key=_entropy_score, reverse=True)


def http_get(url: str, ua: str, lang: str = "zh-CN", timeout: int = 30, retries: int = 3) -> tuple[int, bytes]:
    last = None
    for attempt in range(retries):
        req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Language": lang})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.getcode(), r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"GET failed after {retries} tries: {url}: {last}")


def _looks_like_plugin_array(body: bytes) -> bool:
    try:
        d = json.loads(body)
    except Exception:
        return False
    return isinstance(d, list) and len(d) > 0 and all(isinstance(e, dict) for e in d)


def pick_token(candidates: list[str], api_base: str, ua: str) -> str | None:
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    plugin_url = f"{api_base}/modules?type=plugin&lang=zh&token="
    for c in candidates:
        code, body = http_get(plugin_url + c, ua)
        if code == 200 and _looks_like_plugin_array(body):
            return c
    return candidates[0]


def slugify(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", name.strip()).strip("-").lower()
    return s or "plugin"


def deproxy(url: str) -> str:
    if url.startswith(GH_PROXY_PREFIX):
        rest = url[len(GH_PROXY_PREFIX):]
        if rest.startswith("http://") or rest.startswith("https://"):
            return rest
    return url


def download(url: str, dest: str, ua: str, timeout: int = 60, retries: int = 4) -> int:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
            with open(dest, "wb") as fh:
                fh.write(data)
            return len(data)
        except Exception as e:
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"download failed: {url}: {last}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--version-code", required=True)
    ap.add_argument("--api", default=DEFAULT_API)
    ap.add_argument("--out", default=".")
    ap.add_argument("--mirror-base", default=os.environ.get("MIRROR_BASE_URL", ""))
    ap.add_argument("--lang", default="zh")
    args = ap.parse_args()

    ua = f"APatch/{args.version_code}"

    cands = extract_token_candidates(args.apk)
    token = pick_token(cands, args.api, ua)
    if not token:
        print("no token candidate found in the APK", file=sys.stderr)
        return 2

    index_url = f"{args.api}/modules?type=plugin&lang={args.lang}&token={token}"
    code, body = http_get(index_url, ua)
    if code != 200 or not _looks_like_plugin_array(body):
        print(f"unexpected index response (HTTP {code}): {body[:200]!r}", file=sys.stderr)
        return 3
    entries = json.loads(body)

    index_dir = os.path.join(args.out, "index")
    os.makedirs(index_dir, exist_ok=True)
    with open(os.path.join(index_dir, "plugin.raw.json"), "wb") as fh:
        fh.write(body)

    mirror_base = args.mirror_base.rstrip("/")
    rewritten = []
    seen: dict[str, int] = {}
    total = 0
    for e in entries:
        name = e.get("name", "")
        upstream = e.get("url", "")
        if not (upstream.startswith("http://") or upstream.startswith("https://")):
            print(f"skip bad url: {name!r} {upstream!r}", file=sys.stderr)
            continue
        key = slugify(name)
        if key in seen:
            seen[key] += 1
            key = f"{key}-{seen[key]}"
        else:
            seen[key] = 0

        direct = deproxy(upstream)
        fname = unquote(os.path.basename(urlsplit(direct).path)) or f"{key}.bin"
        rel = f"plugins/{key}/{fname}"
        dest = os.path.join(args.out, rel)
        try:
            n = download(direct, dest, ua)
        except Exception:
            n = download(upstream, dest, ua)
        total += n

        item = dict(e)
        item["upstream_url"] = upstream
        item["url"] = f"{mirror_base}/{rel}" if mirror_base else rel
        rewritten.append(item)

    with open(os.path.join(index_dir, "plugin.json"), "w", encoding="utf-8") as fh:
        json.dump(rewritten, fh, ensure_ascii=False, indent=2)

    meta = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": index_url.replace(token, "***"),
        "app_user_agent": ua,
        "plugin_count": len(rewritten),
        "total_bytes": total,
        "token_source": os.path.basename(args.apk),
    }
    with open(os.path.join(index_dir, "mirror_meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=2)

    print(f"{len(rewritten)} plugins, {total} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
