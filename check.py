#!/usr/bin/env python3
"""Скачивает публичные списки v2ray-конфигов, проверяет какие серверы живые,
и сохраняет лучшие в sub.txt (base64, для импорта в Hiddify / v2rayNG) и status.json.

Только стандартная библиотека Python, ничего ставить не надо.
Проверка: TCP-соединение, а для TLS/Reality ещё и TLS-рукопожатие.
Это показывает, что сервер жив и отвечает. Полную гарантию, что через него идёт трафик,
даёт только реальный клиент.
"""
import asyncio
import base64
import ipaddress
import json
import random
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote, urlsplit

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/Sub1.txt",
]

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")
MAX_CANDIDATES = 4000   # сколько конфигов проверять за один запуск
KEEP = 150              # сколько лучших оставить в подписке
TIMEOUT = 4.0           # секунд на один сервер
CONCURRENCY = 300


def b64decode_loose(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="ignore")


def split_lines(text):
    """Список может быть обычным текстом или целиком в base64."""
    if "://" not in text[:200]:
        try:
            text = b64decode_loose("".join(text.split())).decode("utf-8", errors="ignore")
        except Exception:
            return []
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith(SCHEMES)]


def parse(link):
    """Возвращает (proto, host, port, tls_sni_or_None) или None."""
    try:
        proto = link.split("://", 1)[0]
        if proto == "vmess":
            d = json.loads(b64decode_loose(link[8:]).decode("utf-8", errors="ignore"))
            host, port = d.get("add"), int(d.get("port"))
            sni = (d.get("sni") or d.get("host") or host) if d.get("tls") in ("tls", "1", True) else None
            return proto, host, port, sni
        if proto == "ss":
            body = link[5:].split("#", 1)[0].split("?", 1)[0]
            if "@" not in body:
                body = b64decode_loose(body).decode("utf-8", errors="ignore")
            hostport = body.rsplit("@", 1)[1]
            host, port = hostport.rsplit(":", 1)
            return proto, host.strip("[]"), int(port), None
        u = urlsplit(link)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        host, port = u.hostname, u.port
        if not host or not port:
            return None
        sec = q.get("security", "tls" if proto == "trojan" else "none")
        sni = (q.get("sni") or q.get("host") or host) if sec in ("tls", "reality") else None
        return proto, host, int(port), sni
    except Exception:
        return None


def is_public(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        return host not in ("localhost",) and "." in host


async def check(sem, host, port, sni):
    async with sem:
        t0 = time.perf_counter()
        try:
            if sni:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                coro = asyncio.open_connection(
                    host, port, ssl=ctx, server_hostname=sni, ssl_handshake_timeout=TIMEOUT
                )
            else:
                coro = asyncio.open_connection(host, port)
            _, w = await asyncio.wait_for(coro, TIMEOUT)
            ms = int((time.perf_counter() - t0) * 1000)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return ms
        except Exception:
            return None


async def run(candidates):
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [check(sem, c["host"], c["port"], c["sni"]) for c in candidates]
    return await asyncio.gather(*tasks)


def main():
    seen, candidates = set(), []
    for url in SOURCES:
        try:
            lines = split_lines(fetch(url))
            print(f"{len(lines):6d}  {url}")
        except Exception as e:
            print(f"ОШИБКА  {url}: {e}")
            continue
        for ln in lines:
            if ln in seen:
                continue
            seen.add(ln)
            p = parse(ln)
            if not p or not is_public(p[1]):
                continue
            candidates.append({"link": ln, "proto": p[0], "host": p[1], "port": p[2], "sni": p[3]})

    # убираем дубли по host:port
    uniq, keys = [], set()
    for c in candidates:
        k = (c["host"], c["port"])
        if k not in keys:
            keys.add(k)
            uniq.append(c)
    random.shuffle(uniq)
    uniq = uniq[:MAX_CANDIDATES]
    print(f"К проверке: {len(uniq)}")

    results = asyncio.run(run(uniq))
    alive = sorted(
        ({**c, "ms": ms} for c, ms in zip(uniq, results) if ms is not None),
        key=lambda c: c["ms"],
    )
    best = alive[:KEEP]
    print(f"Живых: {len(alive)}, оставляем: {len(best)}")

    plain = "\n".join(c["link"] for c in best)
    with open("sub_plain.txt", "w", encoding="utf-8") as f:
        f.write(plain + "\n")
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(plain.encode()).decode())
    status = {
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checked": len(uniq),
        "alive": len(alive),
        "kept": len(best),
        "top": [{"proto": c["proto"], "port": c["port"], "ms": c["ms"]} for c in best[:10]],
    }
    with open("status.json", "w", encoding="utf-8") as f:
        json.dump(status, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
