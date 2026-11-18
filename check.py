#!/usr/bin/env python3
"""Скачивает публичные списки v2ray-конфигов, проверяет какие серверы РЕАЛЬНО работают,
и сохраняет лучшие в sub_plain.txt / sub.txt (base64) плюс status.json.

Две стадии проверки:

  Стадия 1 (быстрая): TCP-коннект (+ TLS-рукопожатие). Отсеивает мёртвые адреса.
  Стадия 2 (настоящая): поднимает sing-box с этим конфигом и пробует реально
                        пройти через него в интернет (https://www.gstatic.com/generate_204).
                        Это отсеивает конфиги, у которых протух UUID/пароль/путь,
                        хотя порт открыт.

Если стадия 2 не смогла прогнаться (не скачался sing-box, упал раннер),
скрипт автоматически откатывается на результаты стадии 1 — подписка никогда
не останется пустой из-за поломки проверялки.

Запуск:  python check.py
"""

import asyncio
import base64
import ipaddress
import json
import os
import random
import re
import shutil
import ssl
import tarfile
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote, urlsplit

SOURCES = [
    # первым идёт список, собранный под РФ — он приоритетнее
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless.txt",
    "https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/config/protocols/vless.txt",
]

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")

# Протоколы, которые в РФ душатся DPI сильнее всего. У них TCP-порт открыт и
# «пинг» в клиенте есть, а реальный трафик не проходит — поэтому в подписку
# они не попадают вовсе.
SKIP_PROTOCOLS = {"ss", "ssr"}

MAX_CANDIDATES = 6000   # сколько конфигов проверять на стадии 1
TCP_CONCURRENCY = 400   # одновременных TCP-проверок
PROXY_TEST = 400        # сколько лучших по TCP гнать на стадию 2 (реальный трафик)
PROXY_CONCURRENCY = 40  # сколько sing-box крутить одновременно
KEEP = 150              # сколько оставить в подписке
RU_EXTRA = 20           # сколько серверов из списка под РФ добавить без проверки трафиком
TIMEOUT = 4.0           # сек на TCP-проверку
PROXY_TIMEOUT = 8       # сек на попытку пройти через прокси
SINGBOX_VERSION = "1.10.7"
TEST_URL = "https://www.gstatic.com/generate_204"

UA = "Mozilla/5.0 (check.py)"


# ---------------------------------------------------------------- утилиты

def b64decode_loose(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


LINK_RE = re.compile(r"(?<![A-Za-z0-9])(?:vless|vmess|trojan|ss)://[^\s\"'<>`,]+")


def find_links(text):
    return LINK_RE.findall(text)


def split_lines(text):
    """Достаёт ссылки из любого вида списка: обычный текст, base64, base64 с заголовком."""
    links = find_links(text)
    if links:
        return links
    body = [ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.lstrip().startswith(("#", "//"))]
    for blob in ("".join(body), None):
        try:
            if blob is None:
                decoded = "\n".join(b64decode_loose(ln).decode("utf-8", errors="ignore") for ln in body)
            else:
                decoded = b64decode_loose(blob).decode("utf-8", errors="ignore")
        except Exception:
            continue
        links = find_links(decoded)
        if links:
            return links
    return []


def is_public(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        return host not in ("localhost",) and "." in host


def q1(q, key, default=None):
    v = q.get(key)
    return unquote(v[0]) if v else default


# ---------------------------------------------------------------- разбор ссылок

def parse(link):
    """Возвращает dict с полями proto/host/port/sni или None."""
    try:
        proto = link.split("://", 1)[0]
        if proto == "vmess":
            raw = link[8:].split("#", 1)[0]
            d = json.loads(b64decode_loose(raw).decode("utf-8", errors="ignore"))
            host = d.get("add")
            port = int(d.get("port"))
            tls_on = str(d.get("tls", "")).lower() in ("tls", "reality", "1", "true")
            sni = (d.get("sni") or d.get("host") or host) if tls_on else None
            return {"proto": proto, "host": host, "port": port, "sni": sni}
        if proto == "ss":
            body = link[5:].split("#", 1)[0].split("?", 1)[0]
            if "@" not in body:
                body = b64decode_loose(body).decode("utf-8", errors="ignore")
            hostport = body.rsplit("@", 1)[1]
            host, port = hostport.rsplit(":", 1)
            return {"proto": proto, "host": host.strip("[]"), "port": int(port), "sni": None}
        u = urlsplit(link)
        q = {k: v for k, v in parse_qs(u.query).items()}
        host, port = u.hostname, u.port
        if not host or not port:
            return None
        sec = q1(q, "security", "tls" if proto == "trojan" else "none")
        sni = (q1(q, "sni") or q1(q, "host") or host) if sec in ("tls", "reality") else None
        return {"proto": proto, "host": host, "port": int(port), "sni": sni}
    except Exception:
        return None


# ---------------------------------------------------------------- стадия 1: TCP

async def tcp_check(sem, host, port, sni):
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


async def tcp_stage(candidates):
    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    tasks = [tcp_check(sem, c["host"], c["port"], c["sni"]) for c in candidates]
    results = await asyncio.gather(*tasks)
    alive = [{**c, "tcp_ms": ms} for c, ms in zip(candidates, results) if ms is not None]
    alive.sort(key=lambda c: c["tcp_ms"])
    return alive


# ---------------------------------------------------------------- стадия 2: sing-box

def _tls_block(sec, sni, fp=None, pbk=None, sid=None, alpn=None):
    tls = {"enabled": True, "server_name": sni}
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if alpn:
        tls["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
    if sec == "reality":
        if not pbk:
            return None
        tls["reality"] = {"enabled": True, "public_key": pbk, "short_id": sid or ""}
        tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
    return tls


def _transport(net, path=None, host_hdr=None, svc=None):
    net = (net or "tcp").lower()
    if net in ("tcp", "none", "raw", ""):
        return None
    if net == "ws":
        t = {"type": "ws", "path": path or "/"}
        if host_hdr:
            t["headers"] = {"Host": host_hdr}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": svc or ""}
    if net in ("http", "h2", "h2c"):
        t = {"type": "http", "path": path or "/"}
        if host_hdr:
            t["host"] = [host_hdr]
        return t
    return False  # неизвестный транспорт (kcp, quic, xhttp…) — не умеем, пропускаем


def singbox_outbound(link):
    """Превращает ссылку в outbound для sing-box. None = не поддерживаем."""
    try:
        proto = link.split("://", 1)[0]
        u = urlsplit(link)

        if proto == "vmess":
            d = json.loads(b64decode_loose(link[8:].split("#", 1)[0]).decode("utf-8", errors="ignore"))
            host, port = d.get("add"), int(d.get("port"))
            tls_on = str(d.get("tls", "")).lower() in ("tls", "reality", "1", "true")
            tr = _transport(d.get("net"), d.get("path"), d.get("host"), d.get("path"))
            if tr is False:
                return None
            ob = {
                "type": "vmess",
                "tag": "proxy",
                "server": host,
                "server_port": port,
                "uuid": d.get("id"),
                "security": d.get("scy") or "auto",
                "alter_id": int(d.get("aid") or 0),
            }
            if tls_on:
                tls = _tls_block("tls", d.get("sni") or d.get("host") or host)
                if tls:
                    ob["tls"] = tls
            if tr:
                ob["transport"] = tr
            return ob

        if proto == "ss":
            body = link[5:].split("#", 1)[0]
            query = ""
            if "?" in body:
                body, query = body.split("?", 1)
            if "@" in body:
                creds, hostport = body.rsplit("@", 1)
                if ":" in creds and not re.fullmatch(r"[A-Za-z0-9+/=_-]+", creds):
                    method, password = creds.split(":", 1)
                else:
                    dec = b64decode_loose(creds).decode("utf-8", errors="ignore")
                    method, password = dec.split(":", 1)
            else:
                dec = b64decode_loose(body).decode("utf-8", errors="ignore")
                creds, hostport = dec.rsplit("@", 1)
                method, password = creds.split(":", 1)
            if "plugin" in query:
                return None
            host, port = hostport.rsplit(":", 1)
            return {
                "type": "shadowsocks",
                "tag": "proxy",
                "server": host.strip("[]"),
                "server_port": int(port),
                "method": method.strip(),
                "password": password,
            }

        q = {k: v for k, v in parse_qs(u.query).items()}
        host, port = u.hostname, u.port
        if not host or not port:
            return None

        if proto == "trojan":
            tr = _transport(q1(q, "type"), q1(q, "path"), q1(q, "host"), q1(q, "serviceName"))
            if tr is False:
                return None
            tls = _tls_block("tls", q1(q, "sni") or q1(q, "host") or host,
                            q1(q, "fp"), None, None, q1(q, "alpn"))
            if not tls:
                return None
            ob = {
                "type": "trojan",
                "tag": "proxy",
                "server": host,
                "server_port": int(port),
                "password": unquote(u.username or ""),
                "tls": tls,
            }
            if tr:
                ob["transport"] = tr
            return ob

        # vless
        sec = (q1(q, "security", "none") or "none").lower()
        if sec not in ("none", "tls", "reality"):
            return None
        tr = _transport(q1(q, "type"), q1(q, "path"), q1(q, "host"), q1(q, "serviceName"))
        if tr is False:
            return None
        ob = {
            "type": "vless",
            "tag": "proxy",
            "server": host,
            "server_port": int(port),
            "uuid": unquote(u.username or ""),
        }
        flow = q1(q, "flow")
        if flow:
            ob["flow"] = flow
        if sec in ("tls", "reality"):
            tls = _tls_block(sec, q1(q, "sni") or q1(q, "host") or host,
                             q1(q, "fp"), q1(q, "pbk"), q1(q, "sid"), q1(q, "alpn"))
            if not tls:
                return None
            ob["tls"] = tls
        if tr:
            ob["transport"] = tr
        return ob
    except Exception:
        return None


def build_config(link, port):
    ob = singbox_outbound(link)
    if not ob:
        return None
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [ob, {"type": "direct", "tag": "direct"}],
    }


def download_singbox(workdir):
    """Качает sing-box под linux x64. Возвращает путь к бинарю или None."""
    candidates = [
        f"https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}"
        f"/sing-box-{SINGBOX_VERSION}-linux-amd64.tar.gz",
    ]
    try:
        rel = json.loads(http_get("https://api.github.com/repos/SagerNet/sing-box/releases/latest"))
        tag = rel.get("tag_name", "")
        if tag:
            v = tag.lstrip("v")
            candidates.append(
                f"https://github.com/SagerNet/sing-box/releases/download/{tag}"
                f"/sing-box-{v}-linux-amd64.tar.gz"
            )
    except Exception:
        pass

    for url in candidates:
        tgz = os.path.join(workdir, "sb.tar.gz")
        try:
            print(f"Скачиваю sing-box: {url}")
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=120) as r, open(tgz, "wb") as f:
                shutil.copyfileobj(r, f)
            with tarfile.open(tgz) as t:
                t.extractall(workdir)
            for root, _dirs, files in os.walk(workdir):
                if "sing-box" in files:
                    path = os.path.join(root, "sing-box")
                    os.chmod(path, 0o755)
                    return path
        except Exception as e:
            print(f"  не вышло: {str(e)[:120]}")
    return None


async def _port_open(port, timeout=0.4):
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout)
        w.close()
        return True
    except Exception:
        return False


async def _curl_code(port):
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", os.devnull, "-w", "%{http_code}",
            "--max-time", str(PROXY_TIMEOUT), "--connect-timeout", "5",
            "-x", f"socks5h://127.0.0.1:{port}", TEST_URL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), PROXY_TIMEOUT + 4)
        return out.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


async def proxy_test_one(item, port, sb_bin, tmpdir):
    cfg = build_config(item["link"], port)
    if not cfg:
        return None
    cfg_path = os.path.join(tmpdir, f"c{port}.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            sb_bin, "run", "-c", cfg_path,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        up = False
        for _ in range(40):  # до ~2 сек на подъём
            await asyncio.sleep(0.05)
            if await _port_open(port):
                up = True
                break
        if not up:
            return None
        t0 = time.perf_counter()
        code = await _curl_code(port)
        ms = int((time.perf_counter() - t0) * 1000)
        if code in ("204", "200"):
            return {**item, "proxy_ms": ms}
        return None
    except Exception:
        return None
    finally:
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        try:
            os.remove(cfg_path)
        except Exception:
            pass


async def proxy_stage(items, sb_bin, tmpdir):
    ok = []
    for start in range(0, len(items), PROXY_CONCURRENCY):
        batch = items[start:start + PROXY_CONCURRENCY]
        tasks = [proxy_test_one(it, 20000 + i, sb_bin, tmpdir) for i, it in enumerate(batch)]
        got = await asyncio.gather(*tasks)
        passed = [g for g in got if g]
        ok.extend(passed)
        print(f"  стадия 2: {start + len(batch)}/{len(items)} проверено, рабочих {len(ok)}")
    ok.sort(key=lambda c: c["proxy_ms"])
    return ok


# ---------------------------------------------------------------- main

def collect():
    seen, candidates, src_info, prio = set(), [], [], 0
    skipped = {}
    for url in SOURCES:
        short = url.split("githubusercontent.com/")[-1][:70]
        ru = "russia" in url.lower()  # список собран под РФ — такие серверы важнее
        try:
            text = http_get(url)
            lines = split_lines(text)
            print(f"{len(lines):6d}  {url}")
            src_info.append({"src": short, "bytes": len(text), "links": len(lines)})
        except Exception as e:
            print(f"ОШИБКА  {url}: {e}")
            src_info.append({"src": short, "error": str(e)[:120]})
            prio += 1
            continue
        for ln in lines:
            if ln in seen:
                continue
            seen.add(ln)
            p = parse(ln)
            if not p or not is_public(p["host"]):
                continue
            if p["proto"] in SKIP_PROTOCOLS:
                skipped[p["proto"]] = skipped.get(p["proto"], 0) + 1
                continue
            candidates.append({**p, "link": ln, "prio": prio, "ru": ru})
        prio += 1

    # уникальные по host:port, но приоритет — первым источникам (список под РФ)
    uniq, keys = [], set()
    for c in candidates:
        k = (c["host"], c["port"])
        if k in keys:
            continue
        keys.add(k)
        uniq.append(c)

    # берём срез: сначала приоритетные источники, остальное добираем случайно
    head = [c for c in uniq if c["prio"] <= 1]
    tail = [c for c in uniq if c["prio"] > 1]
    random.shuffle(tail)
    uniq = (head + tail)[:MAX_CANDIDATES]
    if skipped:
        print(f"Пропущено по протоколу (душится DPI): {skipped}")
    return uniq, src_info


def write_results(best, mode):
    plain = "\n".join(c["link"] for c in best)
    with open("sub_plain.txt", "w", encoding="utf-8") as f:
        f.write(plain + "\n")
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(plain.encode()).decode())


def order_for_sub(items):
    """Порядок в подписке: сначала конфиги из списка под РФ, внутри группы — по скорости.

    Клиенты (Hiddify, NekoBox) и авто-выбор по пингу берут серверы сверху списка,
    поэтому наверху должно лежать то, что реально работает из России, а не то,
    что быстро отвечает из американского дата-центра.
    """
    def key(c):
        ms = c.get("proxy_ms")
        if ms is None:
            ms = c.get("tcp_ms", 99999)
        return (0 if c.get("ru") else 1, ms)

    return sorted(items, key=key)


def main():
    started = time.time()
    candidates, src_info = collect()
    print(f"К проверке (стадия 1, TCP): {len(candidates)}")

    alive = asyncio.run(tcp_stage(candidates))
    print(f"Стадия 1: TCP отвечает у {len(alive)}")

    proxy_ok, proxy_note = [], ""
    subset = alive[:PROXY_TEST]
    if subset:
        workdir = tempfile.mkdtemp(prefix="sbx")
        try:
            sb_bin = download_singbox(workdir)
            if not sb_bin:
                proxy_note = "sing-box не скачался — оставлены результаты стадии 1"
                print(proxy_note)
            else:
                print(f"Стадия 2 (реальный трафик): проверяю {len(subset)}")
                proxy_ok = asyncio.run(proxy_stage(subset, sb_bin, workdir))
                print(f"Стадия 2: реально работают {len(proxy_ok)}")
        except Exception as e:
            proxy_note = f"стадия 2 упала: {str(e)[:120]}"
            print(proxy_note)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # fail-safe: если реальная проверка ничего не дала — отдаём TCP-результаты
    if len(proxy_ok) >= 20:
        verified = order_for_sub(proxy_ok)
        mode = "proxy"
    else:
        verified = order_for_sub(alive)
        mode = "tcp"
        if not proxy_note:
            proxy_note = "рабочих на стадии 2 меньше 20 — откат на стадию 1"

    # Серверы из списка под РФ проверяем из США — и они часто валятся именно
    # поэтому, хотя из России работают. Такие ставим в начало подписки без
    # проверки трафиком: клиент попробует их первыми.
    ru_extra = [c for c in alive if c.get("ru")][:RU_EXTRA]
    seen_hosts, best = set(), []
    for c in ru_extra + verified:
        key = (c["host"], c["port"])
        if key in seen_hosts:
            continue
        seen_hosts.add(key)
        best.append(c)
        if len(best) >= KEEP:
            break

    ru_in_sub = sum(1 for c in best if c.get("ru"))
    print(f"Итог: режим {mode}, в подписке {len(best)}, из них из списка под РФ: {ru_in_sub}")

    write_results(best, mode)
    status = {
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": mode,
        "note": proxy_note,
        "checked": len(candidates),
        "tcp_alive": len(alive),
        "proxy_tested": len(subset),
        "proxy_alive": len(proxy_ok),
        "alive": len(alive),
        "kept": len(best),
        "ru_in_sub": ru_in_sub,
        "ru_at_top": sum(1 for c in best[:10] if c.get("ru")),
        "seconds": int(time.time() - started),
        "sources": src_info,
        "top": [
            {
                "proto": c["proto"],
                "port": c["port"],
                "ms": c.get("proxy_ms", c.get("tcp_ms")),
                "tcp_ms": c.get("tcp_ms"),
                "ru": bool(c.get("ru")),
            }
            for c in best[:10]
        ],
    }
    with open("status.json", "w", encoding="utf-8") as f:
        json.dump(status, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
