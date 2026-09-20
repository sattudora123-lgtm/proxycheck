# proxycheck

A small async proxy checker written in Python. Feed it a list of proxies and it tells you which ones work, how fast they are, and how much they reveal about you.

## Features

- Checks hundreds of proxies concurrently (`httpx` + `asyncio`)
- Per-proxy result: alive/dead, latency, exit IP, anonymity level
- Anonymity levels: `transparent` (your real IP leaks), `anonymous` (IP hidden, but proxy headers are visible), `elite` (no obvious proxy signals)
- Hard per-proxy deadline, so stuck proxies can't hang the run
- Live progress counter, JSON output sorted by latency

## Install

```bash
git clone https://github.com/YOUR_USERNAME/proxycheck.git
cd proxycheck
python -m venv venv
# Windows: venv\Scripts\activate    macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
```

For SOCKS proxies: `pip install "httpx[socks]"`

## Usage

Put one proxy per line in `proxies.txt`:

```
1.2.3.4:8080
http://user:pass@1.2.3.4:8080
socks5://1.2.3.4:1080
```

Run it:

```bash
python proxycheck.py proxies.txt --out results.json --timeout 5 --concurrency 100
```

| Flag | Default | What it does |
|---|---|---|
| `--timeout` | 8 | Max seconds per proxy (hard cap) |
| `--concurrency` | 50 | How many proxies to test at once |
| `--out` | results.json | Output file |
| `--alive-only` | off | Only save working proxies |
| `--url` | httpbin.org/get | Echo endpoint (must return httpbin-style JSON) |

## Example output

```
checking 200 proxies (concurrency=100)...
checked 200/200 | alive: 4
  1644 ms  elite       http://95.211.174.135:3128
  1730 ms  elite       http://1.231.81.166:3128
  1975 ms  elite       http://43.134.16.198:8080

alive: 4  dead: 196
saved -> results.json
```

Each result in the JSON looks like:

```json
{"proxy": "http://1.2.3.4:3128", "alive": true, "latency_ms": 1644, "anonymity": "elite", "exit_ip": "1.2.3.4"}
```

Dead proxies include an `error` field (for example `TimeoutError`, `ProxyError`).

## Known limitations

- Anonymity detection is header-based, using what httpbin echoes back. "Elite" means no obvious signs, not undetectable. Sites can still use TLS/behavioral fingerprinting.
- Only tested with HTTP proxies so far. SOCKS support depends on `httpx[socks]` and is untested.
- All requests go through httpbin.org, so a third-party service sees your test traffic. Use `--url` to point at your own echo endpoint.
- Free public proxies are mostly dead or slow (about 2% alive in my tests). Some log or tamper with traffic, so never send logins or personal data through them.

## Responsible use

Only test proxies you're allowed to use, and only send requests you're allowed to send.

## License

MIT
