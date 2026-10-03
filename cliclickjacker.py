import asyncio
import httpx
import pandas as pd
import argparse
import webbrowser
import html
import os
import re
from datetime import datetime


class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    DIM    = "\033[2m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

# Bare scheme sources in frame-ancestors allow EVERY origin of that scheme,
# so they are permissive (effectively unprotected), not a restriction.
PERMISSIVE_SCHEME_SOURCES = {"http:", "https:", "ws:", "wss:", "data:", "blob:", "filesystem:"}


def normalize_url(url):
    url = url.strip()
    # Must check the full scheme prefix, not just "http": a host like
    # "httpbin.org" or "http2.example.com" starts with "http" but has no
    # scheme, and would otherwise be sent to the client without one.
    if not url.lower().startswith(("http://", "https://")):
        return "https://" + url
    return url


# ── CSP frame-ancestors parsing ─────────────────────────
def parse_frame_ancestors(policy):
    """
    Extract the frame-ancestors directive's tokens from ONE CSP policy
    string. Tokens are split on whitespace AND commas — a comma can appear
    when multiple CSP headers get merged into one value — and lowercased.
    Returns None if the directive is absent, else the token list (which may
    be empty if the directive was present with no value).
    """
    if not policy:
        return None
    for directive in policy.split(";"):
        directive = directive.strip()
        if directive.lower().startswith("frame-ancestors"):
            rest = directive[len("frame-ancestors"):]
            toks = re.split(r"[\s,]+", rest.strip())
            return [t.strip().lower() for t in toks if t.strip()]
    return None


def classify_frame_ancestors(tokens):
    """
    Classify one frame-ancestors directive:
      'blocked'    -> 'none': no origin may frame the page
      'permissive' -> any origin may frame it ('*', a bare scheme source,
                      or an empty/misconfigured value)
      'restricted' -> only 'self' and/or specific named origins may frame it
    """
    if not tokens:
        return "permissive"                      # present but empty = no restriction
    if "'none'" in tokens or "none" in tokens:
        return "blocked"
    if "*" in tokens:
        return "permissive"
    if any(t in PERMISSIVE_SCHEME_SOURCES for t in tokens):
        return "permissive"                      # e.g. "frame-ancestors https:"
    return "restricted"


def evaluate_clickjacking(xfo, csp_policies):
    """
    Returns (vulnerable: bool, reason: str, evidence: str).

    xfo          : the X-Frame-Options header value (string, may be "").
    csp_policies : list of Content-Security-Policy header values (each a
                   separate policy; a server may send more than one).

    Precedence matches real browsers: if any CSP policy defines
    frame-ancestors, browsers honor it and IGNORE X-Frame-Options. When
    multiple policies define frame-ancestors, every policy must be
    satisfied, so the MOST restrictive one wins — the page is only
    clickjackable if every frame-ancestors directive present is permissive.
    """
    fa_dirs = []
    for pol in (csp_policies or []):
        toks = parse_frame_ancestors(pol)
        if toks is not None:
            fa_dirs.append(toks)

    if fa_dirs:
        classes = [classify_frame_ancestors(t) for t in fa_dirs]
        evidence = "; ".join(
            "frame-ancestors " + (" ".join(t) if t else "(empty)") for t in fa_dirs
        )
        if "blocked" in classes:
            return False, "Protected (CSP frame-ancestors 'none')", evidence
        if "restricted" in classes:
            return False, "Protected (CSP frame-ancestors restricts framing origins)", evidence
        return True, "Vulnerable (CSP frame-ancestors allows any origin)", evidence

    # No CSP frame-ancestors anywhere — fall back to X-Frame-Options
    xfo = (xfo or "").strip()
    if xfo:
        parts = [p.strip().lower() for p in re.split(r"[,\s]+", xfo) if p.strip()]
        if parts and all(p in ("deny", "sameorigin") for p in parts):
            return False, "Protected (X-Frame-Options)", f"X-Frame-Options: {xfo}"
        # ALLOW-FROM (deprecated), ALLOWALL, invalid, or conflicting duplicate
        # headers — none of these are honored as protection by modern browsers.
        return True, (f"Vulnerable (X-Frame-Options value '{xfo}' is "
                      f"deprecated/invalid/ignored by modern browsers)"), f"X-Frame-Options: {xfo}"

    return True, "Vulnerable (no X-Frame-Options or CSP frame-ancestors header)", "No relevant headers found"


# ── Scan logic ───────────────────────────────────────────
async def scan_target(url, client, timeout, semaphore):
    url = normalize_url(url)
    async with semaphore:
        try:
            res = await client.get(url, headers=HEADERS, timeout=timeout, follow_redirects=True)
            # Read ALL CSP policies separately (a server may send several);
            # merging them into one string breaks directive parsing.
            csp_policies = res.headers.get_list("content-security-policy")
            xfo = res.headers.get("x-frame-options", "")
            vulnerable, reason, evidence = evaluate_clickjacking(xfo, csp_policies)

            return {
                "url": url,
                "final_url": str(res.url),
                "status_code": res.status_code,
                "status": "Vulnerable" if vulnerable else "Not Vulnerable",
                "reason": reason,
                "evidence": evidence,
            }

        except httpx.TimeoutException:
            return {"url": url, "final_url": url, "status_code": None,
                     "status": "Error", "reason": "Request timed out", "evidence": ""}
        except httpx.ConnectError:
            return {"url": url, "final_url": url, "status_code": None,
                     "status": "Error", "reason": "Connection failed", "evidence": ""}
        except Exception as e:
            return {"url": url, "final_url": url, "status_code": None,
                     "status": "Error", "reason": str(e), "evidence": ""}


# ── Load targets ─────────────────────────────────────────
def load_targets(file_path):
    if file_path.endswith(".txt"):
        with open(file_path) as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    elif file_path.endswith(".csv"):
        df = pd.read_csv(file_path)
        urls = df.iloc[:, 0].dropna().astype(str).tolist()

    elif file_path.endswith(".xlsx"):
        df = pd.read_excel(file_path)
        urls = df.iloc[:, 0].dropna().astype(str).tolist()

    else:
        raise Exception("Unsupported file format (use .txt, .csv, or .xlsx)")

    return urls


# ── Async scan with bounded concurrency + progress ────────
async def run_scan(urls, concurrency=20, timeout=8.0, verify=True):
    # Normalize + de-dupe on the NORMALIZED form (so "example.com" and
    # "https://example.com" aren't scanned twice), preserving input order.
    seen = set()
    targets = []
    for u in urls:
        n = normalize_url(u)
        if n not in seen:
            seen.add(n)
            targets.append(n)

    semaphore = asyncio.Semaphore(concurrency)
    results = []
    done = 0
    total = len(targets)

    async with httpx.AsyncClient(verify=verify) as client:
        tasks = [asyncio.create_task(scan_target(u, client, timeout, semaphore)) for u in targets]
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
            done += 1
            if total > 1 and (done % 10 == 0 or done == total):
                print(f"[i] Progress: {done}/{total}", end="\r" if done != total else "\n")

    # Restore input order. Keys are normalized URLs, matching r["url"].
    order = {u: i for i, u in enumerate(targets)}
    results.sort(key=lambda r: order.get(r["url"], len(targets)))
    return results


# ── Terminal output ───────────────────────────────────────
def print_results(results, open_vuln=False):
    vuln_count = sum(1 for r in results if r["status"] == "Vulnerable")
    safe_count = sum(1 for r in results if r["status"] == "Not Vulnerable")
    error_count = sum(1 for r in results if r["status"] == "Error")

    for r in results:
        if r["status"] == "Vulnerable":
            print(f"{C.RED}{C.BOLD}[ VULNERABLE ]{C.RESET}  {r['url']}  {C.DIM}- {r['reason']}{C.RESET}")
            if open_vuln:
                webbrowser.open(r["final_url"] or r["url"])
        elif r["status"] == "Not Vulnerable":
            print(f"{C.GREEN}{C.BOLD}[ SAFE       ]{C.RESET}  {r['url']}  {C.DIM}- {r['reason']}{C.RESET}")
        else:
            print(f"{C.YELLOW}{C.BOLD}[ ERROR      ]{C.RESET}  {r['url']}  {C.DIM}- {r['reason']}{C.RESET}")

    print()
    print(f"Summary: {C.RED}{vuln_count} vulnerable{C.RESET}, {C.GREEN}{safe_count} safe{C.RESET}, {C.YELLOW}{error_count} error(s){C.RESET}  (of {len(results)} total)")


# ── TXT report ─────────────────────────────────────────────
def generate_txt(results, filename):
    vuln_count = sum(1 for r in results if r["status"] == "Vulnerable")
    safe_count = sum(1 for r in results if r["status"] == "Not Vulnerable")
    error_count = sum(1 for r in results if r["status"] == "Error")

    lines = []
    lines.append("Clickjacking Scan Report")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)
    lines.append(f"Vulnerable : {vuln_count}")
    lines.append(f"Safe       : {safe_count}")
    lines.append(f"Errors     : {error_count}")
    lines.append(f"Total      : {len(results)}")
    lines.append("")

    for r in results:
        lines.append("-" * 60)
        lines.append(f"URL       : {r['url']}")
        if r["final_url"] != r["url"]:
            lines.append(f"Final URL : {r['final_url']}  (redirected)")
        if r["status_code"] is not None:
            lines.append(f"Status    : {r['status_code']}")
        lines.append(f"Result    : {r['status']}")
        lines.append(f"Reason    : {r['reason']}")
        if r["evidence"]:
            lines.append(f"Evidence  : {r['evidence']}")
        lines.append("")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[+] Report saved: {filename}")


# ── HTML report ────────────────────────────────────────────
def generate_html(results, filename):
    vuln_count = sum(1 for r in results if r["status"] == "Vulnerable")
    safe_count = sum(1 for r in results if r["status"] == "Not Vulnerable")
    error_count = sum(1 for r in results if r["status"] == "Error")

    rows = []
    for r in results:
        if r["status"] == "Vulnerable":
            status_html = '<span class="vuln">Vulnerable</span>'
        elif r["status"] == "Not Vulnerable":
            status_html = '<span class="safe">Safe</span>'
        else:
            status_html = '<span class="error">Error</span>'

        # Escape everything that originates from the target or the input.
        # evidence comes straight from the scanned server's CSP/XFO header,
        # so it is attacker-influenceable and MUST NOT be trusted as HTML.
        u = r["url"]
        if u.lower().startswith(("http://", "https://")):
            url_html = f'<a href="{html.escape(u, quote=True)}" target="_blank" rel="noopener noreferrer">{html.escape(u)}</a>'
        else:
            url_html = html.escape(u)
        code_html = html.escape(str(r["status_code"])) if r["status_code"] is not None else "-"

        rows.append(f"""
        <tr>
            <td>{url_html}</td>
            <td>{code_html}</td>
            <td>{status_html}</td>
            <td>{html.escape(str(r['reason']))}</td>
            <td class="evidence">{html.escape(str(r['evidence']))}</td>
        </tr>""")

    generated = html.escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    doc = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Clickjacking Report</title>
<style>
    body {{ font-family: Arial, sans-serif; background: #0f172a; color: white; padding: 20px; }}
    h2 {{ text-align: center; }}
    .summary {{ text-align: center; margin-bottom: 1.5rem; color: #94a3b8; }}
    .summary span {{ margin: 0 1rem; }}
    table {{ width: 90%; margin: 20px auto; border-collapse: collapse; }}
    th, td {{ border: 1px solid #334155; padding: 10px; text-align: left; font-size: 0.9rem; }}
    th {{ background: #1e293b; }}
    .vuln  {{ color: #f87171; font-weight: bold; }}
    .safe  {{ color: #4ade80; font-weight: bold; }}
    .error {{ color: #fbbf24; font-weight: bold; }}
    .evidence {{ color: #94a3b8; font-family: monospace; font-size: 0.8rem; word-break: break-all; }}
    a {{ color: #38bdf8; text-decoration: none; }}
</style>
</head>
<body>

<h2>Clickjacking Scan Report</h2>
<div class="summary">
    <span><strong>Vulnerable:</strong> {vuln_count}</span>
    <span><strong>Safe:</strong> {safe_count}</span>
    <span><strong>Errors:</strong> {error_count}</span>
    <span><strong>Generated:</strong> {generated}</span>
</div>

<table>
    <tr>
        <th>Target URL</th>
        <th>HTTP Status</th>
        <th>Result</th>
        <th>Reason</th>
        <th>Evidence</th>
    </tr>
    {"".join(rows)}
</table>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(doc)
    print(f"[+] Report saved: {filename}")


def save_report(results, filename):
    if filename.lower().endswith(".html"):
        generate_html(results, filename)
    else:
        generate_txt(results, filename)


# ── Clickjacking PoC generation ────────────────────────────
_POC_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Clickjacking PoC - __URL_TEXT__</title>
<style>
  body { font-family: Arial, sans-serif; margin: 0; }
  .banner { background: #b91c1c; color: #fff; padding: 10px 16px; font-size: 14px; }
  .wrap { position: relative; }
  /* opacity < 1 so the frame is visibly rendered for the report; a real
     attack would set opacity:1 and overlay decoy UI on top. */
  iframe { width: 100%; height: 90vh; border: 0; opacity: 0.6; }
  .overlay { position: absolute; top: 120px; left: 60px; background: rgba(255,0,0,.15);
             border: 2px dashed red; padding: 14px; font-weight: bold; pointer-events: none; }
</style>
</head>
<body>
<div class="banner">
  Clickjacking PoC — if the target page renders in the frame below, it is missing
  framing protection (X-Frame-Options / CSP frame-ancestors). Target: __URL_TEXT__
</div>
<div class="wrap">
  <div class="overlay">Attacker decoy UI would sit here</div>
  <iframe src="__URL_SRC__"></iframe>
</div>
</body>
</html>"""


def generate_pocs(results, out_dir):
    vuln = [r for r in results if r["status"] == "Vulnerable"]
    if not vuln:
        print("[i] No vulnerable targets — no PoC files generated.")
        return
    os.makedirs(out_dir, exist_ok=True)
    for r in vuln:
        target = r["final_url"] or r["url"]
        host = re.sub(r"[^A-Za-z0-9._-]", "_", target.split("://")[-1])[:80] or "target"
        path = os.path.join(out_dir, host + ".html")
        doc = (_POC_TEMPLATE
               .replace("__URL_SRC__", html.escape(target, quote=True))
               .replace("__URL_TEXT__", html.escape(target)))
        with open(path, "w", encoding="utf-8") as f:
            f.write(doc)
    print(f"[+] {len(vuln)} clickjacking PoC file(s) written to: {out_dir}/")
    print(f"[i] Open them in a browser — if the target renders in the frame, framing is confirmed.")


# ── Main ───────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Clickjacking Scanner CLI")

    parser.add_argument("-u", "--url", help="Single URL")
    parser.add_argument("-f", "--file", help="File with URLs (.txt, .csv, .xlsx)")
    parser.add_argument("-o", "--output", help="Save report (.txt or .html, based on extension)")
    parser.add_argument("--open", action="store_true", help="Open vulnerable sites in browser")
    parser.add_argument("--poc", nargs="?", const="clickjack_poc", metavar="DIR",
                        help="Write an iframe PoC HTML for each vulnerable target "
                             "(default dir: clickjack_poc)")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS certificate verification (for targets with bad certs)")
    parser.add_argument("--concurrency", type=int, default=20, metavar="N",
                        help="Max concurrent requests (default: 20)")
    parser.add_argument("--timeout", type=float, default=8.0, metavar="S",
                        help="Request timeout in seconds (default: 8.0)")

    args = parser.parse_args()

    if not args.url and not args.file:
        print("[-] Provide --url or --file")
        return

    if args.url:
        urls = [args.url]
    else:
        urls = load_targets(args.file)

    if not urls:
        print("[-] No URLs found to scan")
        return

    print(f"[i] Scanning {len(urls)} target(s) (concurrency={args.concurrency}, timeout={args.timeout}s"
          f"{', TLS verify OFF' if args.insecure else ''})")
    results = asyncio.run(run_scan(urls, concurrency=args.concurrency,
                                   timeout=args.timeout, verify=not args.insecure))

    print_results(results, args.open)

    if args.output:
        save_report(results, args.output)

    if args.poc:
        generate_pocs(results, args.poc)


if __name__ == "__main__":
    main()
