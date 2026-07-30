#!/usr/bin/env python3
"""
smblist - SMB share enumerator and file browser

Usage:
  smblist.py <creds> [shares.txt]              - enumerate shares file
  smblist.py <creds> -nxc <nxc_output>         - parse existing nxc output
  smblist.py -nxc <nxc_output>                 - just parse nxc into share list
  smblist.py <creds> -host <host|hosts.txt>    - run nxc then enumerate
  smblist.py <creds> -get <//host/share/file>  - download a specific file
  smblist.py <creds> -gui [-dir <folder>]       - launch web gui (auto-loads smblist_* files)
  smblist.py <creds> [shares.txt] -o out.txt   - output to file and terminal
  smblist.py <creds> -d <DOMAIN> ...           - set/override domain separately from creds

creds: same format as smbclient -U  →  domain/user%pass
  CORP/jsmith%Password123       domain account
  ./localadmin%Pass1            local account  (use . for domain)
  CORP/guest%                   blank password

-d <DOMAIN> can be combined with any mode above, e.g.:
  smblist.py 'jsmith%Password123' -d CORP -gui
  smblist.py 'jsmith%Password123' -d CORP -host hosts.txt
"""

import sys, os, re, subprocess, threading, webbrowser, json, time, queue, urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def parse_creds(c):
    domain = c.split('/')[0] if '/' in c else ''
    userpass = c.split('/')[-1]
    user = userpass.split('%')[0]
    passwd = userpass.split('%')[1] if '%' in userpass else ''
    return domain, user, passwd


def parse_smb_path(path):
    """Split //host/share/dir/file into (share, dir, filename)."""
    parts = path.split('/', 4)
    share = '/'.join(parts[:4]) if len(parts) >= 4 else path
    filepath = '/' + parts[4] if len(parts) > 4 else '/'
    return share, os.path.dirname(filepath), os.path.basename(filepath)


def run_cmd(cmd, use_proxy=False, timeout=None, on_start=None, cancel_check=None):
    """Runs cmd, polling so it can be killed early via cancel_check() (used by the GUI Stop button)."""
    if use_proxy:
        cmd = ['proxychains', '-q'] + cmd
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 env={**os.environ, 'PROXYCHAINS_QUIET_MODE': '1'})
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr=str(e))
    if on_start:
        on_start(proc)
    start = time.time()
    while True:
        try:
            stdout, stderr = proc.communicate(timeout=0.25)
            return subprocess.CompletedProcess(cmd, proc.returncode, stdout=stdout, stderr=stderr)
        except subprocess.TimeoutExpired:
            if cancel_check and cancel_check():
                proc.kill()
                try:
                    stdout, stderr = proc.communicate(timeout=3)
                except Exception:
                    stdout, stderr = '', ''
                return subprocess.CompletedProcess(cmd, -1, stdout=stdout or '', stderr='cancelled')
            if timeout is not None and (time.time() - start) > timeout:
                proc.kill()
                try:
                    stdout, stderr = proc.communicate(timeout=3)
                except Exception:
                    stdout, stderr = '', ''
                return subprocess.CompletedProcess(cmd, 1, stdout=stdout or '', stderr='timed out')


_PERM_RE = re.compile(r'\b((?:READ|WRITE|EXEC)(?:,(?:READ|WRITE|EXEC))*)\b')


def parse_nxc_full(source, is_file=True):
    """Returns (readable_shares, restricted_shares). Restricted = IPC$ or no READ permission."""
    lines = open(source).readlines() if is_file else source.splitlines(keepends=True)
    hostmap = {}
    for line in lines:
        nm = re.search(r'\(name:([^)]+)\)', line)
        dm = re.search(r'\(domain:([^)]+)\)', line)
        im = re.search(r'SMB\s+([\d.]+)', line)
        if im and nm and dm:
            hostmap[im.group(1)] = (nm.group(1).strip() + '.' + dm.group(1).strip()).upper()
    readable = []
    restricted = []
    seen = set()
    for line in lines:
        im = re.search(r'SMB\s+([\d.]+)', line)
        if not im:
            continue
        m = re.match(r'SMB\s+[\d.]+\s+\d+\s+\S+\s+(.+)', line)
        if not m:
            continue
        rest = m.group(1).rstrip('\r\n')
        stripped = rest.strip()
        if not stripped:
            continue
        first_word = stripped.split(None, 1)[0]
        if first_word.startswith('[') or first_word in ('Share', 'Permissions', 'Remark') or first_word.startswith('-'):
            continue
        # netexec pads the share/permissions/remark columns to the width of the
        # longest entry *for that host* — when a share name is at/near that width
        # the gap can shrink to a single space, so we can't split on whitespace
        # runs alone. Anchor on the permissions token itself instead (a fixed,
        # known vocabulary) and treat everything before it as the share name.
        perm_m = _PERM_RE.search(rest)
        if perm_m:
            share = rest[:perm_m.start()].strip()
            has_read = 'READ' in perm_m.group(1).split(',')
        else:
            # no permissions shown at all (blank access) — fall back to splitting
            # on wide gaps to separate the share name from any remark text
            cols = re.split(r'\s{2,}', stripped)
            share = cols[0]
            has_read = False
        if not share:
            continue
        host = hostmap.get(im.group(1), im.group(1))
        share_path = '//' + host + '/' + share
        if share_path in seen:
            continue
        seen.add(share_path)
        if share == 'IPC$' or not has_read:
            restricted.append(share_path)
        else:
            readable.append(share_path)
    return readable, restricted


def parse_nxc(source, is_file=True):
    return parse_nxc_full(source, is_file)[0]


def resolve_host(host, dns_server):
    """Resolve hostname to IP via a specific DNS server using dig."""
    try:
        result = subprocess.run(
            ['dig', '+short', f'@{dns_server}', host],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in reversed(result.stdout.strip().splitlines()):
                line = line.strip()
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                    return line
    except Exception:
        pass
    return host


def smbclient_ls(share, creds, proxy=False, dns_server='', timeout=120, on_start=None, cancel_check=None):
    """Returns (paths, error). error is None on success/empty-but-fine, else a short diagnostic string."""
    if cancel_check and cancel_check():
        return [], None
    share_cmd = share
    if dns_server:
        parts = share.split('/', 3)
        if len(parts) >= 3:
            ip = resolve_host(parts[2], dns_server)
            if ip != parts[2]:
                share_cmd = f'//{ip}/{parts[3]}' if len(parts) > 3 else f'//{ip}/'
    result = run_cmd(['smbclient', share_cmd, '-U', creds, '-c', 'recurse;ls'], proxy, timeout=timeout,
                      on_start=on_start, cancel_check=cancel_check)
    paths = []
    seen = set()
    current_path = ''
    for line in result.stdout.splitlines():
        if line.startswith('\\'):
            current_path = line.strip()
        elif line.strip():
            m = re.match(r'^  (.+?)\s{2,}(\w+)\s', line)
            if not m:
                continue
            name = m.group(1).strip()
            ftype = m.group(2)
            if name in ('.', '..') or 'blocks' in line or ftype.startswith('D'):
                continue
            full = share + current_path.replace('\\', '/') + '/' + name
            if full not in seen:
                seen.add(full)
                paths.append(full)
    err = None
    if not paths:
        stderr = (result.stderr or '').strip()
        if stderr == 'cancelled':
            err = None
        elif stderr == 'timed out':
            err = 'timed out'
        else:
            combined = stderr + '\n' + (result.stdout or '')
            m = re.search(r'NT_STATUS_\w+', combined)
            if m:
                err = m.group(0)
            elif stderr:
                err = stderr.splitlines()[-1][:120]
    return paths, err


def run_smblist(shares, creds, outfile=None, proxy=False):
    """Returns the number of paths found. Only creates/writes outfile if something is actually found."""
    fh = None
    found = 0
    try:
        for share in shares:
            share = share.strip()
            if not share:
                continue
            paths, err = smbclient_ls(share, creds, proxy)
            if not paths:
                reason = err or 'timeout, access denied, or empty'
                print(f'No files found ({reason}): {share}', file=sys.stderr)
            for p in paths:
                print(p)
                if outfile:
                    if fh is None:
                        fh = open(outfile, 'w')
                    fh.write(p + '\n')
                found += 1
    finally:
        if fh:
            fh.close()
    return found


def download_file(fullpath, creds, proxy=False):
    share, d, fname = parse_smb_path(fullpath)
    print(f'Downloading: {fname}')
    print(f'From: {share}{d}')
    run_cmd(['smbclient', share, '-U', creds, '-c', f'cd "{d}"; get "{fname}"'], proxy)
    if os.path.exists(fname):
        print(f'Saved: {os.getcwd()}/{fname}')
    else:
        print(f'Failed: {fname}')


def run_host(target, creds, user, passwd, domain, proxy=False):
    safe = target.replace('/', '_')
    outfile = f'smblist_{safe}'
    print(f'Running nxc against {target}', file=sys.stderr)
    result = run_cmd(
        ['netexec', 'smb', target, '-u', user, '-p', passwd, '-d', domain, '--shares'],
        proxy
    )
    shares = parse_nxc(result.stdout, is_file=False)
    if not shares:
        print(f'No readable shares found for {target}', file=sys.stderr)
        return
    found = run_smblist(shares, creds, outfile=outfile, proxy=proxy)
    if found:
        print(f'Done: {outfile} ({found} paths)', file=sys.stderr)
    else:
        print(f'No files found for {target}', file=sys.stderr)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

HTML = """<!DOCTYPE html>
<html><head><meta charset=UTF-8><title>smblist</title>
<style>
:root{
  --bg0:#010409;--bg1:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#2d333b;
  --bd:#30363d;--bd-s:#21262d;
  --tx:#e6edf3;--tx-m:#b1bac4;--tx-s:#9ca3af;--tx-d:#768390;
  --ac:#2f81f7;--ac-m:rgba(47,129,247,.15);--ac-bg:#1a3a6b;--ac-tx:#79b8ff;
  --green:#3fb950;--green-bg:#1a4a2a;
  --yellow:#e3b341;--red:#f85149;--red-bg:#4a1212;
  --ui:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  --mono:'JetBrains Mono','Cascadia Code','Fira Code','Consolas',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--ui);background:var(--bg1);color:var(--tx);height:100vh;display:flex;flex-direction:column;overflow:hidden;font-size:13px}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--bd);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--tx-d)}
/* === toolbar === */
#top{padding:0 14px;border-bottom:1px solid var(--bd-s);display:flex;gap:5px;align-items:center;background:var(--bg2);flex-shrink:0;height:46px;overflow:hidden}
#brand{display:flex;align-items:center;gap:9px;margin-right:6px;flex-shrink:0}
#brand-mark{width:26px;height:26px;border-radius:7px;background:linear-gradient(135deg,var(--ac) 0%,#1c56b0 100%);display:flex;align-items:center;justify-content:center;color:#fff;flex-shrink:0;box-shadow:0 1px 2px rgba(0,0,0,.35),inset 0 1px 0 rgba(255,255,255,.12)}
#brand-mark svg{width:14px;height:14px;display:block}
#brand-name{font-size:13.5px;font-weight:700;color:var(--tx);letter-spacing:-.01em}
.t-sep{width:1px;background:var(--bd-s);height:22px;margin:0 3px;flex-shrink:0}
.t-lbl{font-size:11px;color:var(--tx-d);white-space:nowrap;flex-shrink:0;font-weight:500}
.t-grp{display:flex;align-items:center;gap:4px;flex-shrink:0}
.tbi{background:var(--bg1);border:1px solid var(--bd);color:var(--tx);padding:5px 9px;font-family:var(--ui);font-size:12px;border-radius:6px;outline:none;transition:border-color .15s,box-shadow .15s}
.tbi:focus{border-color:var(--ac);box-shadow:0 0 0 3px var(--ac-m)}
.tbi::placeholder{color:var(--tx-d)}
#hostinput{width:150px}
.btn{background:var(--bg3);border:1px solid var(--bd);color:var(--tx-m);padding:5px 12px;cursor:pointer;font-family:var(--ui);font-size:12px;border-radius:6px;transition:all .15s;white-space:nowrap;flex-shrink:0;font-weight:500}
.btn:hover{background:var(--bg4);border-color:var(--tx-d);color:var(--tx)}
.btn.active{background:var(--ac-bg);border-color:var(--ac);color:var(--ac-tx)}
.btn-accent{background:var(--ac-bg);border-color:var(--ac);color:var(--ac-tx)}
.btn-accent:hover{background:var(--ac);color:#fff}
.btn-danger{background:var(--bg3);border-color:rgba(248,81,73,.35);color:var(--red)}
.btn-danger:hover{background:var(--red);border-color:var(--red);color:#fff}
.cb-lbl{font-size:12px;color:var(--tx-m);display:flex;align-items:center;gap:5px;cursor:pointer;white-space:nowrap;flex-shrink:0;font-weight:500}
.cb-lbl input[type=checkbox]{accent-color:var(--ac);cursor:pointer;width:13px;height:13px}

/* === jobs strip === */
#jobspanel{padding:6px 14px;border-bottom:1px solid var(--bd-s);background:var(--bg0);flex-shrink:0;display:none;flex-direction:column;gap:0}
.jlbl{font-size:11px;color:var(--tx-d);font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.job{font-size:11px;padding:2px 10px;border-radius:20px;border:1px solid var(--bd-s);background:var(--bg2);display:inline-flex;align-items:center;gap:6px}
.jhost{color:var(--ac-tx);font-weight:600}
.jstat{color:var(--tx-d)}
.jstat.active{color:var(--yellow)}
.jstat.done{color:var(--green)}
.jstat.error{color:var(--red)}
.jcount{color:var(--green);font-size:10px}
.jnote{color:var(--red);font-size:10px}
.jcur{color:var(--tx-d);font-size:10px;font-family:var(--mono);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.spinner{display:inline-block;width:9px;height:9px;border:1.5px solid var(--bd);border-top-color:var(--ac);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

#main{display:flex;flex:1;overflow:hidden;min-height:0}

/* === host tree === */
#hosttree{width:275px;border-right:1px solid var(--bd-s);display:flex;flex-direction:column;flex-shrink:0;background:var(--bg2);min-width:120px}
#treeheader{padding:10px 12px 8px;border-bottom:1px solid var(--bd-s);flex-shrink:0;display:flex;align-items:center;justify-content:space-between}
#treeheader span{font-size:10px;font-weight:700;color:var(--tx-d);letter-spacing:.1em;text-transform:uppercase}
#treeheader button{background:none;border:1px solid var(--bd);color:var(--tx-d);padding:3px 9px;cursor:pointer;font-family:var(--ui);font-size:11px;border-radius:5px;font-weight:500;transition:all .15s}
#treeheader button:hover{border-color:var(--ac);color:var(--ac-tx)}
#treebody{flex:1;overflow-y:auto;padding:4px 0}
.tall{padding:6px 12px;cursor:pointer;font-size:12px;color:var(--tx-d);display:flex;align-items:center;gap:6px;margin:2px 6px;border-radius:6px;font-weight:500;transition:background .1s,color .1s}
.tall:hover{background:var(--bg3);color:var(--tx-m)}
.tall.sel{background:var(--ac-bg);color:var(--ac-tx)}
.tallcount{font-size:11px;color:var(--tx-d);margin-left:auto;font-weight:400;font-family:var(--mono)}
.tall.sel .tallcount{color:var(--ac-tx);opacity:.7}
.tgroup{margin:2px 0}
.tghead{padding:5px 8px 5px 4px;display:flex;align-items:center;gap:5px;cursor:pointer;font-size:12px;color:var(--tx-s);user-select:none;border-radius:6px;margin:1px 6px;transition:background .1s;font-weight:500}
.tghead:hover{background:var(--bg3);color:var(--tx-m)}
.tghead.sel .tgname{color:var(--ac-tx)}
.tghead.dragover{background:rgba(47,129,247,.08);outline:1px dashed rgba(47,129,247,.4);outline-offset:-1px}
.tgcaret{font-size:9px;color:var(--tx-d);flex-shrink:0;display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;padding:0;background:none;border:none;cursor:pointer;border-radius:4px;transition:transform .15s,background .1s;margin:-2px 0}
.tgcaret:hover{background:rgba(255,255,255,.07)}
.tgcaret.open{transform:rotate(90deg)}
.tgname{flex:1;overflow:hidden;text-overflow:ellipsis;color:var(--tx-m);font-size:12px}
.tgcount{font-size:10px;color:var(--tx-d);flex-shrink:0;background:var(--bg3);border-radius:10px;padding:1px 6px;border:1px solid var(--bd-s);font-family:var(--mono)}
.tgdots{color:var(--bd);padding:1px 5px;border-radius:4px;flex-shrink:0;font-size:14px;line-height:1;opacity:0;cursor:pointer;transition:opacity .1s}
.tghead:hover .tgdots{opacity:1}
.tgdots:hover{color:var(--tx-m);background:var(--bg4);opacity:1}
.tghosts{padding-left:8px}
.thost{padding:4px 8px 4px 10px;display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px;border-radius:6px;margin:1px 6px;user-select:none;transition:background .1s}
.thost:hover{background:var(--bg3)}
.thost.sel{background:var(--ac-bg)}
.thost.pick{background:rgba(47,129,247,.18);outline:1px solid rgba(47,129,247,.4);outline-offset:-1px}
.thost-cb{width:11px;height:11px;accent-color:var(--ac);cursor:pointer;flex-shrink:0;opacity:0;transition:opacity .1s;margin-right:1px}
.thost:hover .thost-cb,.thost-cb:checked{opacity:1}
#treesel{padding:6px 10px;border-bottom:1px solid var(--bd-s);background:var(--bg3);display:none;align-items:center;gap:6px;flex-shrink:0;flex-wrap:wrap}
#treesel span{font-size:11px;color:var(--tx-m);white-space:nowrap}
#treesel select{background:var(--bg1);border:1px solid var(--bd);color:var(--tx);padding:3px 6px;font-size:11px;border-radius:5px;outline:none;cursor:pointer}
#treesel select:focus{border-color:var(--ac)}
.thost.dragging{opacity:.25}
.thostname{flex:1;color:var(--tx-s);overflow:hidden;text-overflow:ellipsis;font-size:11px;font-family:var(--mono);letter-spacing:-.02em;cursor:grab}
.thost.sel .thostname{color:var(--ac-tx)}
.thostcount{font-size:10px;color:var(--tx-d);flex-shrink:0;min-width:24px;text-align:right;font-family:var(--mono)}
.thost.sel .thostcount{color:var(--ac-tx);opacity:.6}
.thostwrap{margin:0 6px 3px}
.thostwrap>.thost{margin:1px 0}
.trs-list{padding:2px 4px 6px 38px}
.trs-row{display:flex;align-items:center;gap:5px;padding:2px 5px;border-radius:4px}
.trs-row:hover{background:var(--bg3)}
.trs-name{font-size:10px;color:var(--tx-d);font-family:var(--mono);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.trs-readable{color:var(--ac-tx);cursor:pointer}
.trs-readable:hover{color:var(--ac);text-decoration:underline}
.trs-scan{font-size:10px;padding:1px 7px;flex-shrink:0}
.tugzone{margin:8px 6px 2px;border-radius:6px}
.tugzone.dragover{background:rgba(47,129,247,.05);outline:1px dashed rgba(47,129,247,.3);outline-offset:-1px}
.tuglbl{padding:4px 10px;font-size:10px;color:var(--tx-d);font-weight:700;letter-spacing:.08em;text-transform:uppercase;display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--bd-s);margin-top:2px}

/* === panel dividers === */
#htdiv{width:4px;background:var(--bd-s);cursor:col-resize;flex-shrink:0;transition:background .15s}
#htdiv:hover,#htdiv.drag{background:var(--ac)}
#divider{width:4px;background:var(--bd-s);cursor:col-resize;flex-shrink:0;transition:background .15s}
#divider:hover{background:var(--ac)}

/* === path list === */
#left{width:36%;border-right:1px solid var(--bd-s);display:flex;flex-direction:column;min-height:0;min-width:100px;background:var(--bg1)}
#leftbar{padding:10px 10px 8px;border-bottom:1px solid var(--bd-s);background:var(--bg2);flex-shrink:0;display:flex;flex-direction:column;gap:8px}
.lbl{font-size:10px;font-weight:700;color:var(--tx-d);letter-spacing:.08em;text-transform:uppercase;margin-bottom:3px}
#filterpath{background:var(--bg1);border:1px solid var(--bd);color:var(--tx);padding:5px 9px;font-family:var(--ui);font-size:12px;border-radius:6px;outline:none;width:100%;transition:border-color .15s,box-shadow .15s}
#filterpath:focus{border-color:var(--ac);box-shadow:0 0 0 3px var(--ac-m)}
#filterpath::placeholder{color:var(--tx-d)}
#extdrop-wrap{position:relative}
#extbtn{width:100%;background:var(--bg3);border:1px solid var(--bd);color:var(--tx-m);padding:4px 9px;cursor:pointer;font-family:var(--ui);font-size:11px;border-radius:6px;text-align:left;display:flex;justify-content:space-between;align-items:center;transition:all .15s;line-height:1.4}
#extbtn:hover{border-color:var(--tx-d);color:var(--tx)}
#extbtn.active{border-color:var(--ac);color:var(--ac-tx);background:var(--ac-bg)}
#extdrop{position:absolute;top:calc(100% + 4px);left:0;right:0;background:var(--bg2);border:1px solid var(--bd);border-radius:8px;z-index:500;box-shadow:0 8px 24px rgba(0,0,0,.5);display:none;flex-direction:column;min-width:220px}
#extdrop.open{display:flex}
#extsearch{background:var(--bg1);border:none;border-bottom:1px solid var(--bd-s);color:var(--tx);padding:7px 10px;font-family:var(--ui);font-size:11px;outline:none;width:100%;border-radius:8px 8px 0 0;transition:background .15s}
#extsearch:focus{background:var(--bg0)}
#extsearch::placeholder{color:var(--tx-d)}
#extlist{max-height:240px;overflow-y:auto;padding:3px 0}
.ext-row{display:flex;align-items:center;padding:3px 8px;gap:5px;transition:background .08s}
.ext-row:hover{background:var(--bg3)}
.ext-name{font-family:var(--mono);font-size:11px;color:var(--tx-s);flex-shrink:0;white-space:nowrap}
.ext-desc{font-size:10px;color:var(--tx-d);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;margin-left:4px;min-width:0}
.ext-lbl{display:flex;align-items:baseline;flex:1;overflow:hidden;min-width:0;gap:0}
.ext-cnt{font-size:10px;color:var(--tx-d);min-width:28px;text-align:right;font-family:var(--mono);flex-shrink:0}.ext-inc,.ext-exc{width:20px;height:20px;border-radius:4px;border:1px solid var(--bd-s);background:none;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--tx-d);transition:all .1s;flex-shrink:0;font-family:var(--ui);padding:0}
.ext-inc:hover{border-color:var(--green);color:var(--green);background:var(--green-bg)}
.ext-exc:hover{border-color:var(--red);color:var(--red);background:var(--red-bg)}
.ext-inc.on{background:var(--green-bg);border-color:var(--green);color:var(--green)}
.ext-exc.on{background:var(--red-bg);border-color:var(--red);color:var(--red)}
#extfoot{border-top:1px solid var(--bd-s);padding:5px 8px;display:flex;justify-content:space-between;align-items:center;gap:6px}
#extfoot-lbl{font-size:10px;color:var(--tx-d);flex:1}
#extfoot-clear{background:none;border:1px solid var(--bd-s);color:var(--tx-d);padding:2px 8px;border-radius:4px;cursor:pointer;font-size:10px;font-family:var(--ui);transition:all .12s;white-space:nowrap}
#extfoot-clear:hover{border-color:var(--tx-d);color:var(--tx)}
#sharedrop-wrap{position:relative}
#sharebtn{width:100%;background:var(--bg3);border:1px solid var(--bd);color:var(--tx-m);padding:4px 9px;cursor:pointer;font-family:var(--ui);font-size:11px;border-radius:6px;text-align:left;display:flex;justify-content:space-between;align-items:center;transition:all .15s;line-height:1.4}
#sharebtn:hover{border-color:var(--tx-d);color:var(--tx)}
#sharebtn.active{border-color:var(--ac);color:var(--ac-tx);background:var(--ac-bg)}
#sharedrop{position:absolute;top:calc(100% + 4px);left:0;right:0;background:var(--bg2);border:1px solid var(--bd);border-radius:8px;z-index:500;box-shadow:0 8px 24px rgba(0,0,0,.5);display:none;flex-direction:column;min-width:200px}
#sharedrop.open{display:flex}
#sharelist{max-height:200px;overflow-y:auto;padding:3px 0}
#sharefoot{border-top:1px solid var(--bd-s);padding:5px 8px;display:flex;justify-content:space-between;align-items:center;gap:6px}
#sharefoot-lbl{font-size:10px;color:var(--tx-d);flex:1}
#sharefoot-clear{background:none;border:1px solid var(--bd-s);color:var(--tx-d);padding:2px 8px;border-radius:4px;cursor:pointer;font-size:10px;font-family:var(--ui);transition:all .12s;white-space:nowrap}
#sharefoot-clear:hover{border-color:var(--tx-d);color:var(--tx)}
#pathList{flex:1;overflow-y:auto;position:relative;background:var(--bg1)}
.path{padding:3px 14px;cursor:pointer;font-size:11px;color:var(--tx-s);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;position:absolute;left:0;right:0;font-family:var(--mono);letter-spacing:-.02em;transition:color .08s}
.path:hover{background:var(--bg2);color:var(--tx)}
.path.active{background:var(--ac-bg);color:var(--ac-tx)}

/* === file viewer === */
#right{flex:1;background:var(--bg0);display:flex;flex-direction:column;min-height:0;overflow:hidden;min-width:120px}
#rightbar{padding:7px 12px 6px;border-bottom:1px solid var(--bd-s);background:var(--bg2);flex-shrink:0;display:flex;gap:6px;align-items:center}
#rightbar span{font-size:10px;font-weight:700;color:var(--tx-d);letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}
#filtercontent{flex:1;background:var(--bg1);border:1px solid var(--bd);color:var(--tx);padding:5px 9px;font-family:var(--ui);font-size:12px;border-radius:6px;outline:none;transition:border-color .15s,box-shadow .15s}
#filtercontent:focus{border-color:var(--ac);box-shadow:0 0 0 3px var(--ac-m)}
#filtercontent::placeholder{color:var(--tx-d)}
#header{font-size:11px;color:var(--ac-tx);padding:7px 16px;word-break:break-all;border-bottom:1px solid var(--bd-s);background:var(--bg1);flex-shrink:0;font-family:var(--mono);letter-spacing:-.02em;opacity:.85}
#contentarea{flex:1;overflow-y:auto;padding:16px;min-height:0}
#content{font-size:12px;white-space:pre-wrap;word-break:break-all;color:var(--tx-m);line-height:1.7;margin:0;font-family:var(--mono);letter-spacing:-.01em}
#bottom{padding:10px 14px;border-top:1px solid var(--bd-s);flex-shrink:0;display:none}
.dl-btn{background:var(--green-bg);border:1px solid rgba(63,185,80,.3);color:var(--green);padding:6px 16px;cursor:pointer;font-family:var(--ui);font-size:12px;border-radius:6px;font-weight:500;transition:all .15s}
.dl-btn:hover{background:rgba(63,185,80,.2);border-color:var(--green)}

/* === status bar === */
#status{padding:4px 16px;font-size:11px;color:var(--tx-d);background:var(--bg2);border-top:1px solid var(--bd-s);flex-shrink:0;font-weight:500}
#leftfoot{padding:6px 10px;border-top:1px solid var(--bd-s);background:var(--bg2);flex-shrink:0}

/* === misc === */
.hl{background:rgba(227,179,65,.2);color:var(--yellow);border-radius:2px}
.ok{color:var(--green)}.err{color:var(--red)}.warn{color:var(--yellow)}

/* === context menu === */
.cmenu{position:fixed;background:var(--bg3);border:1px solid var(--bd);border-radius:8px;padding:4px 0;z-index:9999;min-width:150px;box-shadow:0 8px 30px rgba(0,0,0,.6),0 2px 8px rgba(0,0,0,.4)}
.cmitem{padding:6px 14px;font-size:12px;color:var(--tx-m);cursor:pointer;white-space:nowrap;transition:background .1s,color .1s;font-weight:500}
.cmitem:hover{background:var(--bg4);color:var(--tx)}
.cmitem.sub{color:var(--tx-d);cursor:default;font-size:10px;padding:5px 14px 2px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
.cmitem.danger{color:#a55}
.cmitem.danger:hover{background:var(--red-bg);color:var(--red)}
.cmsep{height:1px;background:var(--bd-s);margin:3px 0}
/* === modal === */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:10000;display:flex;align-items:center;justify-content:center}
.modal{background:var(--bg2);border:1px solid var(--bd);border-radius:10px;padding:20px;width:420px;max-width:90vw;box-shadow:0 16px 48px rgba(0,0,0,.7);display:flex;flex-direction:column;gap:12px}
.modal-title{font-size:13px;font-weight:700;color:var(--tx);letter-spacing:-.01em}
.modal-sub{font-size:11px;color:var(--tx-d)}
.modal textarea{background:var(--bg1);border:1px solid var(--bd);color:var(--tx);padding:8px 10px;font-family:var(--mono);font-size:11px;border-radius:6px;outline:none;resize:vertical;min-height:160px;line-height:1.6;transition:border-color .15s,box-shadow .15s}
.modal textarea:focus{border-color:var(--ac);box-shadow:0 0 0 3px var(--ac-m)}
.modal textarea::placeholder{color:var(--tx-d)}
.modal-foot{display:flex;gap:8px;justify-content:flex-end}
</style></head>
<body>
<div id=dlmodal style="display:none" class=modal-overlay onclick="if(event.target===this)closeDlModal()">
  <div class=modal>
    <div class=modal-title>Download All Files</div>
    <div class=modal-sub id=dlmodal-sub>Select a destination folder</div>
    <div class=modal-foot>
      <button class=btn onclick=closeDlModal()>Cancel</button>
      <button class=btn onclick=startDlAll(false)>Single Folder</button>
      <button class="btn btn-accent" onclick=startDlAll(true)>Group by File Type</button>
    </div>
  </div>
</div>
<div id=hostmodal style="display:none" class=modal-overlay onclick="if(event.target===this)closeHostModal()">
  <div class=modal>
    <div class=modal-title>Scan Multiple Hosts</div>
    <div class=modal-sub>One host, FQDN, or CIDR per line</div>
    <textarea id=hostlist placeholder="host1.domain.com&#10;host2.domain.com&#10;192.168.1.0/24"></textarea>
    <div class=modal-foot>
      <button class=btn onclick=closeHostModal()>Cancel</button>
      <button class="btn btn-accent" onclick=submitHostList()>Get Shares</button>
    </div>
  </div>
</div>
<div id=promptmodal style="display:none" class=modal-overlay onclick="if(event.target===this)closePromptModal()">
  <div class=modal>
    <div class=modal-title id=promptmodal-title>Rename</div>
    <input type=text class=tbi id=promptmodal-input style="width:100%" onkeydown="if(event.key==='Enter')submitPromptModal()">
    <div class=modal-foot>
      <button class=btn onclick=closePromptModal()>Cancel</button>
      <button class="btn btn-accent" onclick=submitPromptModal()>Save</button>
    </div>
  </div>
</div>
<div id=top>
  <div id=brand>
    <div id=brand-mark><svg viewBox="0 0 24 24" fill=none xmlns="http://www.w3.org/2000/svg">
      <rect x=3 y=3 width=7.5 height=7.5 rx=1.8 fill="currentColor"/>
      <rect x=13.5 y=3 width=7.5 height=7.5 rx=1.8 fill="currentColor" opacity=.5/>
      <rect x=3 y=13.5 width=7.5 height=7.5 rx=1.8 fill="currentColor" opacity=.5/>
      <rect x=13.5 y=13.5 width=7.5 height=7.5 rx=1.8 fill="currentColor"/>
    </svg></div>
    <span id=brand-name>smblist</span>
  </div>
  <div class=t-sep></div>
  <div class=t-grp>
    <span class=t-lbl>Domain:</span>
    <input type=text class=tbi id=hostinput placeholder="FQDN" onkeydown="if(event.key==='Enter')addHost()">
    <button class="btn btn-accent" onclick=addHost()>Get Shares</button>
    <button class=btn onclick=openHostModal() title="Scan a list of hosts">Paste Hosts</button>
    <label class=btn for=hostfileinput title="Import hosts from a file (one per line)" style="display:inline-flex;align-items:center">Import Hosts</label>
    <input type=file id=hostfileinput style="position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0" onchange=handleHostFile(event)>
  </div>
  <div class=t-sep></div>
  <div class=t-grp>
    <span class=t-lbl>DNS:</span>
    <input type=text class=tbi id=dnsinput placeholder="DC IP / FQDN" style="width:130px" oninput=updateDns()>
  </div>
  <div class=t-sep></div>
  <button class="btn active" id=fnbtn onclick=toggleFN()>Filename Only</button>
  <button class=btn id=unbtn onclick=toggleUN()>Unique Names</button>
  <button class=btn onclick=clearRight()>Clear Preview</button>
  <div class=t-sep></div>
  <button class="btn btn-danger" id=stopbtn onclick=stopAll() title="Cancel all queued and running scans">Stop All</button>
</div>
<div id=jobspanel></div>
<div id=main>
  <div id=hosttree>
    <div id=treeheader>
      <span>Hosts</span>
      <button onclick=addGroup()>+ New Group</button>
    </div>
    <div id=treesel>
      <span id=treeselcount></span>
      <select id=treeseldest></select>
      <button class=btn style="padding:3px 10px;font-size:11px" onclick=addSelectedToGroup()>Add to Group</button>
      <button class=btn style="padding:3px 8px;font-size:11px" onclick=clearSel()>Clear Selection</button>
    </div>
    <div id=treebody></div>
  </div>
  <div id=htdiv></div>
  <div id=left>
    <div id=leftbar>
      <div>
        <div class=lbl>Filter Paths</div>
        <input type=text id=filterpath placeholder="keyword, keyword  (comma = OR)" oninput=scheduleFilter()>
      </div>
      <div>
        <div class=lbl>File Types</div>
        <div id=extdrop-wrap>
          <button id=extbtn onclick="toggleExtDrop(event)"><span id=extbtn-lbl>All Types</span><span style="font-size:9px;opacity:.5;margin-left:4px">&#9660;</span></button>
          <div id=extdrop>
            <input type=text id=extsearch placeholder="Search extensions..." oninput=paintExtChips()>
            <div id=extlist></div>
            <div id=extfoot><span id=extfoot-lbl></span><button id=extfoot-clear onclick=clearExtFilters()>Clear</button></div>
          </div>
        </div>
      </div>
      <div>
        <div class=lbl>Shares</div>
        <div id=sharedrop-wrap>
          <button id=sharebtn onclick="toggleShareDrop(event)"><span id=sharebtn-lbl>All Shares</span><span style="font-size:9px;opacity:.5;margin-left:4px">&#9660;</span></button>
          <div id=sharedrop>
            <div id=sharelist></div>
            <div id=sharefoot><span id=sharefoot-lbl></span><button id=sharefoot-clear onclick=clearShareFilters()>Clear</button></div>
          </div>
        </div>
      </div>
    </div>
    <div id=pathList></div>
    <div id=leftfoot><button class=dl-btn style="width:100%;font-size:11px;padding:5px" onclick=downloadAll()>Download All</button></div>
  </div>
  <div id=divider></div>
  <div id=right>
    <div id=rightbar>
      <span>Search Content</span>
      <input type=text id=filtercontent placeholder="keyword, keyword  (comma = OR)" oninput=scheduleHL()>
    </div>
    <div id=header>Select a File to Preview</div>
    <div id=contentarea><pre id=content style="color:var(--tx-d)">Select a Path from the List to View its Contents</pre></div>
    <div id=bottom><button class=dl-btn onclick=dl()>Download File</button></div>
  </div>
</div>
<div id=status>0 paths</div>
<script>
let _fileDescs={};
const EXT_DESC={
  // Office / Documents
  doc:'Word 97-2003 Document',docx:'Word Document',dot:'Word Template',dotx:'Word Template',docm:'Word Macro-Enabled Document',
  xls:'Excel 97-2003 Workbook',xlsx:'Excel Workbook',xlsm:'Excel Macro-Enabled Workbook',xlsb:'Excel Binary Workbook',xlt:'Excel Template',csv:'Comma-Separated Values',
  ppt:'PowerPoint 97-2003 Presentation',pptx:'PowerPoint Presentation',pptm:'PowerPoint Macro-Enabled',pot:'PowerPoint Template',
  mdb:'Access Database (legacy)',accdb:'Access Database',accde:'Access Compiled Database',
  pub:'Publisher Document',vsd:'Visio Drawing',vsdx:'Visio Drawing (XML)',
  odt:'OpenDocument Text',ods:'OpenDocument Spreadsheet',odp:'OpenDocument Presentation',odg:'OpenDocument Drawing',
  one:'OneNote Notebook',onepkg:'OneNote Package',
  // PDF / Print
  pdf:'PDF Document',xps:'XML Paper Specification',oxps:'Open XPS Document',
  // Text / Config / Code
  txt:'Plain Text',log:'Log File',md:'Markdown',rst:'reStructuredText',nfo:'Info/Readme File',
  ini:'INI Configuration',cfg:'Configuration File',conf:'Configuration File',config:'Configuration File',
  xml:'XML Document',json:'JSON Data',yaml:'YAML Config',yml:'YAML Config',toml:'TOML Config',
  properties:'Java Properties',env:'Environment Variables',
  reg:'Windows Registry Export',inf:'Setup Information File',
  bat:'Windows Batch Script',cmd:'Windows Command Script',ps1:'PowerShell Script',psm1:'PowerShell Module',psd1:'PowerShell Data File',
  vbs:'VBScript',vbe:'Encoded VBScript',js:'JavaScript',jse:'Encoded JScript',wsf:'Windows Script File',wsh:'Windows Script Host',hta:'HTML Application',
  sh:'Shell Script',bash:'Bash Script',zsh:'Zsh Script',fish:'Fish Script',
  py:'Python Script',rb:'Ruby Script',pl:'Perl Script',php:'PHP Script',
  cs:'C# Source',java:'Java Source',cpp:'C++ Source',c:'C Source',h:'C/C++ Header',
  go:'Go Source',rs:'Rust Source',ts:'TypeScript Source',
  sql:'SQL Script',
  // Archives
  zip:'ZIP Archive',rar:'RAR Archive','7z':'7-Zip Archive',tar:'TAR Archive',gz:'Gzip Archive',
  bz2:'Bzip2 Archive',xz:'XZ Archive',cab:'Windows Cabinet',iso:'Disk Image',img:'Disk Image',
  msu:'Windows Update Package',msp:'Windows Installer Patch',
  // Executables / Libraries
  exe:'Windows Executable',dll:'Dynamic Link Library',msi:'Windows Installer Package',
  msc:'MMC Snap-in',cpl:'Control Panel Applet',ocx:'ActiveX Control',
  sys:'Windows System Driver',drv:'Device Driver',vxd:'Virtual Device Driver',
  scr:'Screen Saver / Script',com:'DOS Executable',
  jar:'Java Archive',war:'Java Web Application',ear:'Java Enterprise Archive',
  apk:'Android Package',ipa:'iOS App Package',appx:'Windows App Package',msix:'Windows App Package',
  // Certificates / Keys / Credentials
  pem:'PEM Certificate/Key',crt:'X.509 Certificate',cer:'X.509 Certificate',
  pfx:'PKCS#12 Certificate+Key',p12:'PKCS#12 Certificate+Key',
  key:'Private Key',pub:'Public Key',csr:'Certificate Signing Request',
  kdbx:'KeePass Database',kdb:'KeePass Database (legacy)',
  rdp:'Remote Desktop Connection',
  id_rsa:'SSH Private Key',ppk:'PuTTY Private Key',
  // Network / Security
  pcap:'Packet Capture',pcapng:'Packet Capture (NG)',cap:'Packet Capture',
  ovpn:'OpenVPN Config',
  // Web
  html:'HTML Document',htm:'HTML Document',xhtml:'XHTML Document',
  css:'Cascading Stylesheet',
  asp:'ASP Script',aspx:'ASP.NET Page',ashx:'ASP.NET Handler',asmx:'ASP.NET Web Service',
  jsp:'Java Server Page',php3:'PHP3 Script',php4:'PHP4 Script',php5:'PHP5 Script',
  // Email
  msg:'Outlook Email Message',eml:'Email Message (RFC 822)',emlx:'Apple Mail Message',
  pst:'Outlook Personal Storage',ost:'Outlook Offline Storage',mbox:'Mailbox File',
  // Images
  jpg:'JPEG Image',jpeg:'JPEG Image',png:'PNG Image',gif:'GIF Image',bmp:'Bitmap Image',
  tif:'TIFF Image',tiff:'TIFF Image',ico:'Icon File',svg:'SVG Vector Image',
  webp:'WebP Image',raw:'RAW Camera Image',cr2:'Canon RAW Image',nef:'Nikon RAW Image',
  // Media
  mp3:'MP3 Audio',wav:'WAV Audio',flac:'FLAC Audio',aac:'AAC Audio',ogg:'OGG Audio',wma:'Windows Media Audio',
  mp4:'MP4 Video',avi:'AVI Video',mkv:'MKV Video',mov:'QuickTime Video',wmv:'Windows Media Video',
  // Virtual Machines / Disk
  vmdk:'VMware Disk Image',vhd:'Hyper-V Disk Image',vhdx:'Hyper-V Disk Image',
  ova:'VMware Appliance',ovf:'VMware Config',vmx:'VMware Config',
  vdi:'VirtualBox Disk Image',
  // Databases
  db:'SQLite / Generic Database',sqlite:'SQLite Database',sqlite3:'SQLite3 Database',
  mdf:'SQL Server Data File',ldf:'SQL Server Log File',bak:'Database / File Backup',
  // Dev / IDE
  sln:'Visual Studio Solution',csproj:'C# Project',vbproj:'VB.NET Project',
  vcxproj:'Visual C++ Project',proj:'MSBuild Project',
  // Misc
  tmp:'Temporary File',temp:'Temporary File',swp:'Vim Swap File',
  lnk:'Windows Shortcut',url:'Internet Shortcut',
  wim:'Windows Image File',ntds:'Active Directory Database',
  pf:'Windows Prefetch',evt:'Windows Event Log (legacy)',evtx:'Windows Event Log',
  dmp:'Memory Dump',mdmp:'Mini Memory Dump',
  htpasswd:'Apache Password File',shadow:'Unix Shadow Password File',passwd:'Unix Password File',
  // FoxPro / dBASE family
  dbf:'dBASE/FoxPro Database Table',cdx:'FoxPro Compound Index',fpt:'FoxPro Table Memo',
  prg:'FoxPro/dBASE Program Source',scx:'Visual FoxPro Form',frx:'Visual FoxPro Form Binary',
  frt:'Visual FoxPro Report Binary',spr:'Visual FoxPro Screen Program',
  fxp:'Visual FoxPro Compiled Program',pjx:'Visual FoxPro Project',pjt:'Visual FoxPro Project Memo',
  mnx:'Visual FoxPro Menu',mnt:'Visual FoxPro Menu Memo',vcx:'Visual FoxPro Class Library',
  vct:'Visual FoxPro Class Table',fll:'Visual FoxPro DLL Extension',
  fpw:'FoxPro for Windows File',dbm:'Database Memo/Map File',ldb:'Access Database Lock File',
  // Web / Fonts / Styles
  cshtml:'ASP.NET Razor View',ascx:'ASP.NET User Control',asax:'ASP.NET Application File',
  master:'ASP.NET Master Page',browser:'ASP.NET Browser Definition',
  less:'LESS Stylesheet',xsl:'XSL Stylesheet',xslt:'XSLT Stylesheet',
  ttf:'TrueType Font',otf:'OpenType Font',eot:'Embedded OpenType Font',
  woff:'Web Open Font Format',woff2:'Web Open Font Format 2',
  fon:'Bitmap Font File',pfb:'Printer Font Binary',pfm:'Printer Font Metrics',bdf:'Bitmap Font Distribution Format',
  htc:'IE HTML Component',vue:'Vue.js Single-File Component',
  // Windows / Group Policy / MSBuild
  adm:'Group Policy Template (legacy)',admx:'Group Policy Admin Template',adml:'Group Policy Language File',
  pol:'Group Policy Settings',targets:'MSBuild Targets File',manifest:'Application Manifest',
  rsp:'Compiler Response File',mst:'Windows Installer Transform',mof:'WMI Object Format',
  tlb:'COM Type Library',ocx_old:'ActiveX Control',mui:'Multilingual UI Resource',
  pnf:'Precompiled Setup Information',cat:'Windows Security Catalog',
  application:'ClickOnce Application Manifest',chm:'Compiled HTML Help',
  hlp:'Windows Help File',gid:'Windows Help Index',cnt:'Help Contents File',
  // Reports / Output
  rpt:'Report File (Crystal Reports etc.)',rdl:'SQL Server Report Definition',
  rdlc:'RDLC Report Definition',out:'Program Output/Log File',
  prn:'Print Output/Spool File',rtf:'Rich Text Format',wpd:'WordPerfect Document',
  // Dev / Build / Libraries
  lib:'Static Link Library',exp:'Symbol Exports File',bin:'Binary Data File',
  bas:'BASIC/VBA Module',so:'Linux Shared Library',idx:'Index File',
  resx:'.NET Resource File',scc:'Source Code Control File',
  ins:'InstallShield/Internet Settings',iss:'InstallShield Script',
  inx:'Compiled InstallShield Script',xsd:'XML Schema Definition',dtd:'XML Document Type Definition',
  xpi:'Firefox/Mozilla Extension',dtsx:'SSIS Data Package',
  myd:'MySQL Data File',myi:'MySQL Index File',
  svc:'WCF Service Definition',svclog:'WCF Service Trace Log',asmx_old:'ASP.NET Web Service',
  vbp:'Visual Basic Project',vbr:'Visual Basic Registration File',
  wbk:'Word Backup Document',wks:'Lotus 1-2-3 Worksheet',
  // Certs / Security / Signatures
  sig:'Digital Signature/Checksum File',hash:'Hash/Checksum File',lic:'License File',
  // Fonts / Print
  gpd:'Generic Printer Description',tbl:'Table/Translation File',
  // Archives / Packages
  rpm:'RPM Linux Package',wsp:'SharePoint Solution Package',imz:'Compressed Disk Image',
  xpi_pkg:'Mozilla Extension Package',
  // Audio
  mid:'MIDI Audio',
  // Misc identifiable
  act:'ACT! Database / FoxPro Indexed Memo',tsk:'Task Scheduler Job File',
  map:'Source Map File',seq:'Sequence File',dat:'Data File',
  mht:'MHTML Web Archive',swf:'Adobe Flash Animation',
  ntf:'Lotus Notes Template',stp:'STEP/ISO 3D CAD File',
  app:'Application File',tag:'Tag Index File',
  mo:'GNU Gettext Machine Object',lrc:'Lyrics/Locale Resource File',
  nlp:'Natural Language Data File',tab:'Tab-Delimited Data File',
  msk:'Mask File',cache:'Application Cache File',lan:'Language Resource File',
  sep:'Separator/Report File',policy:'.NET Security Policy',
  udf:'Universal Disk Format / User Function',rcf:'Remote Configuration File',
  rdg:'Remote Desktop Connection Group',scexe:'HP Smart Component',
  osd:'Open Software Description',tbk:'Toolbar/Backup File',
  bgi:'Borland Graphics Interface Driver',ptx:'Printer Descriptor File',
  wpd_wp:'WordPerfect Document',cdj:'Canon Driver Job File',
  sft:'SoftFont/Streaming Media File',aas:'Authorware Shocked Archive',
  // Month-named data (common in older business apps)
  jan:'January Data File',feb:'February Data File',mar:'March Data File',
  apr:'April Data File',may:'May Data File',jun:'June Data File',
  jul:'July Data File',aug:'August Data File',sep2:'September Data File',
  oct:'October Data File',nov:'November Data File',dec:'December Data File',
};
const ROW_H=20;
let all=[],cur=null,ft=null,hlt=null,lastContent='',filtered=[],displayed=[],exts=new Set(),negExts=new Set(),fnOnly=true,uniqueNames=false;
let allRestrictedByHost={};
let allReadableByHost={};
function extractRestricted(jobdata){
  // any share we actually enumerated files from is readable — don't show it as restricted
  const accessible=new Set(allPaths.map(p=>{const parts=p.split('/');return parts.slice(0,4).join('/');}));
  const byHost={};
  Object.values(jobdata).forEach(j=>{
    (j.restricted||[]).forEach(sp=>{
      if(accessible.has(sp))return;
      const m=sp.match(/^\\/\\/([^/]+)/);
      if(m){const h=m[1];if(!byHost[h])byHost[h]=[];if(!byHost[h].includes(sp))byHost[h].push(sp);}
    });
  });
  return byHost;
}
function extractReadable(jobdata){
  const byHost={};
  Object.values(jobdata).forEach(j=>{
    (j.readable||[]).forEach(sp=>{
      const m=sp.match(/^\\/\\/([^/]+)/);
      if(m){const h=m[1];if(!byHost[h])byHost[h]=[];if(!byHost[h].includes(sp))byHost[h].push(sp);}
    });
  });
  return byHost;
}
let incShares=new Set(),negShares=new Set(),_shareCounts={};
let pollTimer=null,dlPollTimer=null;
let activeCtrl=null,activeTid=null;
let _extCounts={};
const previewCache=new Map();
const CACHE_MAX=30;
function cachePut(path,data){if(previewCache.size>=CACHE_MAX)previewCache.delete(previewCache.keys().next().value);previewCache.set(path,data);}
function showPreview(d){
  const c=document.getElementById('content');
  if(d.ok){
    lastContent=d.content;c.innerHTML=hl(d.content);hitcount(d.content);
    if(d.truncated){
      const w=document.createElement('div');w.id='trunc-warn';
      w.style.cssText='color:var(--yellow);font-size:11px;margin-bottom:10px;font-family:var(--ui)';
      w.textContent='[preview truncated at 512 KB — use download to get the full file]';
      document.getElementById('contentarea').prepend(w);
    }
  } else {c.textContent=d.msg;}
  document.getElementById('bottom').style.display='block';
}

// tree state — groups store hostnames, not job ids
let groups=[];        // [{id,name,hostnames:[],collapsed:bool}]
let selectedHosts=new Set(),lastSelHost=null;
let activeFilter=null; // null | {type:'host',hostname} | {type:'group',groupId}
let allPaths=[];
let allJobs={};
let dragState=null;   // {hostname, sourceGroupId}  (null = ungrouped)

function saveGroups(){
  fetch('/savegroups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(groups)}).catch(()=>{});
}

// extract unique hostnames from paths in sorted order
function hostsFromPaths(paths){
  const s=new Set();
  paths.forEach(p=>{const h=pmeta(p).host;if(h)s.add(h);});
  return [...s].sort();
}

function ungroupedHosts(hosts){
  const inGroup=new Set(groups.flatMap(g=>g.hostnames));
  return hosts.filter(h=>!inGroup.has(h));
}

// ── init ──
function loadPaths(){
  document.getElementById('status').innerHTML='<span class=spinner></span> Loading...';
  document.getElementById('treebody').innerHTML='<div style="padding:16px 14px;font-size:11px;color:var(--tx-d);display:flex;align-items:center;gap:8px"><span class=spinner></span>Loading Hosts...</div>';
  Promise.all([
    fetch('/paths').then(r=>r.json()),
    fetch('/groups').then(r=>r.json())
  ]).then(([paths,grps])=>{
    groups=grps;allPaths=paths;all=paths;exts.clear();negExts.clear();
    try{go();}catch(e){console.error('go:',e);}renderTree();
    warmCaches();
  });
}
loadPaths();
fetch('/extdescs').then(r=>r.json()).then(d=>{_fileDescs=d;}).catch(()=>{});
fetch('/jobs').then(r=>r.json()).then(d=>{
  allJobs=d;allRestrictedByHost=extractRestricted(d);allReadableByHost=extractReadable(d);renderJobs(d);renderTree();
  if(Object.values(d).some(j=>j.status!=='done'&&j.status!=='error'))startPolling();
});

// ── host scanning ──
function dnsVal(){return document.getElementById('dnsinput').value.trim();}
function updateDns(){fetch('/setdns?dns='+encodeURIComponent(dnsVal()));}
function addHost(){
  const h=document.getElementById('hostinput').value.trim();if(!h)return;
  fetch('/addhost?host='+encodeURIComponent(h)+'&proxy='+proxy()+'&dns='+encodeURIComponent(dnsVal()))
    .then(r=>r.json()).then(d=>{
      if(d.ok){document.getElementById('hostinput').value='';startPolling();poll();}
      else if(d.skip)document.getElementById('status').innerHTML='<span class=warn>'+esc(d.msg)+'</span>';
      else document.getElementById('status').innerHTML='<span class=err>'+esc(d.msg)+'</span>';
    });
}
function openHostModal(){
  document.getElementById('hostmodal').style.display='flex';
  document.getElementById('hostlist').focus();
}
function closeHostModal(){
  document.getElementById('hostmodal').style.display='none';
  document.getElementById('hostlist').value='';
}
function submitHostList(){
  const hosts=document.getElementById('hostlist').value
    .split(/[\\n,]+/).map(h=>h.trim()).filter(Boolean);
  if(!hosts.length)return;
  closeHostModal();
  queueHosts(hosts);
}
function handleHostFile(e){
  const file=e.target.files[0];
  e.target.value=''; // allow re-selecting the same file later
  if(!file)return;
  const reader=new FileReader();
  reader.onload=()=>{
    const hosts=String(reader.result)
      .split(/[\\r\\n,]+/).map(h=>h.trim()).filter(h=>h&&!h.startsWith('#'));
    if(!hosts.length){
      document.getElementById('status').innerHTML='<span class=err>No hosts found in file</span>';
      return;
    }
    queueHosts(hosts);
  };
  reader.onerror=()=>{document.getElementById('status').innerHTML='<span class=err>Failed to read file</span>';};
  reader.readAsText(file);
}
let stopRequested=false;
function queueHosts(hosts){
  if(!hosts.length)return;
  stopRequested=false;
  document.getElementById('status').textContent='Queuing '+hosts.length+' host(s)...';
  let queued=0,skipped=0,pollingStarted=false;
  function next(i){
    if(stopRequested||i>=hosts.length){
      const parts=[];
      if(queued>0)parts.push(queued+' queued');
      if(skipped>0)parts.push(skipped+' already scanned');
      if(stopRequested)parts.push('stopped');
      if(parts.length)document.getElementById('status').textContent=parts.join(', ');
      return;
    }
    fetch('/addhost?host='+encodeURIComponent(hosts[i])+'&proxy='+proxy()+'&dns='+encodeURIComponent(dnsVal()))
      .then(r=>r.json()).then(d=>{
        if(d.ok){
          queued++;
          if(!pollingStarted){pollingStarted=true;startPolling();poll();}
        } else if(d.skip){skipped++;}
        next(i+1);
      });
  }
  next(0);
}
function stopAll(){
  stopRequested=true;
  document.getElementById('status').innerHTML='<span class=warn>Stopping...</span>';
  fetch('/stopall').then(r=>r.json()).then(d=>{
    document.getElementById('status').innerHTML='<span class=warn>Stopped '+(d.cancelled||0)+' job(s)</span>';
    poll();
  }).catch(()=>{
    document.getElementById('status').innerHTML='<span class=err>Stop request failed</span>';
  });
}
document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeHostModal();closeDlModal();closePromptModal();}});

// ── polling ──
function startPolling(){if(pollTimer)return;pollTimer=setInterval(poll,2000);}
function stopPolling(){if(pollTimer){clearInterval(pollTimer);pollTimer=null;}}
let _lastPathSig='',_lastTreeSig='';
function poll(){
  Promise.all([
    fetch('/paths').then(r=>r.json()),
    fetch('/jobs').then(r=>r.json())
  ]).then(([newPaths,jobdata])=>{
    allJobs=jobdata;allRestrictedByHost=extractRestricted(jobdata);allReadableByHost=extractReadable(jobdata);allPaths=newPaths;
    warmCaches();
    renderJobs(jobdata);
    const treeSig=newPaths.length+'|'+(newPaths[newPaths.length-1]||'');
    if(treeSig!==_lastTreeSig){_lastTreeSig=treeSig;renderTree();}
    const pathSig=newPaths.length+'|'+(newPaths[newPaths.length-1]||'');
    if(pathSig!==_lastPathSig){
      _lastPathSig=pathSig;
      if(activeFilter){applyFilter();}else{all=newPaths;go();}
    }
    const anyActive=Object.values(jobdata).some(j=>j.status!=='done'&&j.status!=='error');
    if(!anyActive&&Object.keys(jobdata).length>0){stopPolling();all=allPaths;go();renderTree();}
  });
}

// ── jobs panel ──
let _seenCompleted=new Set();
let _completedLog=[]; // [{host,found,note,status}] newest first
function renderJobs(jobdata){
  const panel=document.getElementById('jobspanel');
  // collect newly finished jobs
  Object.values(jobdata).forEach(j=>{
    if((j.status==='done'||j.status==='error')&&!_seenCompleted.has(j.host)){
      _seenCompleted.add(j.host);
      _completedLog.unshift({host:j.host,found:j.found||0,note:j.note||'',status:j.status});
    }
  });
  const active=Object.values(jobdata).filter(j=>j.status!=='done'&&j.status!=='error');
  const scanning=active.filter(j=>j.status!=='queued');
  const queued=active.filter(j=>j.status==='queued');
  const hasContent=active.length>0||_completedLog.length>0;
  if(!hasContent){panel.style.display='none';return;}
  panel.style.display='flex';panel.innerHTML='';
  // ── progress summary + active scanning row ──
  if(active.length>0){
    const total=scanning.length+queued.length+_completedLog.length;
    const done=_completedLog.length;
    const remaining=scanning.length+queued.length;
    const pct=total>0?Math.round(done/total*100):0;
    // progress bar row
    const prog=document.createElement('div');
    prog.style.cssText='display:flex;align-items:center;gap:8px;width:100%;margin-bottom:4px';
    const barWrap=document.createElement('div');
    barWrap.style.cssText='flex:1;height:4px;background:var(--bg4);border-radius:2px;overflow:hidden;max-width:200px';
    const barFill=document.createElement('div');
    barFill.style.cssText=`height:100%;border-radius:2px;background:var(--ac);width:${pct}%;transition:width .4s`;
    barWrap.appendChild(barFill);
    prog.innerHTML=`<span class=jlbl>hosts</span><span style="font-size:12px;font-weight:700;color:var(--tx)">${done}<span style="color:var(--tx-d);font-weight:400"> / ${total}</span></span>`;
    prog.appendChild(barWrap);
    prog.innerHTML+=`<span style="font-size:11px;color:var(--yellow);font-weight:600">${remaining} remaining</span>`;
    if(queued.length>0)prog.innerHTML+=`<span style="font-size:11px;color:var(--tx-d)">(${queued.length} queued)</span>`;
    panel.appendChild(prog);
    // scanning chips row
    const row=document.createElement('div');
    row.style.cssText='display:flex;flex-wrap:wrap;gap:5px;align-items:center;width:100%';
    let html=`<span class=jlbl>scanning (${scanning.length}/15):</span>`;
    html+=scanning.map(j=>{
      const count=j.found>0?`<span class=jcount>${j.found}</span>`:'';
      const cur=j.current?`<span class=jcur title="${esc(j.current)}">${esc(j.current.split('/').pop()||j.current)}</span>`:'';
      return `<span class=job><span class=spinner></span><span class=jhost>${esc(j.host)}</span>${count}${cur}</span>`;
    }).join('');
    row.innerHTML=html;panel.appendChild(row);
  }
  // ── completed log row ──
  if(_completedLog.length>0){
    const withShares=_completedLog.filter(c=>c.found>0);
    const noShares=_completedLog.filter(c=>c.found===0&&c.status!=='error');
    const errors=_completedLog.filter(c=>c.status==='error');
    const row=document.createElement('div');
    row.style.cssText='display:flex;flex-wrap:wrap;gap:4px;align-items:center;width:100%;'+(active.length>0?'border-top:1px solid var(--bd-s);padding-top:5px;margin-top:3px':'');
    let html=`<span class=jlbl>done (${_completedLog.length}):</span>`;
    if(withShares.length>0)html+=`<span style="font-size:11px;font-weight:700;color:var(--green)">${withShares.length} found shares</span>`;
    if(noShares.length>0)html+=`<span style="font-size:11px;color:var(--tx-d)">${noShares.length} empty</span>`;
    if(errors.length>0)html+=`<span style="font-size:11px;font-weight:700;color:var(--red)">${errors.length} errors</span>`;
    const chips=[...withShares,...errors.slice(0,6)].slice(0,15);
    if(chips.length>0){
      html+='<span style="color:var(--bd);margin:0 2px">|</span>';
      html+=chips.map(c=>{
        const ok=c.found>0;
        const col=ok?'var(--green)':'var(--red)';
        const bg=ok?'rgba(63,185,80,.12)':'rgba(248,81,73,.12)';
        const lbl=ok?`${c.found} paths`:(c.note||'error');
        return `<span class=job style="border-color:${col};background:${bg}"><span style="color:${col};font-weight:700;font-size:11px">${esc(c.host)}</span><span style="color:${col};font-size:10px">${esc(lbl)}</span></span>`;
      }).join('');
    }
    row.innerHTML=html;panel.appendChild(row);
  }
}

// ── tree rendering ──
let _hostPathCounts={};
let _hostShareMap={};
function renderTree(){
  const hosts=hostsFromPaths(allPaths);
  const ug=ungroupedHosts(hosts);
  // build count map once — O(paths) instead of O(hosts*paths)
  _hostPathCounts={};
  const hostShareSets={};
  allPaths.forEach(p=>{
    const meta=pmeta(p);
    if(!meta.host)return;
    const h=meta.host;
    _hostPathCounts[h]=(_hostPathCounts[h]||0)+1;
    if(meta.share)(hostShareSets[h]||(hostShareSets[h]=new Set())).add(meta.share);
  });
  Object.keys(allReadableByHost).forEach(h=>{
    const set=hostShareSets[h]||(hostShareSets[h]=new Set());
    allReadableByHost[h].forEach(sp=>{
      const parts=sp.split('/').filter(Boolean);
      if(parts[1])set.add(parts[1]);
    });
  });
  _hostShareMap={};
  Object.keys(hostShareSets).forEach(h=>{_hostShareMap[h]=[...hostShareSets[h]].sort();});
  const body=document.getElementById('treebody');
  body.innerHTML='';

  // all
  const allEl=document.createElement('div');
  allEl.className='tall'+(activeFilter===null?' sel':'');
  allEl.innerHTML='all <span class=tallcount>('+allPaths.length+')</span>';
  allEl.onclick=()=>setFilter(null);
  body.appendChild(allEl);

  // named groups
  groups.forEach(g=>body.appendChild(makeGroupEl(g)));

  // ungrouped drop zone + host list
  if(hosts.length>0){
    body.appendChild(makeUngroupedEl(ug));
  }
}

// selection/pick highlighting only — no DOM rebuild. Safe whenever activeFilter
// or selectedHosts changes but the host/group/share structure itself hasn't
// (a full renderTree() rebuilds every host + share row, which is expensive
// once there are many hosts — most clicks only change which one is selected).
function updateTreeHighlights(){
  const body=document.getElementById('treebody');
  if(!body)return;
  body.querySelectorAll('.tall').forEach(el=>el.classList.toggle('sel',activeFilter===null));
  body.querySelectorAll('.tghead').forEach(el=>{
    el.classList.toggle('sel',!!(activeFilter&&activeFilter.type==='group'&&activeFilter.groupId===el.dataset.groupid));
  });
  body.querySelectorAll('.thost').forEach(el=>{
    const h=el.dataset.hostname;
    el.classList.toggle('sel',!!(activeFilter&&activeFilter.type==='host'&&activeFilter.hostname===h));
    el.classList.toggle('pick',selectedHosts.has(h));
  });
}

function makeGroupEl(group){
  const wrap=document.createElement('div');
  wrap.className='tgroup';

  const isSel=activeFilter&&activeFilter.type==='group'&&activeFilter.groupId===group.id;
  const head=document.createElement('div');
  head.className='tghead'+(isSel?' sel':'');
  head.dataset.groupid=group.id;

  // drop target
  head.addEventListener('dragover',e=>{e.preventDefault();head.classList.add('dragover');});
  head.addEventListener('dragleave',()=>head.classList.remove('dragover'));
  head.addEventListener('drop',e=>{e.preventDefault();head.classList.remove('dragover');dropOnGroup(group.id);});

  const caret=document.createElement('button');
  caret.className='tgcaret'+(group.collapsed?'':' open');
  caret.textContent='▶';
  caret.title='Collapse / expand';
  caret.onclick=e=>{
    e.stopPropagation();
    group.collapsed=!group.collapsed;
    caret.className='tgcaret'+(group.collapsed?'':' open');
    bodyEl.style.display=group.collapsed?'none':'block';
    saveGroups();
  };

  const nm=document.createElement('span');
  nm.className='tgname';nm.textContent=group.name;

  const cnt=document.createElement('span');
  cnt.className='tgcount';cnt.textContent='('+group.hostnames.length+')';

  const dots=document.createElement('span');
  dots.className='tgdots';dots.textContent='⋮';
  dots.onclick=e=>{e.stopPropagation();showGroupMenu(e,group.id);};

  head.appendChild(caret);head.appendChild(nm);head.appendChild(cnt);head.appendChild(dots);

  const bodyEl=document.createElement('div');
  bodyEl.className='tghosts';
  bodyEl.style.display=group.collapsed?'none':'block';

  head.onclick=e=>{
    if(e.target===dots||e.target.classList.contains('tgdots'))return;
    if(e.target===caret||e.target.closest('.tgcaret'))return;
    setFilter({type:'group',groupId:group.id});
  };

  group.hostnames.forEach(h=>{
    bodyEl.appendChild(makeHostEl(h,_hostPathCounts[h]||0,group.id));
  });

  wrap.appendChild(head);wrap.appendChild(bodyEl);
  return wrap;
}

function makeUngroupedEl(hosts){
  const wrap=document.createElement('div');
  wrap.className='tugzone';

  // label row — also a drop target for moving hosts back to ungrouped
  const lbl=document.createElement('div');
  lbl.className='tuglbl';
  lbl.innerHTML='<span>Ungrouped</span><span style="color:#1e3e1e">'+hosts.length+'</span>';
  lbl.addEventListener('dragover',e=>{e.preventDefault();wrap.classList.add('dragover');});
  lbl.addEventListener('dragleave',()=>wrap.classList.remove('dragover'));
  lbl.addEventListener('drop',e=>{e.preventDefault();wrap.classList.remove('dragover');dropOnGroup(null);});
  wrap.appendChild(lbl);

  hosts.forEach(h=>{
    wrap.appendChild(makeHostEl(h,_hostPathCounts[h]||0,null));
  });
  return wrap;
}

function clearSel(){selectedHosts.clear();lastSelHost=null;updateSelBar();updateTreeHighlights();}
function updateSelBar(){
  const bar=document.getElementById('treesel');
  if(selectedHosts.size===0){bar.style.display='none';return;}
  bar.style.display='flex';
  document.getElementById('treeselcount').textContent=selectedHosts.size+' host'+(selectedHosts.size>1?'s':'')+' selected';
  const sel=document.getElementById('treeseldest');
  sel.innerHTML=groups.map(g=>`<option value="${g.id}">${esc(g.name)}</option>`).join('')
    +'<option value="__new__">+ new group</option>';
}
function addSelectedToGroup(){
  const sel=document.getElementById('treeseldest');
  let gid=sel.value;
  if(gid==='__new__'){
    const name=prompt('Group name:');
    if(!name||!name.trim())return;
    gid='g'+Date.now();
    groups.push({id:gid,name:name.trim().toUpperCase(),hostnames:[],collapsed:false});
  }
  const g=groups.find(x=>x.id===gid);
  if(!g)return;
  selectedHosts.forEach(h=>{
    groups.forEach(gr=>{gr.hostnames=gr.hostnames.filter(x=>x!==h);});
    if(!g.hostnames.includes(h))g.hostnames.push(h);
  });
  saveGroups();clearSel();
}

function filterToShare(hostname,shareName){
  activeFilter={type:'host',hostname};
  exts.clear();negExts.clear();
  incShares.clear();negShares.clear();
  incShares.add(shareName);
  syncShareChips();updateShareBtn();
  updateTreeHighlights();requestAnimationFrame(applyFilter);
}
function makeHostEl(hostname,pathCount,sourceGroupId){
  const isSel=activeFilter&&activeFilter.type==='host'&&activeFilter.hostname===hostname;
  const isPick=selectedHosts.has(hostname);
  const div=document.createElement('div');
  div.className='thost'+(isSel?' sel':'')+(isPick?' pick':'');
  div.dataset.hostname=hostname;
  div.draggable=true;
  div.addEventListener('dragstart',e=>{
    dragState={hostname,sourceGroupId};
    e.dataTransfer.effectAllowed='move';
    e.dataTransfer.setData('text/plain',hostname);
    setTimeout(()=>div.classList.add('dragging'),0);
  });
  div.addEventListener('dragend',()=>{div.classList.remove('dragging');});
  div.onclick=e=>{
    if(e.target===cb)return;
    setFilter({type:'host',hostname});
  };
  const cb=document.createElement('input');
  cb.type='checkbox';cb.className='thost-cb';cb.checked=isPick;
  cb.addEventListener('click',e=>{
    e.stopPropagation();
    if(e.shiftKey&&cb.checked&&lastSelHost){
      const visible=[...document.querySelectorAll('.thost .thostname')].map(n=>n.title);
      const lo=Math.min(visible.indexOf(hostname),visible.indexOf(lastSelHost));
      const hi=Math.max(visible.indexOf(hostname),visible.indexOf(lastSelHost));
      for(let i=lo;i<=hi;i++)selectedHosts.add(visible[i]);
      document.querySelectorAll('.thost').forEach(el=>{
        const n=el.querySelector('.thostname'),c=el.querySelector('.thost-cb');
        if(n&&c){const on=selectedHosts.has(n.title);c.checked=on;el.classList.toggle('pick',on);}
      });
    } else {
      if(cb.checked){selectedHosts.add(hostname);}
      else selectedHosts.delete(hostname);
      div.classList.toggle('pick',cb.checked);
    }
    lastSelHost=hostname;updateSelBar();
  });
  const nm=document.createElement('span');
  nm.className='thostname';nm.title=hostname;nm.textContent=hostname;
  const cnt=document.createElement('span');
  cnt.className='thostcount';cnt.textContent=pathCount||'';
  div.appendChild(cb);div.appendChild(nm);div.appendChild(cnt);

  const wrap=document.createElement('div');
  wrap.className='thostwrap';
  wrap.appendChild(div);
  const readable=_hostShareMap[hostname]||[];
  if(readable.length>0){
    const rList=document.createElement('div');rList.className='trs-list';
    readable.forEach(name=>{
      const row=document.createElement('div');row.className='trs-row';
      const snm=document.createElement('span');
      snm.className='trs-name trs-readable';
      snm.textContent=name;
      snm.title='Filter to '+name;
      snm.onclick=e=>{e.stopPropagation();filterToShare(hostname,name);};
      row.appendChild(snm);
      rList.appendChild(row);
    });
    wrap.appendChild(rList);
  }
  return wrap;
}
function scanRestrictedShare(sharePath,btn){
  btn.textContent='...';btn.disabled=true;
  fetch('/scanshare?share='+encodeURIComponent(sharePath)+'&proxy='+proxy())
    .then(r=>r.json()).then(d=>{
      if(d.ok){startPolling();poll();btn.textContent='Queued';setTimeout(()=>{btn.textContent='Re-scan';btn.disabled=false;},4000);}
      else{btn.textContent='Error';btn.disabled=false;}
    }).catch(()=>{btn.textContent='Error';btn.disabled=false;});
}

// ── drag / drop ──
function dropOnGroup(targetGroupId){
  if(!dragState)return;
  const{hostname,sourceGroupId}=dragState;
  dragState=null;
  if(sourceGroupId===targetGroupId)return;

  // remove from source group
  if(sourceGroupId!==null){
    const src=groups.find(g=>g.id===sourceGroupId);
    if(src)src.hostnames=src.hostnames.filter(h=>h!==hostname);
  }
  // add to target group
  if(targetGroupId!==null){
    const tgt=groups.find(g=>g.id===targetGroupId);
    if(tgt&&!tgt.hostnames.includes(hostname))tgt.hostnames.push(hostname);
  }
  saveGroups();renderTree();
  if(activeFilter)applyFilter();
}

// ── filter ──
function setFilter(f){
  activeFilter=f;exts.clear();negExts.clear();incShares.clear();negShares.clear();
  syncShareChips();updateShareBtn();updateTreeHighlights();requestAnimationFrame(applyFilter);
}

// per-host path lists, both in raw (scan) order and in name-sorted order — lets
// switching to a single host be an O(1) lookup instead of an O(allPaths) scan.
// Rebuilt only when allPaths itself changes (same cache-by-reference trick as
// getSortedAllPaths).
// the sort cache and host index are otherwise built lazily on whichever click
// happens to need them first — meaning that click (and only that one) pays the
// full O(n) cost, then everything after is instant. Warm both proactively as
// soon as new data lands (in browser idle time, so it never blocks rendering)
// so the first real click doesn't have to pay for it.
function warmCaches(){
  const run=()=>{getSortedAllPaths();ensureHostIndex();};
  if(window.requestIdleCallback)requestIdleCallback(run,{timeout:1500});
  else setTimeout(run,0);
}
let _hostIndexRaw=null,_hostIndexSorted=null,_hostIndexRef=null;
function ensureHostIndex(){
  if(_hostIndexRef===allPaths)return;
  const raw={};
  allPaths.forEach(p=>{const h=pmeta(p).host;if(h)(raw[h]||(raw[h]=[])).push(p);});
  const sorted={};
  getSortedAllPaths().forEach(p=>{const h=pmeta(p).host;if(h)(sorted[h]||(sorted[h]=[])).push(p);});
  _hostIndexRaw=raw;_hostIndexSorted=sorted;_hostIndexRef=allPaths;
}
// applies the current host/group scope to any source array (raw or presorted) —
// filter() preserves relative order, so scoping a presorted array yields a
// presorted result without re-sorting. Host scoping specifically uses the
// prebuilt index above instead of scanning source, since source is always
// either allPaths or getSortedAllPaths() (the only two call sites below).
function scopeFilter(source){
  if(!activeFilter)return source;
  if(activeFilter.type==='host'){
    ensureHostIndex();
    const idx=source===allPaths?_hostIndexRaw:_hostIndexSorted;
    return idx[activeFilter.hostname]||[];
  }
  if(activeFilter.type==='group'){
    const g=groups.find(x=>x.id===activeFilter.groupId);
    if(!g)return source;
    return source.filter(p=>g.hostnames.some(h=>p.startsWith('//'+h+'/')));
  }
  return source;
}
function applyFilter(){
  if(activeFilter&&activeFilter.type==='group'&&!groups.find(x=>x.id===activeFilter.groupId)){
    activeFilter=null;
  }
  all=scopeFilter(allPaths);
  go();
}

// ── group management ──
let _promptCb=null;
function showPrompt(title,defVal,cb){
  document.getElementById('promptmodal-title').textContent=title;
  const inp=document.getElementById('promptmodal-input');
  inp.value=defVal||'';
  _promptCb=cb;
  document.getElementById('promptmodal').style.display='flex';
  setTimeout(()=>{inp.focus();inp.select();},0);
}
function closePromptModal(){document.getElementById('promptmodal').style.display='none';_promptCb=null;}
function submitPromptModal(){
  const val=document.getElementById('promptmodal-input').value.trim();
  const cb=_promptCb;
  closePromptModal();
  if(val&&cb)cb(val);
}
function addGroup(){
  showPrompt('New Group Name','',name=>{
    groups.push({id:'g'+Date.now(),name:name.toUpperCase(),hostnames:[],collapsed:false});
    saveGroups();renderTree();
  });
}
function renameGroup(id){
  const g=groups.find(x=>x.id===id);if(!g)return;
  showPrompt('Rename Group',g.name,name=>{
    g.name=name.toUpperCase();saveGroups();renderTree();
  });
}
function deleteGroup(id){
  groups=groups.filter(x=>x.id!==id);
  if(activeFilter&&activeFilter.type==='group'&&activeFilter.groupId===id){
    activeFilter=null;all=allPaths;go();
  }
  saveGroups();renderTree();
}

// ── context menu ──
function closeMenu(){const m=document.getElementById('_cm');if(m)m.remove();}
document.addEventListener('click',closeMenu);

function posMenu(menu,e){
  document.body.appendChild(menu);
  const r=menu.getBoundingClientRect();
  let x=e.clientX,y=e.clientY;
  if(x+r.width>window.innerWidth)x=e.clientX-r.width;
  if(y+r.height>window.innerHeight)y=e.clientY-r.height;
  menu.style.left=x+'px';menu.style.top=y+'px';
}
function mkItem(text,cls,cb){
  const d=document.createElement('div');
  d.className='cmitem'+(cls?' '+cls:'');d.textContent=text;
  if(cb)d.onclick=()=>{closeMenu();cb();};return d;
}
function mkSep(){const d=document.createElement('div');d.className='cmsep';return d;}

function showGroupMenu(e,groupId){
  closeMenu();
  const menu=document.createElement('div');
  menu.className='cmenu';menu.id='_cm';
  menu.appendChild(mkItem('Rename','',()=>renameGroup(groupId)));
  menu.appendChild(mkSep());
  menu.appendChild(mkItem('Delete Group','danger',()=>deleteGroup(groupId)));
  e.stopPropagation();posMenu(menu,e);
}

// ── resizable panels ──
(()=>{
  const dv=document.getElementById('htdiv'),ht=document.getElementById('hosttree');
  let drag=false,sx=0,sw=0;
  dv.addEventListener('mousedown',e=>{drag=true;sx=e.clientX;sw=ht.offsetWidth;dv.classList.add('drag');document.body.style.cssText='cursor:col-resize;user-select:none';});
  document.addEventListener('mousemove',e=>{if(!drag)return;ht.style.width=Math.max(100,Math.min(sw+e.clientX-sx,400))+'px';});
  document.addEventListener('mouseup',()=>{drag=false;dv.classList.remove('drag');document.body.style.cssText='';});
})();
(()=>{
  const dv=document.getElementById('divider'),lf=document.getElementById('left');
  let drag=false,sx=0,sw=0;
  dv.addEventListener('mousedown',e=>{drag=true;sx=e.clientX;sw=lf.offsetWidth;document.body.style.cssText='cursor:col-resize;user-select:none';});
  document.addEventListener('mousemove',e=>{if(!drag)return;lf.style.width=Math.max(100,Math.min(sw+e.clientX-sx,window.innerWidth-200))+'px';lf.style.flex='none';});
  document.addEventListener('mouseup',()=>{drag=false;document.body.style.cssText='';});
})();

// ── path list ──
// per-path metadata (basename lowercase, extension, host, share) is expensive to
// re-derive with regex/split — and go() reruns on every filter/share/ext click, not
// just on data load — so compute each unique path's metadata once and reuse it.
const _pathMeta=new Map();
function pmeta(p){
  let m=_pathMeta.get(p);
  if(!m){
    const name=p.split('/').pop()||p;
    const em=name.match(/\\.([a-zA-Z0-9]+)$/);
    const sm=p.match(/^\\/\\/([^/]+)\\/([^/]+)/);
    m={nameLower:name.toLowerCase(),ext:em?em[1].toLowerCase():null,host:sm?sm[1]:null,share:sm?sm[2]:null};
    _pathMeta.set(p,m);
  }
  return m;
}
function getExt(p){return pmeta(p).ext;}
// allPaths sorted by basename is the single most expensive thing go() used to
// redo on every keystroke/click (O(n log n) over the whole "all" view — the
// worst case being the unfiltered "all" scope itself). Sort once per data
// change and cache it; scopeFilter()/val/share/ext filters below are all
// order-preserving, so a presorted source stays sorted through every stage
// with no re-sort needed.
let _sortedAllPaths=null,_sortedAllPathsRef=null;
function getSortedAllPaths(){
  if(_sortedAllPathsRef!==allPaths){
    _sortedAllPaths=allPaths.slice().sort((a,b)=>{
      const ka=pmeta(a).nameLower,kb=pmeta(b).nameLower;
      return ka<kb?-1:ka>kb?1:0;
    });
    _sortedAllPathsRef=allPaths;
  }
  return _sortedAllPaths;
}
function go(){
  const val=document.getElementById('filterpath').value.trim();
  let tf=fnOnly?scopeFilter(getSortedAllPaths()):all;
  if(val){const terms=val.toLowerCase().split(',').map(t=>t.trim()).filter(Boolean);tf=tf.filter(p=>{const target=fnOnly?pmeta(p).nameLower:p.toLowerCase();return terms.some(t=>target.includes(t));});}
  rebuildShares(tf);
  if(incShares.size>0||negShares.size>0){tf=tf.filter(p=>{const sn=pmeta(p).share;if(!sn)return true;if(negShares.has(sn))return false;return incShares.size===0||incShares.has(sn);});}
  rebuildExts(tf);
  let out=exts.size>0?tf.filter(p=>{const e=pmeta(p).ext;return e&&exts.has(e);}):tf;
  if(negExts.size>0)out=out.filter(p=>{const e=pmeta(p).ext;return !e||!negExts.has(e);});
  filtered=out;
  render(out);
}
function toggleExtDrop(e){
  if(e)e.stopPropagation();
  const d=document.getElementById('extdrop');
  const willOpen=!d.classList.contains('open');
  d.classList.toggle('open',willOpen);
  if(willOpen){computeExtCounts(_extCountSrc);paintExtChips();document.getElementById('extsearch').focus();}
}
document.addEventListener('click',function(e){
  const w=document.getElementById('extdrop-wrap');
  if(w&&!w.contains(e.target))document.getElementById('extdrop').classList.remove('open');
  const sw=document.getElementById('sharedrop-wrap');
  if(sw&&!sw.contains(e.target))document.getElementById('sharedrop').classList.remove('open');
});
function updateExtBtn(){
  const inc=exts.size,exc=negExts.size;
  const btn=document.getElementById('extbtn');
  const lbl=document.getElementById('extbtn-lbl');
  const fl=document.getElementById('extfoot-lbl');
  if(!inc&&!exc){
    lbl.textContent='All Types';btn.classList.remove('active');
    if(fl)fl.textContent='';
  } else {
    const parts=[];
    if(inc)parts.push(inc+' included');
    if(exc)parts.push(exc+' excluded');
    lbl.textContent=parts.join(', ');btn.classList.add('active');
    if(fl)fl.textContent=(inc+exc)+' active';
  }
}
function syncExtChips(){
  document.querySelectorAll('.ext-row').forEach(row=>{
    const ext=row.dataset.ext;
    const incBtn=row.querySelector('.ext-inc');
    const excBtn=row.querySelector('.ext-exc');
    if(incBtn)incBtn.classList.toggle('on',exts.has(ext));
    if(excBtn)excBtn.classList.toggle('on',negExts.has(ext));
  });
  updateExtBtn();
}
// counting extensions is itself an O(paths) pass — same story as painting:
// almost always wasted since the dropdown is almost always closed. Stash the
// set to count and defer both the count and the paint until it's opened.
let _extCountSrc=[];
function computeExtCounts(paths){
  const counts={};
  paths.forEach(p=>{const e=pmeta(p).ext;if(e)counts[e]=(counts[e]||0)+1;});
  _extCounts=counts;
  const unknown=Object.keys(counts).filter(e=>!EXT_DESC[e]&&!_fileDescs[e]);
  if(unknown.length){
    fetch('/lookupexts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({exts:unknown})})
      .then(r=>r.json()).then(d=>{
        if(d.queued>0){
          setTimeout(()=>{
            fetch('/extdescs').then(r=>r.json()).then(data=>{_fileDescs=data;paintExtChips();}).catch(()=>{});
          },6000);
        }
      }).catch(()=>{});
  }
}
function rebuildExts(paths){
  _extCountSrc=paths;
  const dd=document.getElementById('extdrop');
  if(dd&&dd.classList.contains('open')){computeExtCounts(paths);paintExtChips();}
  else updateExtBtn();
}
function paintExtChips(){
  const inp=document.getElementById('extsearch');
  const search=inp?inp.value.toLowerCase().trim():'';
  let entries=Object.entries(_extCounts).sort((a,b)=>b[1]-a[1]);
  if(search)entries=entries.filter(([ext])=>ext.includes(search)||(EXT_DESC[ext]||_fileDescs[ext]||'').toLowerCase().includes(search));
  const list=document.getElementById('extlist');
  const frag=document.createDocumentFragment();
  entries.slice(0,300).forEach(([ext,cnt])=>{
    const row=document.createElement('div');
    row.className='ext-row';row.dataset.ext=ext;
    const lbl=document.createElement('span');lbl.className='ext-lbl';
    const nm=document.createElement('span');nm.className='ext-name';nm.textContent='.'+ext;
    lbl.appendChild(nm);
    const ds=document.createElement('span');ds.className='ext-desc';
    ds.textContent=EXT_DESC[ext]||_fileDescs[ext]||'';
    lbl.appendChild(ds);
    const ct=document.createElement('span');ct.className='ext-cnt';ct.textContent=cnt;
    const inc=document.createElement('button');
    inc.className='ext-inc'+(exts.has(ext)?' on':'');
    inc.textContent='+';inc.title='Include — show only this type';
    inc.onclick=ev=>{
      ev.stopPropagation();
      negExts.delete(ext);
      if(exts.has(ext))exts.delete(ext);else exts.add(ext);
      syncExtChips();requestAnimationFrame(go);
    };
    const exc=document.createElement('button');
    exc.className='ext-exc'+(negExts.has(ext)?' on':'');
    exc.textContent='\\u2715';exc.title='Exclude — hide this type';
    exc.onclick=ev=>{
      ev.stopPropagation();
      exts.delete(ext);
      if(negExts.has(ext))negExts.delete(ext);else negExts.add(ext);
      syncExtChips();requestAnimationFrame(go);
    };
    row.appendChild(lbl);row.appendChild(ct);row.appendChild(inc);row.appendChild(exc);
    frag.appendChild(row);
  });
  if(!entries.length){
    const empty=document.createElement('div');
    empty.style.cssText='padding:12px 10px;font-size:11px;color:var(--tx-d);text-align:center';
    empty.textContent='No extensions found';
    frag.appendChild(empty);
  }
  list.innerHTML='';list.appendChild(frag);
  updateExtBtn();
}
function clearExtFilters(){exts.clear();negExts.clear();paintExtChips();requestAnimationFrame(go);}
function onExtSearch(){paintExtChips();}
let _shareCountSrc=[];
function computeShareCounts(paths){
  const counts={};
  paths.forEach(p=>{const sn=pmeta(p).share;if(sn)counts[sn]=(counts[sn]||0)+1;});
  const hostsInScope=activeFilter&&activeFilter.type==='host'
    ?[activeFilter.hostname]
    :activeFilter&&activeFilter.type==='group'
      ?(groups.find(g=>g.id===activeFilter.groupId)||{hostnames:[]}).hostnames
      :Object.keys(allReadableByHost);
  hostsInScope.forEach(h=>{
    (allReadableByHost[h]||[]).forEach(sp=>{
      const parts=sp.split('/').filter(Boolean);
      if(parts[1]&&!(parts[1] in counts))counts[parts[1]]=0;
    });
  });
  _shareCounts=counts;
}
function rebuildShares(paths){
  _shareCountSrc=paths;
  const sd=document.getElementById('sharedrop');
  if(sd&&sd.classList.contains('open')){computeShareCounts(paths);paintShareChips();}
  else updateShareBtn();
}
function toggleShareDrop(e){
  if(e)e.stopPropagation();
  const d=document.getElementById('sharedrop');
  const willOpen=!d.classList.contains('open');
  d.classList.toggle('open',willOpen);
  if(willOpen){computeShareCounts(_shareCountSrc);paintShareChips();}
}
function updateShareBtn(){
  const inc=incShares.size,exc=negShares.size;
  const btn=document.getElementById('sharebtn');const lbl=document.getElementById('sharebtn-lbl');
  const fl=document.getElementById('sharefoot-lbl');
  if(!inc&&!exc){lbl.textContent='All Shares';btn.classList.remove('active');if(fl)fl.textContent='';}
  else{const parts=[];if(inc)parts.push(inc+' included');if(exc)parts.push(exc+' excluded');lbl.textContent=parts.join(', ');btn.classList.add('active');if(fl)fl.textContent=(inc+exc)+' active';}
}
function syncShareChips(){
  document.querySelectorAll('#sharelist .ext-row').forEach(row=>{
    const sn=row.dataset.share;
    const ib=row.querySelector('.ext-inc');const eb=row.querySelector('.ext-exc');
    if(ib)ib.classList.toggle('on',incShares.has(sn));
    if(eb)eb.classList.toggle('on',negShares.has(sn));
  });
  updateShareBtn();
}
function paintShareChips(){
  const list=document.getElementById('sharelist');if(!list)return;
  const frag=document.createDocumentFragment();
  const entries=Object.entries(_shareCounts).sort((a,b)=>b[1]-a[1]);
  entries.forEach(([sn,cnt])=>{
    const row=document.createElement('div');row.className='ext-row';row.dataset.share=sn;
    const lbl=document.createElement('span');lbl.className='ext-lbl';
    const nm=document.createElement('span');nm.className='ext-name';nm.textContent=sn;lbl.appendChild(nm);
    const ct=document.createElement('span');ct.className='ext-cnt';ct.textContent=cnt;
    const inc=document.createElement('button');inc.className='ext-inc'+(incShares.has(sn)?' on':'');inc.textContent='+';inc.title='Show only this share';
    inc.onclick=ev=>{ev.stopPropagation();negShares.delete(sn);if(incShares.has(sn))incShares.delete(sn);else incShares.add(sn);syncShareChips();requestAnimationFrame(go);};
    const exc=document.createElement('button');exc.className='ext-exc'+(negShares.has(sn)?' on':'');exc.textContent='\\u2715';exc.title='Hide this share';
    exc.onclick=ev=>{ev.stopPropagation();incShares.delete(sn);if(negShares.has(sn))negShares.delete(sn);else negShares.add(sn);syncShareChips();requestAnimationFrame(go);};
    row.appendChild(lbl);row.appendChild(ct);row.appendChild(inc);row.appendChild(exc);frag.appendChild(row);
  });
  if(!entries.length){const e=document.createElement('div');e.style.cssText='padding:12px 10px;font-size:11px;color:var(--tx-d);text-align:center';e.textContent='No shares found';frag.appendChild(e);}
  list.innerHTML='';list.appendChild(frag);updateShareBtn();
}
function clearShareFilters(){incShares.clear();negShares.clear();paintShareChips();requestAnimationFrame(go);}
function scheduleFilter(){clearTimeout(ft);exts.clear();negExts.clear();ft=setTimeout(go,150);}
function scheduleHL(){clearTimeout(hlt);hlt=setTimeout(()=>{if(lastContent){document.getElementById('content').innerHTML=hl(lastContent);hitcount(lastContent);}},150);}
function toggleFN(){
  fnOnly=!fnOnly;
  const b=document.getElementById('fnbtn');
  b.textContent=fnOnly?'Filename Only':'Full Path';
  b.classList.toggle('active',fnOnly);exts.clear();negExts.clear();requestAnimationFrame(go);
}
function toggleUN(){
  uniqueNames=!uniqueNames;
  document.getElementById('unbtn').classList.toggle('active',uniqueNames);
  requestAnimationFrame(()=>render(filtered));
}
function render(paths){
  if(uniqueNames){
    const seen=new Set();
    displayed=paths.filter(p=>{const n=pmeta(p).nameLower;return seen.has(n)?false:(seen.add(n),true);});
  } else {
    displayed=paths;
  }
  const suffix=(uniqueNames?' \u2192 '+displayed.length+' unique':'')+(activeFilter?' \u25b6 filtered':'');
  document.getElementById('status').textContent=paths.length||all.length?paths.length+' / '+all.length+' paths'+suffix:'No Paths Loaded — Scan a Host or Load a File';
  const list=document.getElementById('pathList');list.innerHTML='';
  if(!displayed.length)return;
  const spacer=document.createElement('div');
  spacer.style.height=(displayed.length*ROW_H)+'px';spacer.style.position='relative';
  list.appendChild(spacer);
  let lastStart=-1;
  function paint(){
    const scrollTop=list.scrollTop;
    const visible=Math.ceil(list.clientHeight/ROW_H);
    const start=Math.max(0,Math.floor(scrollTop/ROW_H)-5);
    const end=Math.min(displayed.length,start+visible+10);
    if(start===lastStart)return;lastStart=start;
    spacer.querySelectorAll('.path').forEach(e=>e.remove());
    for(let i=start;i<end;i++){
      const p=displayed[i];
      const d=document.createElement('div');
      d.className='path';d.title=p;
      d.textContent=fnOnly?(p.split('/').pop()||p):p;
      d.style.top=(i*ROW_H)+'px';d.dataset.idx=i;
      d.addEventListener('click',function(){sel(this,displayed[+this.dataset.idx]);});
      spacer.appendChild(d);
    }
  }
  list.onscroll=paint;paint();requestAnimationFrame(()=>{lastStart=-1;paint();});
}
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function escRe(s){return s.replace(/[.*+?^${}()|[\\]\\\\]/g,'\\\\$&');}
function hl(text){
  const val=document.getElementById('filtercontent').value.trim();
  let r=esc(text);if(!val)return r;
  val.split(',').map(t=>t.trim()).filter(Boolean).forEach(t=>{
    r=r.replace(new RegExp(escRe(esc(t)),'gi'),m=>'<span class=hl>'+m+'</span>');
  });
  return r;
}
function hitcount(text){
  const val=document.getElementById('filtercontent').value.trim();
  const rb=document.getElementById('rightbar');
  const old=rb.querySelector('.hc');if(old)old.remove();
  if(!val)return;
  let total=0;
  val.split(',').map(t=>t.trim()).filter(Boolean).forEach(t=>{
    const m=esc(text).match(new RegExp(escRe(esc(t)),'gi'));if(m)total+=m.length;
  });
  if(total>0){
    const s=document.createElement('span');s.className='hc';
    s.style.cssText='font-size:10px;color:#ff8;margin-left:4px;white-space:nowrap';
    s.textContent=total+' match'+(total===1?'':'es');rb.appendChild(s);
  }
}
function proxy(){return 0;}
function sel(el,path){
  // abort any in-flight request
  if(activeCtrl){clearTimeout(activeTid);activeCtrl.abort();activeCtrl=null;activeTid=null;}
  document.querySelectorAll('.path').forEach(e=>e.classList.remove('active'));
  el.classList.add('active');cur=path;
  document.getElementById('header').textContent=path;
  document.getElementById('bottom').style.display='none';
  const oldWarn=document.getElementById('trunc-warn');if(oldWarn)oldWarn.remove();
  lastContent='';
  // serve from cache if available
  if(previewCache.has(path)){showPreview(previewCache.get(path));return;}
  document.getElementById('content').textContent='Loading...';
  activeCtrl=new AbortController();
  activeTid=setTimeout(()=>{if(activeCtrl)activeCtrl.abort();},35000);
  fetch('/cat?path='+encodeURIComponent(path)+'&proxy='+proxy(),{signal:activeCtrl.signal})
    .then(r=>r.json()).then(d=>{
      clearTimeout(activeTid);activeCtrl=null;activeTid=null;
      if(d.ok)cachePut(path,d);
      showPreview(d);
    }).catch(e=>{
      clearTimeout(activeTid);activeCtrl=null;activeTid=null;
      const c=document.getElementById('content');
      c.textContent=e.name==='AbortError'?'Timed out reading file — use download to get the full file':'Error reading file';
      document.getElementById('bottom').style.display='block';
    });
}
function dl(){
  if(!cur)return;
  document.getElementById('status').textContent='Downloading '+cur;
  fetch('/download?path='+encodeURIComponent(cur)+'&proxy='+proxy())
    .then(r=>r.json()).then(d=>{
      document.getElementById('status').innerHTML=d.ok?'<span class=ok>Saved: '+d.msg+'</span>':'<span class=err>Failed: '+d.msg+'</span>';
    });
}
function startDlPoll(){
  if(dlPollTimer)return;
  dlPollTimer=setInterval(()=>{
    fetch('/dlstatus').then(r=>r.json()).then(d=>{
      const s=document.getElementById('status');
      if(d.running){
        s.textContent='Downloading '+d.done+'/'+d.total+'...';
      } else if(d.total>0){
        clearInterval(dlPollTimer);dlPollTimer=null;
        const msg=d.failed>0
          ?'Download complete — '+d.done+' saved, '+d.failed+' failed'
          :'Download complete — '+d.done+' file(s) saved';
        s.innerHTML='<span class=ok>'+msg+'</span>';
      }
    });
  },2000);
}
function downloadAll(){
  if(!displayed.length){document.getElementById('status').textContent='Nothing to download';return;}
  document.getElementById('dlmodal-sub').textContent='Which folder would you like to save '+displayed.length+' file'+(displayed.length===1?'':'s')+' to?';
  document.getElementById('dlmodal').style.display='flex';
}
function closeDlModal(){document.getElementById('dlmodal').style.display='none';}
function startDlAll(extFolders){
  closeDlModal();
  const n=displayed.length;
  document.getElementById('status').textContent='Queuing '+n+' file(s) for download...';
  fetch('/downloadall',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({paths:displayed,proxy:proxy()===1,extfolders:extFolders})
  }).then(r=>r.json()).then(d=>{
    const s=document.getElementById('status');
    if(d.ok){startDlPoll();}
    else s.innerHTML='<span class=err>'+esc(d.msg)+'</span>';
  });
}
function clearRight(){
  cur=null;lastContent='';
  document.getElementById('header').textContent='Select a Path';
  document.getElementById('content').textContent='Click a Path to View its Contents';
  document.getElementById('bottom').style.display='none';
  const old=document.getElementById('rightbar').querySelector('.hc');if(old)old.remove();
}
</script></body></html>"""


def start_gui(creds, pathsfile=''):
    domain, user, passwd = parse_creds(creds)

    live_paths = []
    paths_lock = threading.Lock()
    jobs = {}
    dns_server = ['']   # mutable so handlers can update it
    jobs_lock = threading.Lock()
    job_counter = [0]
    dl_status = [{'running': False, 'done': 0, 'failed': 0, 'total': 0}]
    SCAN_WORKERS = 15
    scan_queue = queue.Queue()
    active_procs = {}       # job_id -> currently running Popen for that job
    active_procs_lock = threading.Lock()

    def is_cancelled(job_id):
        with jobs_lock:
            return jobs.get(job_id, {}).get('cancelled', False)

    def register_proc(job_id, proc):
        with active_procs_lock:
            active_procs[job_id] = proc

    def unregister_proc(job_id):
        with active_procs_lock:
            active_procs.pop(job_id, None)

    ext_descs = {}
    ext_descs_lock = threading.Lock()
    ext_descs_file = 'smblist_extensions'
    if os.path.exists(ext_descs_file):
        try:
            with open(ext_descs_file) as f:
                for line in f:
                    line = line.strip()
                    if '=' in line:
                        k, v = line.split('=', 1)
                        k = k.strip().lower()
                        if k:
                            ext_descs[k] = v.strip()
        except Exception:
            pass

    gui_groups = []
    gui_groups_lock = threading.Lock()
    gui_groups_file = 'smblist_myfolders'
    if os.path.exists(gui_groups_file):
        try:
            with open(gui_groups_file) as f:
                gui_groups = json.load(f)
        except Exception:
            gui_groups = []

    # names that start with smblist_ but are not path lists
    _SMBLIST_NON_PATH = {'smblist_extensions', 'smblist_myfolders'}

    if pathsfile and os.path.exists(pathsfile):
        with open(pathsfile) as f:
            live_paths = [l.strip() for l in f if l.strip()]
    else:
        # auto-load any smblist_<host> files in cwd
        print(f'Scanning for smblist_* files in: {os.path.abspath(".")}', file=sys.stderr)
        seen = set()
        for fname in sorted(os.listdir('.')):
            if fname.startswith('smblist_') and fname not in _SMBLIST_NON_PATH and os.path.isfile(fname):
                try:
                    before = len(live_paths)
                    with open(fname) as f:
                        for line in f:
                            p = line.strip()
                            if p and p not in seen:
                                seen.add(p)
                                live_paths.append(p)
                    added = len(live_paths) - before
                    if added == 0:
                        # empty/no-op result file — clean it up and don't clutter the log
                        try:
                            os.remove(fname)
                        except Exception:
                            pass
                        continue
                    print(f'Loaded: {fname} ({len(live_paths)} paths total)', file=sys.stderr)
                except Exception:
                    pass

    def bg_run_host(job_id, host, use_proxy, dns=''):
        def setstatus(s):
            with jobs_lock:
                jobs[job_id]['status'] = s
        if is_cancelled(job_id):
            return
        try:
            setstatus('running nxc')
            nxc_cmd = ['netexec', 'smb', host, '-u', user, '-p', passwd, '-d', domain, '--shares']
            if dns:
                nxc_cmd += ['--dns-server', dns]
            result = run_cmd(nxc_cmd, use_proxy, timeout=60,
                              on_start=lambda proc: register_proc(job_id, proc),
                              cancel_check=lambda: is_cancelled(job_id))
            unregister_proc(job_id)
            if result.stderr.strip() == 'cancelled':
                return
            if result.stderr.strip() == 'timed out':
                with jobs_lock:
                    jobs[job_id]['status'] = 'error'
                    jobs[job_id]['note'] = 'timed out'
                return
            shares, restricted_shares = parse_nxc_full(result.stdout, is_file=False)
            with jobs_lock:
                jobs[job_id]['restricted'] = restricted_shares
                jobs[job_id]['readable'] = shares
            if not shares:
                note = 'no readable shares' + (f' ({len(restricted_shares)} restricted)' if restricted_shares else '')
                combined = (result.stderr + result.stdout).lower()
                if 'logon_failure' in combined or 'logon failure' in combined or 'status_access_denied' in combined or ('authentication' in combined and 'fail' in combined):
                    note = 'authentication failed — check credentials'
                elif 'connection' in combined and ('refused' in combined or 'timed out' in combined or 'reset' in combined):
                    note = 'connection failed'
                elif 'name or service not known' in combined or 'resolve' in combined or 'dns' in combined:
                    note = 'DNS resolution failed — set DNS server'
                elif result.returncode != 0 and result.stderr.strip():
                    note = result.stderr.strip().splitlines()[-1][:60]
                with jobs_lock:
                    jobs[job_id]['status'] = 'done'
                    jobs[job_id]['note'] = note
                return

            safe = re.sub(r'[/\\:]', '_', host)
            outfile = f'smblist_{safe}'

            setstatus(f'enumerating {len(shares)} share(s)')
            fh = None
            share_errors = []
            try:
                for share in shares:
                    if is_cancelled(job_id):
                        break
                    new_paths, err = smbclient_ls(share, creds, use_proxy, dns_server=dns,
                                                   on_start=lambda proc: register_proc(job_id, proc),
                                                   cancel_check=lambda: is_cancelled(job_id))
                    unregister_proc(job_id)
                    if new_paths:
                        with paths_lock:
                            live_paths.extend(new_paths)
                        with jobs_lock:
                            jobs[job_id]['found'] += len(new_paths)
                            jobs[job_id]['current'] = new_paths[-1]
                        if fh is None:
                            fh = open(outfile, 'w')
                        fh.write('\n'.join(new_paths) + '\n')
                        fh.flush()
                    elif err:
                        share_errors.append(f"{share.rsplit('/', 1)[-1]}: {err}")
            finally:
                if fh:
                    fh.close()

            if not is_cancelled(job_id):
                setstatus('done')
                with jobs_lock:
                    if jobs[job_id]['found'] == 0 and not jobs[job_id].get('note'):
                        jobs[job_id]['note'] = '; '.join(share_errors)[:150] if share_errors else 'no files found'
        except Exception as e:
            if not is_cancelled(job_id):
                with jobs_lock:
                    jobs[job_id]['status'] = 'error'
                    jobs[job_id]['note'] = str(e)

    def bg_scan_share(job_id, share_path, use_proxy, dns=''):
        try:
            with jobs_lock:
                jobs[job_id]['status'] = 'scanning'
            if is_cancelled(job_id):
                return
            new_paths, err = smbclient_ls(share_path, creds, use_proxy, dns_server=dns, timeout=600,
                                           on_start=lambda proc: register_proc(job_id, proc),
                                           cancel_check=lambda: is_cancelled(job_id))
            unregister_proc(job_id)
            if is_cancelled(job_id):
                return
            if new_paths:
                with paths_lock:
                    live_paths.extend(new_paths)
                host_part = share_path.lstrip('/').split('/')[0] if '/' in share_path.lstrip('/') else share_path
                safe = re.sub(r'[/\\: ]', '_', host_part)
                outfile = f'smblist_{safe}'
                with open(outfile, 'a') as fh:
                    fh.write('\n'.join(new_paths) + '\n')
                with jobs_lock:
                    jobs[job_id]['found'] = len(new_paths)
                    jobs[job_id]['current'] = new_paths[-1]
            with jobs_lock:
                jobs[job_id]['status'] = 'done'
                if not new_paths:
                    jobs[job_id]['note'] = err or 'no files found'
        except Exception as e:
            if not is_cancelled(job_id):
                with jobs_lock:
                    jobs[job_id]['status'] = 'error'
                    jobs[job_id]['note'] = str(e)

    def scan_worker():
        while True:
            job_id, host, use_proxy, dns = scan_queue.get()
            try:
                bg_run_host(job_id, host, use_proxy, dns)
            finally:
                scan_queue.task_done()

    for _ in range(SCAN_WORKERS):
        threading.Thread(target=scan_worker, daemon=True).start()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def send_json(self, data):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-cache, no-store')
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())

        def do_GET(self):
            p = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(p.query)
            use_proxy = qs.get('proxy', ['0'])[0] == '1'

            if p.path == '/':
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Cache-Control', 'no-cache, no-store')
                self.end_headers()
                self.wfile.write(HTML.encode())

            elif p.path == '/paths':
                with paths_lock:
                    snapshot = list(dict.fromkeys(live_paths))
                self.send_json(snapshot)

            elif p.path == '/jobs':
                with jobs_lock:
                    snapshot = dict(jobs)
                self.send_json(snapshot)

            elif p.path == '/setdns':
                dns_server[0] = qs.get('dns', [''])[0].strip()
                self.send_json({'ok': True})

            elif p.path == '/addhost':
                host = qs.get('host', [''])[0].strip()
                dns = qs.get('dns', [''])[0].strip() or dns_server[0]
                if dns:
                    dns_server[0] = dns
                if not host:
                    self.send_json({'ok': False, 'msg': 'no host provided'})
                    return
                # only block if a job is currently active (queued/running)
                with jobs_lock:
                    active_job = any(
                        j['host'].lower() == host.lower() and
                        j['status'] not in ('done', 'error')
                        for j in jobs.values()
                    )
                if active_job:
                    self.send_json({'ok': False, 'msg': f'{host} is already being scanned', 'skip': True})
                    return
                with jobs_lock:
                    job_counter[0] += 1
                    job_id = str(job_counter[0])
                    jobs[job_id] = {'host': host, 'status': 'queued', 'found': 0, 'note': '', 'current': '', 'restricted': [], 'readable': []}
                scan_queue.put((job_id, host, use_proxy, dns))
                self.send_json({'ok': True, 'id': job_id})

            elif p.path == '/loadfile':
                path = qs.get('path', [''])[0]
                try:
                    with open(path) as f:
                        loaded = [l.strip() for l in f if l.strip()]
                    self.send_json({'ok': True, 'paths': loaded})
                except Exception as e:
                    self.send_json({'ok': False, 'msg': str(e)})

            elif p.path == '/cat':
                path = qs.get('path', [''])[0]
                share, d, fname = parse_smb_path(path)
                filepath = d.rstrip('/') + '/' + fname if fname else d
                tmppath = f'/tmp/smblist_preview_{threading.get_ident()}'
                result = run_cmd(
                    ['smbclient', share, '-U', creds, '-c',
                     f'get "{filepath}" {tmppath}'],
                    use_proxy, timeout=30
                )
                try:
                    CAP = 512 * 1024
                    with open(tmppath, 'rb') as f:
                        raw = f.read(CAP + 1)
                    os.remove(tmppath)
                    truncated = len(raw) > CAP
                    content = raw[:CAP].decode('utf-8', errors='replace')
                    self.send_json({'ok': True, 'content': content, 'truncated': truncated})
                except:
                    try: os.remove(tmppath)
                    except: pass
                    self.send_json({'ok': False,
                                    'msg': result.stderr.strip() or 'could not read file'})

            elif p.path == '/download':
                path = qs.get('path', [''])[0]
                share, d, fname = parse_smb_path(path)
                filepath = d.rstrip('/') + '/' + fname if fname else d
                local_dir = os.path.join('smblist', 'downloads')
                os.makedirs(local_dir, exist_ok=True)
                safe_name = path.lstrip('/').replace('/', '_').replace(' ', '-')
                local_path = os.path.join(local_dir, safe_name)
                result = run_cmd(
                    ['smbclient', share, '-U', creds, '-c', f'get "{filepath}" {local_path}'],
                    use_proxy
                )
                if os.path.exists(local_path):
                    self.send_json({'ok': True, 'msg': local_path})
                else:
                    self.send_json({'ok': False, 'msg': result.stderr.strip()})

            elif p.path == '/groups':
                with gui_groups_lock:
                    data = list(gui_groups)
                self.send_json(data)

            elif p.path == '/extdescs':
                with ext_descs_lock:
                    data = dict(ext_descs)
                self.send_json(data)

            elif p.path == '/dlstatus':
                self.send_json(dl_status[0])

            elif p.path == '/stopall':
                cancelled = 0
                drained = []
                while True:
                    try:
                        drained.append(scan_queue.get_nowait())
                    except queue.Empty:
                        break
                with jobs_lock:
                    for job_id, host, use_proxy, dns in drained:
                        j = jobs.get(job_id)
                        if j and j['status'] not in ('done', 'error'):
                            j['status'] = 'error'
                            j['note'] = 'cancelled'
                            j['cancelled'] = True
                            cancelled += 1
                    for job_id, j in jobs.items():
                        if j['status'] not in ('done', 'error'):
                            j['cancelled'] = True
                            j['status'] = 'error'
                            j['note'] = 'cancelled'
                            cancelled += 1
                with active_procs_lock:
                    procs = list(active_procs.values())
                for proc in procs:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                self.send_json({'ok': True, 'cancelled': cancelled})

            elif p.path == '/scanshare':
                share_path = qs.get('share', [''])[0].strip()
                if not share_path:
                    self.send_json({'ok': False, 'msg': 'no share'})
                    return
                with jobs_lock:
                    job_counter[0] += 1
                    job_id = str(job_counter[0])
                    jobs[job_id] = {'host': share_path, 'status': 'queued', 'found': 0,
                                    'note': '', 'current': '', 'restricted': [], 'share_scan': True}
                dns = dns_server[0]
                threading.Thread(target=bg_scan_share,
                                 args=(job_id, share_path, use_proxy, dns),
                                 daemon=True).start()
                self.send_json({'ok': True, 'id': job_id})

            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            p = urllib.parse.urlparse(self.path)
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length) or b'{}')

            if p.path == '/downloadall':
                paths = body.get('paths', [])
                use_proxy = bool(body.get('proxy', False))
                ext_folders = bool(body.get('extfolders', False))
                if not paths:
                    self.send_json({'ok': False, 'msg': 'no paths'})
                    return

                def do_dl_all():
                    dl_status[0] = {'running': True, 'done': 0, 'failed': 0, 'total': len(paths)}
                    lock = threading.Lock()

                    base_dir = os.path.join('smblist', 'downloads')
                    os.makedirs(base_dir, exist_ok=True)

                    def download_one(path):
                        try:
                            share, d, fname = parse_smb_path(path)
                            if not fname:
                                with lock: dl_status[0]['failed'] += 1
                                return
                            filepath = d.rstrip('/') + '/' + fname
                            safe_name = path.lstrip('/').replace('/', '_').replace(' ', '-')
                            if ext_folders:
                                ext = os.path.splitext(fname)[1].lstrip('.').lower() or 'no_ext'
                                local_dir = os.path.join(base_dir, ext)
                                os.makedirs(local_dir, exist_ok=True)
                            else:
                                local_dir = base_dir
                            local_path = os.path.join(local_dir, safe_name)
                            for attempt in range(3):
                                run_cmd(['smbclient', share, '-U', creds, '-c',
                                         f'get "{filepath}" {local_path}'], use_proxy)
                                if os.path.exists(local_path):
                                    break
                                if attempt < 2:
                                    time.sleep(2)
                            with lock:
                                if os.path.exists(local_path):
                                    dl_status[0]['done'] += 1
                                else:
                                    dl_status[0]['failed'] += 1
                        except Exception:
                            with lock: dl_status[0]['failed'] += 1

                    with ThreadPoolExecutor(max_workers=30) as pool:
                        pool.map(download_one, paths)
                    dl_status[0]['running'] = False

                threading.Thread(target=do_dl_all, daemon=True).start()
                self.send_json({'ok': True, 'count': len(paths)})

            elif p.path == '/savegroups':
                new_groups = body if isinstance(body, list) else []
                with gui_groups_lock:
                    gui_groups.clear()
                    gui_groups.extend(new_groups)
                try:
                    with open(gui_groups_file, 'w') as fh:
                        json.dump(new_groups, fh)
                except Exception:
                    pass
                self.send_json({'ok': True})

            elif p.path == '/lookupexts':
                raw = body.get('exts', [])
                with ext_descs_lock:
                    to_fetch = [e for e in raw
                                if isinstance(e, str) and re.match(r'^[a-z0-9_]+$', e)
                                and len(e) <= 20 and e not in ext_descs]
                self.send_json({'queued': len(to_fetch)})

                def _fetch_exts(exts_list):
                    for ext in exts_list:
                        with ext_descs_lock:
                            if ext in ext_descs:
                                continue
                        try:
                            req = urllib.request.Request(
                                f'https://fileinfo.com/extension/{ext}',
                                headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}
                            )
                            html = urllib.request.urlopen(req, timeout=8).read().decode('utf-8', errors='replace')
                            desc = None
                            m = re.search(r'<meta name="description" content="([^"]{10,180})"', html)
                            if m:
                                desc = m.group(1).strip()
                                desc = re.sub(r'\s+', ' ', desc)
                            if not desc:
                                m2 = re.search(r'<h1[^>]*>([^<]+?)\s+File</h1>', html, re.IGNORECASE)
                                if m2:
                                    desc = m2.group(1).strip() + ' File'
                            if desc:
                                with ext_descs_lock:
                                    ext_descs[ext] = desc
                                with open(ext_descs_file, 'a') as fh:
                                    fh.write(f'{ext}={desc}\n')
                                    fh.flush()
                        except Exception:
                            pass
                        time.sleep(0.5)

                if to_fetch:
                    threading.Thread(target=_fetch_exts, args=(to_fetch,), daemon=True).start()

            else:
                self.send_response(404)
                self.end_headers()

    port = 18888

    def _wsl_ip():
        try:
            with open('/proc/version') as f:
                if 'microsoft' not in f.read().lower():
                    return None
            r = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=3)
            ip = r.stdout.strip().split()[0] if r.stdout.strip() else None
            return ip
        except Exception:
            return None

    wsl_ip = _wsl_ip()
    url = f'http://{wsl_ip}:{port}' if wsl_ip else f'http://127.0.0.1:{port}'
    print(f'smblist running at {url}')
    print('Press Ctrl+C to stop')

    def _open_browser():
        if wsl_ip:
            try:
                subprocess.Popen(['explorer.exe', url], stderr=subprocess.DEVNULL)
                return
            except Exception:
                pass
        webbrowser.open(url)

    threading.Timer(1, _open_browser).start()
    ThreadingHTTPServer(('0.0.0.0', port), Handler).serve_forever()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def usage():
    print(__doc__)
    sys.exit(1)


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        usage()

    if sys.argv[1] == '-nxc':
        if len(sys.argv) < 3:
            usage()
        for s in parse_nxc(sys.argv[2]):
            print(s)
        return

    creds = sys.argv[1]
    args = sys.argv[2:]
    domain, user, passwd = parse_creds(creds)

    if '-d' in args:
        idx = args.index('-d')
        if idx + 1 >= len(args):
            usage()
        domain = args[idx + 1]
        args = [a for i, a in enumerate(args) if i != idx and i != idx + 1]
        creds = f'{domain}/{user}%{passwd}'

    outfile = None
    if '-o' in args:
        idx = args.index('-o')
        outfile = args[idx + 1]
        args = [a for i, a in enumerate(args) if i != idx and i != idx + 1]
        open(outfile, 'w').close()

    if not args:
        shares = [l.strip() for l in sys.stdin if l.strip()]
        run_smblist(shares, creds, outfile=outfile)

    elif args[0] == '-gui':
        gui_args = args[1:]
        pathsfile = ''
        if '-dir' in gui_args:
            idx = gui_args.index('-dir')
            if idx + 1 < len(gui_args):
                target_dir = gui_args[idx + 1]
                try:
                    os.chdir(target_dir)
                    print(f'Working directory: {os.path.abspath(".")}', file=sys.stderr)
                except Exception as e:
                    print(f'Cannot change to directory {target_dir!r}: {e}', file=sys.stderr)
                    sys.exit(1)
                gui_args = [a for i, a in enumerate(gui_args) if i != idx and i != idx + 1]
        if gui_args and not gui_args[0].startswith('-'):
            pathsfile = gui_args[0]
        start_gui(creds, pathsfile)

    elif args[0] == '-get':
        download_file(args[1], creds)

    elif args[0] == '-nxc':
        for s in parse_nxc(args[1]):
            print(s)

    elif args[0] == '-host':
        target = args[1]
        if os.path.isfile(target):
            with open(target) as f:
                for host in f:
                    host = host.strip()
                    if host:
                        run_host(host, creds, user, passwd, domain)
        else:
            run_host(target, creds, user, passwd, domain)

    else:
        sharesfile = args[0]
        with open(sharesfile) as f:
            shares = [l.strip() for l in f if l.strip()]
        run_smblist(shares, creds, outfile=outfile)


if __name__ == '__main__':
    main()
