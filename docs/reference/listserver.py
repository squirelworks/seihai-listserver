"""Lab listserver for real Graal clients, Seihai and GServer-v2.

Lab only: binds 127.0.0.1, never forwards anything off loopback, and by
default accepts every account. Python 3 standard library only.

Ports: 14900 for gservers, 14921/14922/14923 for clients.

Client side (what each login shape gets back):
  id 0 list name alone, plain zlib (2.00, 2.05; shape A): id 0 server list,
      then id 2 status. This is the reply real 2.05 accepted in the lab.
  id 0 + id 1 account/password in one frame (2.17; shape B): the same reply,
      once, after the account.
  id 4 key + token (gen 4, 2.19 to 2.21): bz2 frames, partial XOR.
  id 5 key + token (RC list, gen 5): every server, type-tagged.
  id 7 key + token + list name (gen 5, 2.22 and 2.31): after id 1, two
      zlib (ctype 4) frames: id 0 list, then id 2 status, id 3 site URL and
      id 5 upgrade URL. This is the shape the public listserver sends on 14922
      (Graal_analysis protocol/public-listserver-2026-10-25.md).
  A refused login gets id 4 (error text) and the link is closed.

Gserver side: SVO_REGISTERV3 (one uncompressed line), then zlib frames.
  NEWSERVER, SERVERHQLEVEL, SETPLYR/PLYRADD/PLYRREM (player count), VERIACC2
  (answered SUCCESS, or the account error), SETIP (the 60 s keep-alive of
  GServer-v2 beta4), PING (a pong: logged, never answered). A gserver's entry
  is dropped from the list when its link closes.

Usage: python3 listserver.py [LOGFILE] [--accounts FILE] [--name TEXT]
  --accounts FILE   lines of "account password"; only these may log in.
"""
import argparse, asyncio, bz2, struct, time, zlib

SITE_URL = b''     # set your own; empty by default
UPGRADE_URL = b''  # set your own; empty by default

# Client to listserver ids, and listserver to client ids.
PLI_V1VER, PLI_SERVERLIST, PLI_V2VER, PLI_V2SERVERLISTRC, PLI_V2ENCRYPTKEYCL = 0, 1, 4, 5, 7
PLO_SVRLIST, PLO_STATUS, PLO_SITEURL, PLO_ERROR, PLO_UPGURL = 0, 2, 3, 4, 5
# Gserver to listserver (SVO) and listserver to gserver (SVI) ids, gs2lib names.
SVO_SETIP, SVO_SETPLYR, SVO_PLYRADD, SVO_PLYRREM, SVO_PING, SVO_VERIACC2 = 5, 7, 14, 15, 16, 17
SVO_NEWSERVER, SVO_SERVERHQPASS, SVO_SERVERHQLEVEL, SVO_SENDTEXT = 22, 23, 24, 31
SVI_VERIACC2 = 11
# HQ level to list tag, as graal-serverlist: 0 hidden, 1 bronze, 2 classic, 3 gold, 4 G3D.
HQ_TAG = {0: b'U ', 1: b'H ', 2: b'', 3: b'P ', 4: b'3 '}

ARGS = None
LOG = None
SERVERS = {}   # gserver writer -> entry dict
ACCOUNTS = None  # None: accept everything; else {account: password}


def log(*a):
    LOG.write(time.strftime('%H:%M:%S ') + ' '.join(str(x) for x in a) + '\n')


def gchar(n): return bytes([n + 32])
def gstr(s): return gchar(len(s)) + s
def gshort(b): return ((b[0] - 32) << 7) | (b[1] - 32)


class Codec:
    """Gen 4/5 partial XOR stream (gs2lib CEncryption). One per direction."""
    LIMIT = {2: 0x0C, 4: 0x04, 6: 0x04}

    def __init__(self, key):
        self.key, self.it = key, 0x4A80B38

    def apply(self, buf, ctype):
        limit = self.LIMIT.get(ctype, -1)
        out = bytearray(buf)
        for i in range(len(out)):
            if i % 4 == 0:
                if limit == 0:
                    break
                self.it = (self.it * 0x8088405 + self.key) & 0xFFFFFFFF
                if limit > 0:
                    limit -= 1
            out[i] ^= struct.pack('<I', self.it)[i % 4]
        return bytes(out)


def account_error(acct, password):
    """None when the login is allowed, else the error text."""
    if ACCOUNTS is None:
        return None
    if acct not in ACCOUNTS:
        return b'Account does not exist.'
    if ACCOUNTS[acct] != password:
        return b'Your password is incorrect.'
    return None


def server_list(tagged):
    rows = [e for e in SERVERS.values() if 'name' in e]
    out = gchar(PLO_SVRLIST) + gchar(len(rows))
    for e in rows:
        name = (HQ_TAG.get(e['hq'], b'') if tagged else b'') + e['name']
        players = str(len(e['players'])).encode()
        out += gchar(8) + b''.join(gstr(f) for f in (
            name, e['lang'], e['desc'], e['url'], e['ver'], players, e['ip'], e['port']))
    return out


def status_text(acct):
    n = len([e for e in SERVERS.values() if 'name' in e])
    return gchar(PLO_STATUS) + b'Welcome to ' + ARGS.name.encode() + b', ' + acct + b'.\r' \
        + b'There are ' + str(n).encode() + b' server(s) online.'


async def client(reader, writer, port):
    peer = writer.get_extra_info('peername')
    log('client', port, peer)
    gen, cin, cout, tagged, buf = 2, None, None, False, b''

    def send(lines, ctype=4):
        data = b''.join(l + b'\n' for l in lines)
        if gen == 2:
            body = zlib.compress(data)
        elif gen == 4:   # whole frame bz2, no compression byte
            body = cout.apply(bz2.compress(data), 6)
        else:            # gen 5: compression byte, then the XORed body
            body = bytes([ctype]) + cout.apply(zlib.compress(data) if ctype == 4 else data, ctype)
        writer.write(struct.pack('>H', len(body)) + body)

    def decode(body):
        if gen == 2:
            return zlib.decompress(body)
        if gen == 4:
            return bz2.decompress(cin.apply(body, 6))
        ctype, rest = body[0], cin.apply(body[1:], body[0])
        return {2: lambda b: b, 4: zlib.decompress, 6: bz2.decompress}[ctype](rest)

    closing = False
    while not closing:
        d = await reader.read(65536)
        if not d:
            break
        buf += d
        while len(buf) >= 2 and not closing:
            n = struct.unpack('>H', buf[:2])[0]
            if len(buf) < n + 2:
                break
            body, buf = buf[2:n + 2], buf[n + 2:]
            try:
                raw = decode(body)
            except Exception as e:
                log('client undecodable gen', gen, e, body[:40].hex())
                continue
            msgs = [l for l in raw.split(b'\n') if l]
            has_account = any(l[0] - 32 == PLI_SERVERLIST for l in msgs)
            for line in msgs:
                pid = line[0] - 32
                if pid == PLI_SERVERLIST:
                    al = line[1] - 32
                    acct = line[2:2 + al]
                    pw = line[3 + al:3 + al + line[2 + al] - 32]
                    log('client', port, 'account', acct)
                    err = account_error(acct, pw)
                    if err:
                        log('client', port, 'refused', acct, err)
                        send([gchar(PLO_ERROR) + err])
                        closing = True
                        break
                    if gen == 5:
                        send([server_list(tagged)])
                        send([status_text(acct), gchar(PLO_SITEURL) + SITE_URL, gchar(PLO_UPGURL) + UPGRADE_URL])
                    else:
                        send([server_list(tagged), status_text(acct)])
                elif pid == PLI_V1VER:
                    log('client', port, 'v1ver', line[1:])
                    if not has_account:  # 2.00 and 2.05 send the list name only
                        send([server_list(False), status_text(b'player')])
                elif pid in (PLI_V2VER, PLI_V2SERVERLISTRC, PLI_V2ENCRYPTKEYCL):
                    key = line[1] - 32
                    gen = 4 if pid == PLI_V2VER else 5
                    cin, cout = Codec(key), Codec(key)
                    tagged = True
                    log('client', port, 'handshake id', pid, 'gen', gen, 'token', line[2:10], 'list', line[10:])
                else:
                    log('client', port, 'unhandled id', pid, repr(line[1:40]))
        await writer.drain()
    writer.close()
    log('client closed', port, peer)


async def gserver(reader, writer):
    log('gserver connected', writer.get_extra_info('peername'))
    entry = SERVERS[writer] = {'players': set(), 'hq': 1}
    try:
        reg = await reader.readuntil(b'\n')  # SVO_REGISTERV3, uncompressed
    except asyncio.IncompleteReadError:
        del SERVERS[writer]
        return
    log('gserver register', reg[1:-1])
    buf = b''

    def send(line):
        z = zlib.compress(line + b'\n')
        writer.write(struct.pack('>H', len(z)) + z)

    while True:
        d = await reader.read(65536)
        if not d:
            break
        buf += d
        while len(buf) >= 2:
            n = struct.unpack('>H', buf[:2])[0]
            if len(buf) < n + 2:
                break
            body, buf = buf[2:n + 2], buf[n + 2:]
            for line in zlib.decompress(body).split(b'\n'):
                if not line:
                    continue
                pid, p = line[0] - 32, line[1:]
                if pid == SVO_NEWSERVER:
                    f, i = [], 0
                    for _ in range(8):
                        l = p[i] - 32
                        f.append(p[i + 1:i + 1 + l])
                        i += 1 + l
                    entry.update(zip(('name', 'desc', 'lang', 'ver', 'url', 'ip', 'port', 'localip'), f))
                    entry['ip'] = b'127.0.0.1'
                    log('gserver newserver', entry['name'], 'port', entry['port'], 'ver', entry['ver'])
                elif pid == SVO_SERVERHQLEVEL:
                    entry['hq'] = p[0] - 32
                elif pid == SVO_SETPLYR:
                    entry['players'].clear()
                elif pid == SVO_PLYRADD:
                    entry['players'].add(gshort(p))
                    log('gserver player add', gshort(p), 'type', p[2] - 32, 'now', len(entry['players']))
                elif pid == SVO_PLYRREM:
                    entry['players'].discard(gshort(p))
                    log('gserver player rem', gshort(p), 'now', len(entry['players']))
                elif pid == SVO_VERIACC2:
                    al = p[0] - 32
                    acct = p[1:1 + al]
                    i = 1 + al
                    pw = p[i + 1:i + 1 + p[i] - 32]
                    i += 1 + p[i] - 32
                    pidb, typ = p[i:i + 2], p[i + 2:i + 3]
                    # beta4 and efb5b90 append GSHORT length + identity ("win",hwids,os for v5+)
                    ident = ' identity %d bytes' % gshort(p[i + 3:i + 5]) if len(p) >= i + 5 else ''
                    err = account_error(acct, pw)
                    log('gserver veriacc2', acct, 'id', gshort(pidb), 'type', typ[0] - 32, ident + ',', 'refused: ' + err.decode() if err else 'ok')
                    send(gchar(SVI_VERIACC2) + gstr(acct) + pidb + typ + (err or b'SUCCESS'))
                elif pid in (SVO_SETIP, SVO_PING, SVO_SERVERHQPASS):
                    pass  # keep-alive, pong, HQ password: nothing to answer
                elif pid == SVO_SENDTEXT:
                    log('gserver sendtext', repr(p[:60]))  # e.g. Listserver,settings,allowedversions,...
                else:
                    log('gserver unhandled id', pid, repr(p[:80]))
        await writer.drain()
    SERVERS.pop(writer, None)
    log('gserver closed', entry.get('name'))


def load_accounts(path):
    out = {}
    with open(path, 'rb') as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith(b'#'):
                out[parts[0]] = parts[1]
    return out


async def main():
    global ARGS, LOG, ACCOUNTS
    ap = argparse.ArgumentParser()
    ap.add_argument('logfile', nargs='?', default='listserver.log')
    ap.add_argument('--accounts')
    ap.add_argument('--name', default='Lab listserver')
    ap.add_argument('--host', default='127.0.0.1')
    ARGS = ap.parse_args()
    LOG = open(ARGS.logfile, 'a', buffering=1)
    if ARGS.accounts:
        ACCOUNTS = load_accounts(ARGS.accounts)
    await asyncio.start_server(gserver, ARGS.host, 14900)
    for port in (14921, 14922, 14923):
        await asyncio.start_server(lambda r, w, p=port: client(r, w, p), ARGS.host, port)
    log('listening', 'accounts:', 'any' if ACCOUNTS is None else len(ACCOUNTS))
    await asyncio.Event().wait()


if __name__ == '__main__':
    asyncio.run(main())
