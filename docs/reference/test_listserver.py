"""Exercise a running lab listserver with every login shape.

Registers a fake gserver on 14900 (REGISTERV3, NEWSERVER, HQ level, two
players added and one removed, a VERIACC2), then logs in as each client shape
and checks the reply: shape A (id 0 only), shape B (id 0 + id 1), gen 4 (id 4),
gen 5 (id 7, 2.22/2.31) and the RC list (id 5).

Usage: python3 test_listserver.py [--bad-login ACCOUNT PASSWORD]
Exit 0 when every check passes.
"""
import bz2, socket, struct, sys, time, zlib

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from listserver import Codec, gchar, gstr  # noqa: E402

HOST = '127.0.0.1'
FAILS = []


def check(name, ok, detail=''):
    print(('ok   ' if ok else 'FAIL ') + name + (' : ' + detail if detail else ''))
    if not ok:
        FAILS.append(name)


def frame(body): return struct.pack('>H', len(body)) + body


def read_frames(s, wait=1.0):
    s.settimeout(wait)
    data = b''
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
    except socket.timeout:
        pass
    out = []
    while len(data) >= 2:
        n = struct.unpack('>H', data[:2])[0]
        out.append(data[2:2 + n])
        data = data[2 + n:]
    return out


def lines(raw): return [l for l in raw.split(b'\n') if l]


def fake_gserver():
    g = socket.create_connection((HOST, 14900))
    g.sendall(b'\x3e' + b'lab-test\n')  # SVO_REGISTERV3 (30) uncompressed
    fields = [b'TestWorld', b'A test server', b'English', b'3.0.9', b'http://x/', b'AUTO', b'14802', b'']
    msgs = [gchar(23) + b'',  # SERVERHQPASS
            gchar(22) + b''.join(gstr(f) for f in fields),
            gchar(24) + gchar(3),  # HQ level gold
            gchar(7),               # SETPLYR (clear)
            gchar(14) + gchar(0) + gchar(2) + gchar(0) + b'props',
            gchar(14) + gchar(0) + gchar(3) + gchar(0) + b'props',
            gchar(15) + gchar(0) + gchar(3),
            gchar(17) + gstr(b'acct') + gstr(b'pw') + gchar(0) + gchar(2) + gchar(5) + gchar(0) + gchar(3) + b'win',
            gchar(5) + gstr(b'AUTO')]  # SETIP keep-alive
    g.sendall(frame(zlib.compress(b''.join(m + b'\n' for m in msgs))))
    replies = [l for f in read_frames(g) for l in lines(zlib.decompress(f))]
    veri = [l for l in replies if l[0] - 32 == 11]
    check('gserver VERIACC2 answered', bool(veri) and veri[0].endswith(b'SUCCESS'), repr(veri[:1]))
    check('gserver gets no ping reply', all(l[0] - 32 != 99 for l in replies))
    return g


def parse_list(l):
    n, i, rows = l[1] - 32, 2, []
    for _ in range(n):
        i += 1
        row = []
        for _ in range(8):
            ln = l[i] - 32
            row.append(l[i + 1:i + 1 + ln])
            i += 1 + ln
        rows.append(row)
    return rows


def shape_plain(port, with_account, name):
    s = socket.create_connection((HOST, port))
    msg = gchar(0) + b'newmain\n'
    if with_account:
        msg += gchar(1) + gstr(b'acct') + gstr(b'pw') + b'\n'
    s.sendall(frame(zlib.compress(msg)))
    got = [l for f in read_frames(s) for l in lines(zlib.decompress(f))]
    ids = [l[0] - 32 for l in got]
    rows = parse_list(got[0]) if got and ids[0] == 0 else []
    check(name + ' list + status, once', ids == [0, 2], str(ids))
    check(name + ' row untagged, 1 player', bool(rows) and rows[0][0] == b'TestWorld' and rows[0][5] == b'1',
          repr(rows[:1]))
    s.close()


def shape_gen5(port, pid, name, account=b'acct', password=b'pw', expect_error=False):
    key = 0x45
    s = socket.create_connection((HOST, port))
    s.sendall(frame(zlib.compress(gchar(pid) + gchar(key) + b'GNW30123' + (b'newmain' if pid == 7 else b'') + b'\n')))
    cin, cout = Codec(key), Codec(key)
    body = (gchar(1) + gstr(account) + gstr(password) + b'\n')
    s.sendall(frame(bytes([2]) + cout.apply(body, 2)))
    frames = read_frames(s)
    got, ctypes = [], []
    for f in frames:
        ctypes.append(f[0])
        raw = cin.apply(f[1:], f[0])
        got.append([l[0] - 32 for l in lines(zlib.decompress(raw) if f[0] == 4 else raw)])
        if f[0] == 4 and got[-1] and got[-1][0] == 0:
            rows = parse_list(lines(zlib.decompress(raw))[0])
    if expect_error:
        check(name + ' refused with id 4', got == [[4]], str(got))
        return
    check(name + ' two zlib frames: [0] then [2,3,5]', got == [[0], [2, 3, 5]] and ctypes == [4, 4], f'{got} ctypes {ctypes}')
    if got[:1] == [[0]]:
        check(name + ' row tagged gold', rows[0][0] == b'P TestWorld', repr(rows[0][0]))
    s.close()


def shape_gen4(port):
    key = 0x21
    s = socket.create_connection((HOST, port))
    s.sendall(frame(zlib.compress(gchar(4) + gchar(key) + b'GNW15053\n')))
    cin, cout = Codec(key), Codec(key)
    s.sendall(frame(cout.apply(bz2.compress(gchar(1) + gstr(b'acct') + gstr(b'pw') + b'\n'), 6)))
    got = [[l[0] - 32 for l in lines(bz2.decompress(cin.apply(f, 6)))] for f in read_frames(s)]
    check('gen 4 (id 4) list + status', got == [[0, 2]], str(got))
    s.close()


if __name__ == '__main__':
    g = fake_gserver()
    time.sleep(0.2)
    shape_plain(14921, False, 'shape A (2.00/2.05)')
    shape_plain(14923, True, 'shape B (2.17)')
    shape_gen4(14922)
    shape_gen5(14922, 7, 'gen 5 (2.22/2.31)')
    shape_gen5(14922, 5, 'RC list (id 5)')
    if len(sys.argv) == 4 and sys.argv[1] == '--bad-login':
        shape_gen5(14922, 7, 'gen 5 bad password', sys.argv[2].encode(), sys.argv[3].encode(), expect_error=True)
    g.close()
    time.sleep(0.3)
    s = socket.create_connection((HOST, 14923))
    s.sendall(frame(zlib.compress(gchar(0) + b'newmain\n' + gchar(1) + gstr(b'acct') + gstr(b'pw') + b'\n')))
    got = [l for f in read_frames(s) for l in lines(zlib.decompress(f))]
    check('entry dropped after the gserver disconnects', got and got[0][1] - 32 == 0, repr(got[:1]))
    print('FAILED: ' + ', '.join(FAILS) if FAILS else 'all checks passed')
    sys.exit(1 if FAILS else 0)
