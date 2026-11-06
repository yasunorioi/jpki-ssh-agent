#!/usr/bin/env python3
# jpki_agent.py — マイナンバーカード(利用者証明用鍵)を署名鍵にする ssh-agent。
# JPKI署名APDUを直接駆動し、ssh-agentプロトコルを素で喋る。PC/SC も OpenSC も不要。
#
# transport は 2バックエンド自動選択:
#   PC/SC(pyscard)  … ほぼ全ての CCID リーダー (Sony RC-S300 / ACR1252U 等)
#   nfcpy           … Sony PaSoRi RC-S330/360/370/380 等 (CCID非準拠でPC/SC不可な機種)
# どちらか一方が入っていれば動く。環境変数 JPKI_BACKEND=pcsc|nfc で強制も可。
#
# 使い方:
#   公開鍵(authorized_keys行)を出す : python jpki_agent.py --print-key
#   agent を前面で起動             : python jpki_agent.py
#     -> 表示される export SSH_AUTH_SOCK=... を ssh する端末で設定するだけ。
#        署名が要るたびこの端末に「カード+PIN」プロンプトが出る。
import os, sys, socket, struct, getpass, base64, time, pathlib, threading, subprocess
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

try:
    import nfc
    HAVE_NFC = True
except Exception:
    HAVE_NFC = False
try:
    from smartcard.System import readers as _pcsc_readers
    HAVE_PCSC = True
except Exception:
    HAVE_PCSC = False

# ---- JPKI 利用者証明用 AP / APDU 定数(実機確認済み) ----
AUTH_AP  = bytes.fromhex("D392F000260100000001")
SEL_AP   = bytes([0x00,0xA4,0x04,0x0C,len(AUTH_AP)]) + AUTH_AP
SEL_PIN  = bytes.fromhex("00A4020C020018")   # 利用者証明用PIN EF
SEL_KEY  = bytes.fromhex("00A4020C020017")   # 利用者証明用鍵 EF
SEL_CERT = bytes.fromhex("00A4020C02000A")   # 利用者証明用証明書 EF
QUERY_PIN = bytes.fromhex("00200080")        # 空VERIFY=残回数照会(減算なし)
RSA_SHA2_256, RSA_SHA2_512 = 2, 4
HASHSPEC = {  # ssh署名アルゴ名 -> (hash, DigestInfo prefix)
    "rsa-sha2-256": (hashes.SHA256(), bytes.fromhex("3031300d060960864801650304020105000420")),
    "rsa-sha2-512": (hashes.SHA512(), bytes.fromhex("3051300d060960864801650304020305000440")),
    "ssh-rsa":      (hashes.SHA1(),   bytes.fromhex("3021300906052b0e03021a05000414")),
}
C_REQUEST_IDENTITIES, C_SIGN_REQUEST = 11, 13
A_FAILURE, A_IDENTITIES_ANSWER, A_SIGN_RESPONSE = 5, 12, 14

def hx(b): return bytes(b).hex().upper()
def _ok(r): return r[-2:] == b"\x90\x00"
class CardError(Exception): pass

# ================= transport 抽象 =================
class Transport:
    label = "?"
    def transceive(self, apdu: bytes) -> bytes: raise NotImplementedError
    def close(self): pass

class PCSCTransport(Transport):
    def __init__(self, conn, label): self.conn = conn; self.label = label
    def transceive(self, apdu):
        data, sw1, sw2 = self.conn.transmit(list(apdu))
        while sw1 == 0x61:                                  # more data (T=0保険)
            data2, sw1, sw2 = self.conn.transmit([0x00,0xC0,0x00,0x00, sw2]); data += data2
        if sw1 == 0x6C:                                     # wrong Le (READ BINARY保険)
            data, sw1, sw2 = self.conn.transmit(list(apdu[:4]) + [sw2])
        return bytes(data) + bytes([sw1, sw2])
    def close(self):
        try: self.conn.disconnect()
        except Exception: pass

class NFCTransport(Transport):
    def __init__(self, clf, tag, label): self.clf = clf; self.tag = tag; self.label = label
    def transceive(self, apdu):
        return bytes(self.tag.transceive(bytes(apdu), timeout=10.0))
    def close(self):
        try: self.clf.close()
        except Exception: pass

def _open_pcsc(deadline):
    if not HAVE_PCSC: return None
    try: rlist = list(_pcsc_readers())
    except Exception: return None
    if not rlist: return None
    while time.time() < deadline:
        for r in rlist:
            try:
                conn = r.createConnection(); conn.connect()   # カード無しは例外
                return PCSCTransport(conn, f"PC/SC:{r}")
            except Exception:
                continue
        time.sleep(0.3)
    return None

def _open_nfc(deadline):
    if not HAVE_NFC: return None
    try: clf = nfc.ContactlessFrontend('usb')
    except Exception: return None
    tag = clf.connect(rdwr={'on-connect': lambda t: False, 'beep-on-connect': False},
                      terminate=lambda: time.time() > deadline)
    if tag is None or not hasattr(tag, "transceive"):
        clf.close(); return None
    return NFCTransport(clf, tag, f"nfcpy:{clf.device}")

def open_card(what, timeout=30):
    forced = os.environ.get("JPKI_BACKEND", "").lower()
    if forced == "pcsc": order = [_open_pcsc]
    elif forced == "nfc": order = [_open_nfc]
    else: order = [_open_pcsc, _open_nfc]            # PC/SC優先→nfcpyフォールバック
    sys.stderr.write(f">>> {what}: カードをかざしてください...\n")
    deadline = time.time() + timeout
    for opener in order:
        t = opener(deadline)
        if t:
            sys.stderr.write(f"    [{t.label}]\n")
            return t
    raise CardError("カード/対応リーダーが見つからない "
                    f"(pyscard={HAVE_PCSC}, nfcpy={HAVE_NFC})")

# ================= JPKI 操作(transport越し) =================
def _read_binary(t):
    r = t.transceive(bytes.fromhex("00B0000000"))
    if not _ok(r): raise CardError(f"READ BINARY SW={hx(r[-2:])}")
    buf = bytearray(r[:-2])
    nlen = buf[1] & 0x7F
    total = (2 + nlen + int.from_bytes(buf[2:2+nlen], "big")) if (buf[1] & 0x80) else (2 + buf[1])
    while len(buf) < total:
        off = len(buf)
        r = t.transceive(bytes([0x00,0xB0,(off>>8)&0x7F,off&0xFF,0x00]))
        if not _ok(r): raise CardError(f"READ BINARY@{off} SW={hx(r[-2:])}")
        buf += r[:-2]
    return bytes(buf[:total])

def _verify(t, pin=None):
    """SELECT PIN EF -> 残回数ゲート -> (pin未指定なら getpass) -> VERIFY 1回。失敗で即例外, リトライ禁止。"""
    if not _ok(t.transceive(SEL_PIN)): raise CardError("SELECT PIN EF 失敗")
    r = t.transceive(QUERY_PIN)
    rem = (r[-1] & 0x0F) if (r[-2] == 0x63 and (r[-1] & 0xF0) == 0xC0) else None
    if rem is None or rem < 2:
        raise CardError(f"残り試行回数={rem} → ロック回避のため中断")
    if pin is None:                                          # 対話モード
        sys.stderr.write(f"  [残り試行 {rem} 回] ")
        pin = getpass.getpass("利用者証明用PIN(4桁): ").strip()
    if not (pin.isdigit() and len(pin) == 4): raise CardError("PINが4桁数字でない")
    r = t.transceive(bytes([0x00,0x20,0x00,0x80,len(pin)]) + pin.encode("ascii"))
    if not _ok(r):
        if r[-2] == 0x63 and (r[-1] & 0xF0) == 0xC0:
            raise CardError(f"PIN不一致(残り{r[-1]&0x0F}回) → リトライせず中断")
        raise CardError(f"VERIFY 失敗 SW={hx(r[-2:])}")

def extract_pubkey():
    t = open_card("公開鍵をカードから抽出")
    try:
        if not _ok(t.transceive(SEL_AP)): raise CardError("SELECT AP 失敗")
        if not _ok(t.transceive(SEL_CERT)):     # 証明書EFがPIN必須なら一度照合
            _verify(t)
            if not _ok(t.transceive(SEL_CERT)): raise CardError("SELECT 証明書EF 失敗")
        cert = x509.load_der_x509_certificate(_read_binary(t))
        return cert.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    finally:
        t.close()

def card_sign(data, algo, pin=None):
    hashalg, prefix = HASHSPEC[algo]
    h = hashes.Hash(hashalg); h.update(data); digest_info = prefix + h.finalize()
    t = open_card(f"SSH署名({algo})")
    try:
        if not _ok(t.transceive(SEL_AP)): raise CardError("SELECT AP 失敗")
        _verify(t, pin)                                      # VERIFY 直後に鍵選択→署名
        if not _ok(t.transceive(SEL_KEY)): raise CardError("SELECT 鍵EF 失敗")
        apdu = bytes([0x80,0x2A,0x00,0x80,len(digest_info)]) + digest_info + bytes([0x00])
        r = t.transceive(apdu)
        if not _ok(r): raise CardError(f"COMPUTE SIG 失敗 SW={hx(r[-2:])}")
        return bytes(r[:-2])
    finally:
        t.close()

# ================= ssh-agent ワイヤ =================
def ps(b): return struct.pack(">I", len(b)) + b
def gstr(buf, off):
    (n,) = struct.unpack(">I", buf[off:off+4]); off += 4
    return buf[off:off+n], off+n
def pubkey_blob(line): return base64.b64decode(line.split()[1])

def recvall(conn, n):
    out = b""
    while len(out) < n:
        chunk = conn.recv(n - len(out))
        if not chunk: return None
        out += chunk
    return out
def read_msg(conn):
    hdr = recvall(conn, 4)
    if not hdr: return None
    (n,) = struct.unpack(">I", hdr)
    return recvall(conn, n)
def send_msg(conn, body): conn.sendall(struct.pack(">I", len(body)) + body)

def handle(conn, blob, comment, signer=None):
    while True:
        msg = read_msg(conn)
        if msg is None: return
        mtype, payload = msg[0], msg[1:]
        if mtype == C_REQUEST_IDENTITIES:
            send_msg(conn, bytes([A_IDENTITIES_ANSWER]) + struct.pack(">I", 1)
                     + ps(blob) + ps(comment.encode()))
        elif mtype == C_SIGN_REQUEST:
            key, off = gstr(payload, 0)
            data, off = gstr(payload, off)
            (flags,) = struct.unpack(">I", payload[off:off+4])
            if key != blob:
                send_msg(conn, bytes([A_FAILURE])); continue
            algo = "rsa-sha2-512" if (flags & RSA_SHA2_512) else \
                   "rsa-sha2-256" if (flags & RSA_SHA2_256) else "ssh-rsa"
            try:
                sig = (signer or card_sign)(data, algo)
            except Exception as e:
                sys.stderr.write(f"!! 署名失敗: {e}\n")
                send_msg(conn, bytes([A_FAILURE])); continue
            send_msg(conn, bytes([A_SIGN_RESPONSE]) + ps(ps(algo.encode()) + ps(sig)))
            sys.stderr.write("    署名OK\n")
        else:
            send_msg(conn, bytes([A_FAILURE]))

# ================= main =================
def load_or_extract_pubkey():
    cache = pathlib.Path.home() / ".config" / "jpki-agent" / "pubkey.pub"
    if cache.exists():
        return cache.read_text().strip()
    line = extract_pubkey()
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(line + "\n")
    sys.stderr.write(f"    公開鍵を {cache} にキャッシュしました。\n")
    return line

def run_ssh(ssh_args):
    """1端末完結モード: 先にPINを読み、非対話agentを裏で立て、ssh を exec する。"""
    cache = pathlib.Path.home() / ".config" / "jpki-agent" / "pubkey.pub"
    if not cache.exists():
        sys.exit("先に `--print-key` を一度実行して公開鍵をキャッシュしてください。")
    blob = pubkey_blob(cache.read_text().strip())
    sys.stderr.write(">>> カードをリーダーに載せてから PIN を入力してください。\n")
    pin = getpass.getpass("利用者証明用PIN(4桁): ").strip()
    if not (pin.isdigit() and len(pin) == 4):
        sys.exit("PINが4桁数字でない")

    sock_dir = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    sock_path = os.path.join(sock_dir, f"jpki-agent.{os.getpid()}.sock")
    if os.path.exists(sock_path): os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path); os.chmod(sock_path, 0o600); srv.listen(5); srv.settimeout(0.5)

    stop = threading.Event()
    signer = lambda data, algo: card_sign(data, algo, pin=pin)
    def serve():
        while not stop.is_set():
            try: conn, _ = srv.accept()
            except socket.timeout: continue
            except OSError: break
            try: handle(conn, blob, "jpki-mynumber-auth", signer=signer)
            except Exception: pass
            finally: conn.close()
    th = threading.Thread(target=serve, daemon=True); th.start()

    env = dict(os.environ, SSH_AUTH_SOCK=sock_path)
    cmd = ["ssh", "-o", "IdentitiesOnly=yes", "-i", str(cache)] + list(ssh_args)
    try:
        rc = subprocess.call(cmd, env=env)
    finally:
        stop.set(); srv.close()
        if os.path.exists(sock_path): os.unlink(sock_path)
    sys.exit(rc)

def main():
    if not (HAVE_PCSC or HAVE_NFC):
        sys.exit("エラー: pyscard も nfcpy も import できません。どちらか入れてください。")
    args = sys.argv[1:]
    if args and args[0] == "--print-key":
        print(load_or_extract_pubkey()); return
    if args and args[0] == "ssh":
        run_ssh(args[1:]); return
    line = load_or_extract_pubkey()
    blob = pubkey_blob(line)
    sock_dir = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    sock_path = os.path.join(sock_dir, f"jpki-agent.{os.getpid()}.sock")
    if os.path.exists(sock_path): os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path); os.chmod(sock_path, 0o600); srv.listen(5)
    print(f"jpki-agent 起動 (pyscard={HAVE_PCSC}, nfcpy={HAVE_NFC})。別端末で:\n")
    print(f"    export SSH_AUTH_SOCK={sock_path}\n")
    print(f"authorized_keys 用公開鍵:\n{line}\n")
    print("Ctrl-C で終了。", file=sys.stderr)
    try:
        while True:
            conn, _ = srv.accept()
            try: handle(conn, blob, "jpki-mynumber-auth")
            finally: conn.close()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
        if os.path.exists(sock_path): os.unlink(sock_path)
        sys.stderr.write("\njpki-agent 終了。\n")

if __name__ == "__main__":
    main()
