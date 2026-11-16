#!/usr/bin/env python3
"""TradeChannel 邀请服务（服务器侧）：管理身份、邀请签发、18443 接收。

这个文件是**服务器上**跑的那一份，由客户端经 SSH 上传后调用。它只做四件事：

1. `init`    造出这台服务器的管理身份（RSA-3072 私钥 + TLS 自签证书），此后不再改。
2. `create`  用管理私钥签一张一次性邀请，输出 `TCI1.…` 邀请码。
3. `serve`   在 18443 上提供邀请描述（`GET /v1/invitations/<id>`）与**消费**
   （`POST /v1/invitations/<id>/consume`）：新电脑在这里提交申请、换回授权、
   被加进 WireGuard。
4. `status` / `cancel`  给本机命令行用的只读投影与作废。

设计约束（与客户端 `src/pairing.rs` 逐条对齐，改一处就要改另一处）：

* 邀请码是 `TCI1.` + base64url(JSON)，字段**恰好**是 `v/h/p/i/k/t/m/e`；
* 描述符与邀请都是 RS256 紧凑 JWS，签名者是管理私钥；
* 管理身份指纹是 `SHA256:` + **标准** base64（无填充）的 43 个字符；
* HTTP 侧的状态词表是 `InvitationReady/RetryOnly/Cancelled/Expired`，与状态文件里的
  `Open/Consumed/Cancelled/Expired` **不是**一套词（见 `client_state`）；
* 申请**先验签再算摘要**，授权是「RS256 明文 + RSA-OAEP-256/A256CBC-HS512 的 JWE」；
* 响应必须是 `application/json` + `Content-Length`，不允许分块传输；
* 客户端只走 TLS 1.2，证书信任锚是邀请码里固定的 DER 指纹（不看 CA 链）。

私钥永远不出这台机器：客户端拿到的是签好的邀请码，不是签名能力。
"""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading
import uuid
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(os.environ.get("TC_PAIR_ROOT", "/var/lib/tradechannel/pairing-rs"))
SERVER = ROOT / "server.json"
SIGNING = ROOT / "signing.pem"
PUBLIC = ROOT / "signing-public.json"
INVITES = ROOT / "invites.json"
# 设备显示名：公钥 → {Name, UpdatedAtUtc}。改名只改这一份，不碰邀请状态、不碰 wg；
# 因此部署创建的设备（没有邀请记录）也能有名字。
NAMES = ROOT / "device-names.json"
CERT = ROOT / "tls.crt"
TLSKEY = ROOT / "tls.key"

# WireGuard 侧的四处覆盖点。**生产默认值就是现在这一套**（`/etc/wireguard` + `wg`），
# 留出覆盖只是为了能在没有 wg 的机器（Windows 测试机）上把整条链路跑一遍。
# 覆盖值可以是一条命令（例如「python 假的 wg 脚本」）：Windows 上没法把 .py 当作
# 可执行文件直接跑，只给一个可执行文件路径的覆盖点在那里等于没有。路径不要带空格。
WG_ROOT = Path(os.environ.get("TC_PAIR_WG_ROOT", "/etc/wireguard"))
WG_BIN = os.environ.get("TC_PAIR_WG_BIN", "wg")
WGQUICK_BIN = os.environ.get("TC_PAIR_WGQUICK_BIN", "wg-quick")
IP_BIN = os.environ.get("TC_PAIR_IP_BIN", "ip")

PAIR_LIMIT = 131072
DEFAULT_PORT = 18443
CERT_DAYS = 825

# 授权密文的固定参数（旧版的 `PairCrypto.Encrypt`）。客户端只认这一对算法，
# 报文里声明的算法它一概不读，所以这里也不许从别处取。
AUTHORIZATION_ALG = "RSA-OAEP-256"
AUTHORIZATION_ENC = "A256CBC-HS512"
AUTHORIZATION_CTY = "TC-Pairing-v1"
CEK_LEN = 64
MAC_KEY_LEN = 32
IV_LEN = 16
TAG_LEN = 32

# 消费邀请会同时改「邀请状态文件」和「WireGuard 配置」，两个请求同时进来会各自
# 分到同一个地址、或者互相覆盖配置。串行化这两步，代价是一次消费几十毫秒。
CONSUME_LOCK = threading.Lock()


class Fail(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def need(condition, code, message):
    if not condition:
        raise Fail(code, message)


# ---------------------------------------------------------------- 编码

def compact(value):
    """规范 JSON：键排序、无空格、纯 ASCII。签名与摘要都基于它。"""
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64u(text, limit=PAIR_LIMIT):
    need(isinstance(text, str) and 0 < len(text) <= limit, "InvalidEncoding", "编码无效。")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    need(b64u(raw) == text, "InvalidEncoding", "编码不是规范形态。")
    return raw


def b64std(raw):
    return base64.b64encode(raw).decode("ascii").rstrip("=")


def sha256_hex(raw):
    return hashlib.sha256(raw).hexdigest()


def rfc3339(seconds):
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- DER / JWK

def der(tag, content):
    length = len(content)
    if length < 128:
        encoded = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + encoded + content


def parse_public_der(value):
    """SubjectPublicKeyInfo → JWK。只认 rsaEncryption + 两个 INTEGER。"""
    def item(raw, offset=0):
        need(offset + 2 <= len(raw), "InvalidSigningKey", "公钥编码无效。")
        tag, length, at = raw[offset], raw[offset + 1], offset + 2
        if length & 0x80:
            count = length & 0x7F
            need(0 < count <= 4 and at + count <= len(raw), "InvalidSigningKey", "公钥编码无效。")
            length, at = int.from_bytes(raw[at:at + count], "big"), at + count
        need(at + length <= len(raw), "InvalidSigningKey", "公钥编码无效。")
        return tag, raw[at:at + length], at + length

    tag, content, end = item(value)
    need(tag == 0x30 and end == len(value), "InvalidSigningKey", "公钥编码无效。")
    alg, algorithm, pos = item(content)
    need(alg == 0x30 and algorithm == bytes.fromhex("06092a864886f70d0101010500"),
         "InvalidSigningKey", "公钥不是 RSA。")
    tag, bits, end = item(content, pos)
    need(tag == 3 and bits[:1] == b"\0" and end == len(content), "InvalidSigningKey", "公钥编码无效。")
    tag, rsa, end = item(bits[1:])
    need(tag == 0x30 and end == len(bits) - 1, "InvalidSigningKey", "公钥编码无效。")
    tag, n, pos = item(rsa)
    need(tag == 2, "InvalidSigningKey", "公钥编码无效。")
    tag, e, end = item(rsa, pos)
    need(tag == 2 and end == len(rsa), "InvalidSigningKey", "公钥编码无效。")
    return {"kty": "RSA", "n": b64u(n.lstrip(b"\0")), "e": b64u(e.lstrip(b"\0"))}


def fingerprint(jwk):
    """`SHA256:` + 标准 base64（无填充）。与 Rust `RsaJwk::fingerprint` 同一算法。"""
    canonical = '{"e":"%s","kty":"RSA","n":"%s"}' % (jwk["e"], jwk["n"])
    return "SHA256:" + b64std(hashlib.sha256(canonical.encode("ascii")).digest())


# ---------------------------------------------------------------- OpenSSL

def openssl_call(args, data=None):
    """跑一次 openssl，返回 `(退出码, stdout)`。非零**不抛**。

    「验签失败」是一个正常结果，不是环境错误：把它和「openssl 没装」混成同一个
    异常，就没法把「这张申请是假的」报成 `InvalidPairRequest`。
    """
    exe = "/usr/bin/openssl" if os.name == "posix" else "openssl"
    try:
        done = subprocess.run([exe] + args, input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Fail("MissingOpenSSL", "需要 openssl 才能签发邀请；请先安装 openssl。") from None
    return done.returncode, done.stdout


def openssl(args, data=None):
    code, stdout = openssl_call(args, data)
    need(code == 0, "SigningOperationFailed", "openssl 操作失败（细节已省略）。")
    need(len(stdout) <= PAIR_LIMIT, "SigningOperationFailed", "openssl 输出超出上限。")
    return stdout


def write_private_file(directory, name, text, mode=0o600):
    """在只有自己能读的临时目录里落一份材料，返回路径。

    openssl 的私钥类参数只吃**文件路径**（不接受标准输入），所以必须落盘；
    落盘就必须管好权限——这些文件里有私钥和待签的密文。
    """
    path = os.path.join(directory, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
        stream.write(text)
    return path


def sign(private_pem, message):
    with tempfile.TemporaryDirectory(prefix="tc-pair-") as directory:
        os.chmod(directory, 0o700)
        path = write_private_file(directory, "signing.pem", private_pem)
        return openssl(["dgst", "-sha256", "-sign", path], message)


def public_from(private_pem):
    return parse_public_der(openssl(["pkey", "-pubout", "-outform", "DER"], private_pem.encode("ascii")))


def sign_jws(private_pem, body):
    header = b64u(b'{"alg":"RS256","typ":"JWT"}')
    payload = b64u(compact(body).encode("utf-8"))
    message = (header + "." + payload).encode("ascii")
    return message.decode("ascii") + "." + b64u(sign(private_pem, message))


# ---------------------------------------------------------------- 状态文件

def read_json(path, default=None):
    if not path.exists():
        return default
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def write_json(path, value, mode=0o600):
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(compact(value) + "\n")
    os.replace(tmp, path)


def load_server():
    value = read_json(SERVER)
    need(isinstance(value, dict), "NotInitialized", "这台服务器还没有初始化邀请服务，请先运行 init。")
    return value


def load_invites():
    value = read_json(INVITES, {"SchemaVersion": 1, "Invites": {}})
    need(isinstance(value, dict) and isinstance(value.get("Invites"), dict),
         "InvalidState", "邀请记录损坏。")
    return value


def load_names():
    value = read_json(NAMES, {"SchemaVersion": 1, "Names": {}})
    need(isinstance(value, dict) and isinstance(value.get("Names"), dict),
         "InvalidState", "设备名称记录损坏。")
    return value


# ---------------------------------------------------------------- WireGuard

def command_of(setting, name):
    """把一个覆盖点变成 argv 前缀（默认只是一个命令名）。

    拆空格是有意为之：测试机上的 wg 是「解释器 + 假脚本」两条 argv。
    """
    parts = setting.split()
    need(bool(parts), "MissingWireGuard", "这台机器上没有 %s 命令。" % name)
    return parts


def conf_file(interface):
    return WG_ROOT / ("%s.conf" % interface)


def read_conf(interface):
    path = conf_file(interface)
    need(path.exists(), "ServerKeyMissing", "找不到 %s。" % path)
    return path.read_text(encoding="utf-8")


def wg_public(interface):
    """从私钥推导服务器公钥：不要求接口正在运行，卸载后也能读。"""
    key = WG_ROOT / ("%s.key" % interface)
    if not key.exists():
        raise Fail("ServerKeyMissing", "找不到接口私钥 %s。" % key)
    try:
        done = subprocess.run(command_of(WG_BIN, "wg") + ["pubkey"], input=key.read_bytes(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    except OSError:
        raise Fail("ServerKeyMissing", "这台机器上没有 wg 命令，无法推导服务器公钥。") from None
    need(done.returncode == 0, "ServerKeyMissing", "无法从接口私钥推导服务器公钥。")
    value = done.stdout.decode("utf-8").strip()
    need(len(value) == 44 and value.endswith("="), "ServerKeyMissing", "服务器公钥形状无效。")
    return value


def wg_subnet(interface):
    conf = conf_file(interface)
    need(conf.exists(), "ServerKeyMissing", "找不到 %s。" % conf)
    for line in conf.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text.lower().startswith("address"):
            _, value = text.split("=", 1)
            return value.strip()
    raise Fail("ServerKeyMissing", "接口配置里没有 Address。")


def local_ipv4(interface):
    """接口自己的 IPv4（不含前缀）。取不到就退回配置里的 Address 主机部分。

    `ip` 只在 Linux 上有：拿不到时**不能**让整次调用失败——配置里的 Address 就是
    同一个事实的另一个来源。少了这条兜底，任何没有 `ip` 命令的环境（比如测试机）
    都会在初始化时莫名崩掉。
    """
    try:
        done = subprocess.run(command_of(IP_BIN, "ip") + ["-4", "-o", "addr", "show", "dev", interface],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        done = None
    if done is not None and done.returncode == 0:
        for token in done.stdout.decode("utf-8", "replace").split():
            if token.count(".") == 3 and "/" in token:
                return token.split("/")[0]
    return wg_subnet(interface).split("/")[0]


# ---------------------------------------------------------------- init

def ensure_identity():
    if SIGNING.exists() and PUBLIC.exists():
        private_pem = SIGNING.read_text(encoding="ascii")
        jwk = read_json(PUBLIC)
        need(isinstance(jwk, dict) and "n" in jwk and "e" in jwk, "InvalidSigningKey", "管理公钥损坏。")
        return private_pem, jwk
    private_pem = openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
                           "-pkeyopt", "rsa_keygen_pubexp:65537"]).decode("ascii")
    jwk = public_from(private_pem)
    os.chmod(ROOT, 0o700)
    fd = os.open(SIGNING, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
        stream.write(private_pem)
    write_json(PUBLIC, jwk, 0o644)
    return private_pem, jwk


def ensure_cert(host):
    if CERT.exists() and TLSKEY.exists():
        return
    openssl(["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", str(CERT_DAYS),
             "-nodes", "-keyout", str(TLSKEY), "-out", str(CERT), "-subj", "/CN=%s" % host])
    os.chmod(TLSKEY, 0o600)


def cert_sha256():
    """证书**DER** 的 SHA-256。

    不是文件字节：客户端（rustls）拿到的是 TLS 握手里的 DER，与 PEM 文本的哈希
    永远对不上。这个区别只有真连一次才会暴露，所以单独一个函数把它钉住。
    """
    return sha256_hex(openssl(["x509", "-in", str(CERT), "-outform", "DER"]))


def command_init(args):
    ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(ROOT, 0o700)
    private_pem, jwk = ensure_identity()
    # 公钥与网段分开取：网段读不到只影响「服务器地址」这一格，
    # 不该把已经从接口私钥算出来的公钥一起丢掉。
    server_key, subnet = "", ""
    try:
        server_key = wg_public(args.interface)
    except Fail:
        need(args.server_key is not None, "ServerKeyMissing",
             "读不到接口 %s 的公钥；请用 --server-key 显式给出。" % args.interface)
        server_key = args.server_key
    try:
        subnet = wg_subnet(args.interface)
    except Fail:
        subnet = ""
    endpoint_host, _, endpoint_port = args.endpoint.rpartition(":")
    need(endpoint_host.count(".") == 3 and endpoint_port.isdigit(),
         "InvalidEndpoint", "入口要写成 IPv4:端口，例如 203.0.113.10:18443。")
    port = int(endpoint_port)
    need(1024 <= port <= 65535, "InvalidEndpoint", "端口必须在 1024–65535。")
    ensure_cert(endpoint_host)
    existing = read_json(SERVER) or {}
    # 服务器隧道地址只在真读到接口配置时才有；只给 --server-key 的场景留空，
    # 不拿一个猜出来的地址去填（那会变成「看起来对、连不上」的配置）。
    if existing.get("ServerAddress"):
        server_address = existing["ServerAddress"]
    elif subnet:
        server_address = local_ipv4(args.interface)
    else:
        server_address = ""
    record = {
        "SchemaVersion": 1,
        "Interface": args.interface,
        "Endpoint": "%s:%d" % (endpoint_host, port),
        "PublicHost": endpoint_host,
        "Port": port,
        "TunnelSubnet": existing.get("TunnelSubnet") or subnet,
        "ServerAddress": server_address,
        "ServerPublicKey": server_key,
        "RemoteOwnerId": existing.get("RemoteOwnerId") or str(uuid.uuid4()),
        "NodeId": existing.get("NodeId") or str(uuid.uuid4()),
        "NodeName": args.node_name or existing.get("NodeName") or "TradeChannel server",
        "ManagementFingerprint": fingerprint(jwk),
        "CreatedAtUtc": existing.get("CreatedAtUtc") or rfc3339(int(dt.datetime.now(dt.timezone.utc).timestamp())),
    }
    write_json(SERVER, record)
    return {
        "initialized": True,
        "endpoint": record["Endpoint"],
        "serverPublicKey": record["ServerPublicKey"],
        "nodeId": record["NodeId"],
        "tlsSha256": cert_sha256(),
        "managementFingerprint": record["ManagementFingerprint"],
        "root": str(ROOT),
    }


# ---------------------------------------------------------------- create / status / cancel

def create_invite(lifetime, device_name):
    server = load_server()
    private_pem = SIGNING.read_text(encoding="ascii")
    jwk = read_json(PUBLIC)
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    expires = now + lifetime
    invite_id = str(uuid.uuid4())
    token = b64u(secrets.token_bytes(32))
    need(len(token) == 43, "Internal", "令牌长度异常。")

    binding = {
        "RemoteOwnerId": server["RemoteOwnerId"],
        "NodeId": server["NodeId"],
        "ServerPublicKey": server["ServerPublicKey"],
    }
    capabilities = {
        "PairingVersion": 1,
        "ManagementApiVersion": 2,
        "Transport": server.get("Transport") or "udp",
    }
    invite_body = {
        "SchemaVersion": 1,
        "Kind": "TradeChannel.PairInvite",
        "InviteId": invite_id,
        "RemoteOwnerId": server["RemoteOwnerId"],
        "NodeId": server["NodeId"],
        "ServerPublicKey": server["ServerPublicKey"],
        "ManagementSigningPublicKey": jwk,
        "PublicEndpoint": server["Endpoint"],
        "IssuedAtUtc": rfc3339(now),
        "ExpiresAtUtc": rfc3339(expires),
        "Capabilities": capabilities,
        "ServerBinding": binding,
        "DeviceName": device_name,
    }
    invite_jws = sign_jws(private_pem, invite_body)

    tls_sha = cert_sha256()
    descriptor = {
        "SchemaVersion": 1,
        "Kind": "TradeChannel.OnlineInvite",
        "InviteId": invite_id,
        "Invite": invite_jws,
        "PublicHost": server["PublicHost"],
        "Port": server["Port"],
        "TlsSha256": tls_sha,
        "ManagementFingerprint": server["ManagementFingerprint"],
        "ManagementSigningPublicKey": jwk,
        "ExpiresAtUtc": rfc3339(expires),
        "RetryUntilUtc": rfc3339(expires + 120),
    }
    descriptor_jws = sign_jws(private_pem, descriptor)

    code = "TCI1." + b64u(compact({
        "v": 1,
        "h": server["PublicHost"],
        "p": server["Port"],
        "i": invite_id,
        "k": token,
        "t": tls_sha,
        "m": server["ManagementFingerprint"],
        "e": expires,
    }).encode("utf-8"))

    state = load_invites()
    # 只保留最近 512 张，按签发时间倒序，避免状态文件无限增长。
    if len(state["Invites"]) >= 512:
        ordered = sorted(state["Invites"].items(), key=lambda item: item[1].get("IssuedAtUtc", ""))
        for stale, _ in ordered[: len(state["Invites"]) - 511]:
            state["Invites"].pop(stale, None)
    state["Invites"][invite_id] = {
        "State": "Open",
        "Token": token,
        "DeviceName": device_name,
        "IssuedAtUtc": rfc3339(now),
        "ExpiresAtUtc": rfc3339(expires),
        "SignedDescriptor": descriptor_jws,
        # 离线交接要交付的是**签过名的邀请本身**，不是 TCI1 码：新电脑连不上 18443，
        # 没法用码去服务器读描述符。邀请里没有令牌，单独拿到它也消费不了邀请。
        "Invite": invite_jws,
        # 授权里的 `ServerBinding` 必须与邀请里的**逐字节**相同，而授权是消费时
        # 才组装的。把当初签进去的那一份抄下来，比消费时再从 server.json 复算可靠。
        "ServerBinding": binding,
    }
    write_json(INVITES, state)
    return {
        "code": code,
        "invite": invite_jws,
        "inviteId": invite_id,
        "deviceName": device_name,
        "issuedAtUtc": rfc3339(now),
        "expiresAtUtc": rfc3339(expires),
        "expiresUnix": expires,
        "publicHost": server["PublicHost"],
        "port": server["Port"],
        "tlsSha256": tls_sha,
        "managementFingerprint": server["ManagementFingerprint"],
    }


def effective_state(record, now):
    state = record.get("State", "Open")
    if state == "Open":
        if parse_time(record["ExpiresAtUtc"]) <= now:
            return "Expired"
    return state


def parse_time(text):
    return int(dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp())


def parse_client_time(text):
    """RFC 3339 UTC，带或不带小数秒；解析不了回 `None`。

    客户端的 `CreatedAtUtc` 带 6 位微秒（`2026-11-07T14:21:33.123456Z`），服务器自己
    写的时间戳不带——同一个字段两种写法，必须都认。这个函数**只**用于时钟合理性
    检查；摘要认的是原始字符串，不能被这里解析出来的结果改写。
    """
    if not isinstance(text, str) or not 0 < len(text) <= 40:
        return None
    for pattern in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            stamp = dt.datetime.strptime(text, pattern)
        except ValueError:
            continue
        return int(stamp.replace(tzinfo=dt.timezone.utc).timestamp())
    return None


# HTTP 侧的状态词表：状态文件里的 `State` 是服务器自己的状态机（CLI 与界面读它），
# 而客户端 `pairing::join::check_status` 只认这四个值，其余一律当「协议变了」拒掉。
# 两套词各自稳定，映射只放在这一处——别在两个地方各维护一份。
CLIENT_STATES = {
    "Open": "InvitationReady",
    "Consumed": "RetryOnly",
    "Cancelled": "Cancelled",
    "Expired": "Expired",
}


def client_state(record, now):
    """状态文件里的状态 → 客户端认的状态词。

    认不出来的状态原样透出：让客户端报「不认识的邀请状态」比在这里悄悄挑一个
    看起来正常的值安全——后者会把「状态机坏了」伪装成「可以继续」。
    """
    state = effective_state(record, now)
    return CLIENT_STATES.get(state, state)


def constant_time_equal(expected, given):
    """常数时间比对（令牌、摘要都走这里）。

    令牌被猜中的代价是整台服务器，而普通 `==` 会在第一个不同的字节上返回，
    反复试探就能一位一位把令牌拼出来。非 ASCII 直接判不匹配：`compare_digest`
    对非 ASCII 字符串会抛异常，而异常抬头会变成 500——那是把「凭据不对」谎报成
    「服务器坏了」。
    """
    if not isinstance(given, str) or not given.isascii():
        return False
    return hmac.compare_digest(str(expected), given)


def find_invite(invite_id):
    state = load_invites()
    record = state["Invites"].get(invite_id)
    need(record is not None, "InviteNotFound", "这张邀请码不在这台服务器上。")
    return record


def command_status(args):
    record = find_invite(args.id)
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    return {
        "inviteId": args.id,
        "state": effective_state(record, now),
        "deviceName": record.get("DeviceName", ""),
        "issuedAtUtc": record.get("IssuedAtUtc", ""),
        "expiresAtUtc": record.get("ExpiresAtUtc", ""),
        "requestId": record.get("RequestId"),
        # 这三项在 consume 时就写进记录了，只是以前没往外递。没有它们，撤设备
        # 的人只能看到「某台设备」而无从判断它是哪一台、占了哪个地址——那正是
        # 「按邀请记录找设备」这条路径缺的那一环。
        "deviceId": record.get("DeviceId"),
        "clientPublicKey": record.get("ClientPublicKey"),
        "clientAddress": record.get("ClientAddress"),
        "consumedAtUtc": record.get("ConsumedAtUtc"),
        "cancelledAtUtc": record.get("CancelledAtUtc"),
    }


def command_cancel(args):
    state = load_invites()
    record = state["Invites"].get(args.id)
    need(record is not None, "InviteNotFound", "这张邀请码不在这台服务器上。")
    need(record.get("State") != "Consumed", "InviteConsumed", "这张邀请码已经被用掉了；要断开那台设备请用撤设备。")
    if record.get("State") != "Cancelled":
        record["State"] = "Cancelled"
        record["CancelledAtUtc"] = rfc3339(int(dt.datetime.now(dt.timezone.utc).timestamp()))
        write_json(INVITES, state)
    return {"inviteId": args.id, "state": record["State"], "cancelledAtUtc": record.get("CancelledAtUtc", "")}


def command_device_names(_args):
    """公钥 → 显示名。只读；没有记录时返回空表，不是错误。"""
    state = load_names()
    return {"names": state["Names"]}


def command_forget_device(args):
    """删除一台**已不在隧道上**的设备的名称记录。

    只动 `device-names.json`：WireGuard peer、邀请审计与授权都不在这里删。
    撤销设备时 peer 已经摘掉，名字条目会留下来；设备页从 `wg` 读列表之后它就不
    再出现，于是变成一条永远清不掉的孤儿记录。这个子命令只负责把那条记录清掉。
    """
    key = (args.key or "").strip()
    need(is_wireguard_key(key), "InvalidClientKey", "设备公钥无效。")
    state = load_names()
    existed = key in state["Names"]
    state["Names"].pop(key, None)
    write_json(NAMES, state)
    return {"key": key, "removed": existed}


def command_rename_device(args):
    """改一台设备的显示名：只写 `device-names.json`，不碰邀请状态与 wg。

    按**公钥**而不是邀请 id 定位：部署创建的设备没有邀请记录，但它们同样需要名字；
    wg 侧唯一稳定的身份就是公钥。
    """
    key = (args.key or "").strip()
    name = (args.name or "").strip()
    need(is_wireguard_key(key), "InvalidClientKey", "设备公钥无效。")
    need(1 <= len(name) <= 64, "InvalidDeviceName", "设备名称须为 1 至 64 个字符。")
    need(not any(ch in name for ch in ("\n", "\r", "\t")), "InvalidDeviceName",
         "设备名称不能包含换行、制表符等控制字符。")
    state = load_names()
    state["Names"][key] = {
        "Name": name,
        "UpdatedAtUtc": rfc3339(int(dt.datetime.now(dt.timezone.utc).timestamp())),
    }
    write_json(NAMES, state)
    return {"key": key, "name": name}


# ---------------------------------------------------------------- 隧道网段与地址

def server_tunnel_address(network):
    """服务端地址按协议固定为网段首 +1。

    不是「接口实际配在哪」：客户端会逐字节比 `ServerAddress == 网段首+1`，配在别处
    的服务器本来就不该被邀请码接入（那会让生成出来的客户端配置连不通）。
    """
    return network.network_address + 1


def private_blocks():
    return [ipaddress.ip_network(text) for text in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def tunnel_network(interface, server):
    """读出隧道网段并归一到「网络地址/前缀」。

    优先读接口配置里的 Address：真正在用的网段只有配置说了算，server.json 里那份
    是初始化那一刻抄下来的，可能已经被改过。客户端要求网段必须是**网络地址本身**
    且是 RFC1918、前缀 /16–/30，这里提前按同一套判据拒绝，好过让客户端去猜。
    """
    text = ""
    try:
        text = wg_subnet(interface)
    except Fail:
        text = str(server.get("TunnelSubnet") or "")
    need(bool(text), "ServerSubnetMissing",
         "读不到隧道网段：接口 %s 的配置里没有 Address。" % interface)
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise Fail("ServerSubnetMissing", "隧道网段不是 IPv4 CIDR。") from None
    need(network.version == 4, "ServerSubnetMissing", "隧道网段必须是 IPv4。")
    need(16 <= network.prefixlen <= 30, "ServerSubnetMissing", "隧道网段前缀必须在 /16 到 /30 之间。")
    need(any(network.subnet_of(block) for block in private_blocks()), "ServerSubnetMissing",
         "隧道网段必须是私有网段（10/8、172.16/12、192.168/16）。")
    return network


def split_sections(text):
    """按 `[xxx]` 头切段，保留每段的原文顺序。

    保留原文是为了能**原样回滚**：回滚时重新排版一遍配置，与原文不一致就等于把
    别人的配置改了一次。
    """
    sections = []
    header = ""
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if header or lines:
                sections.append((header, lines))
            header, lines = stripped, []
            continue
        lines.append(raw)
    if header or lines:
        sections.append((header, lines))
    return sections


def render_sections(sections):
    """段之间空一行、每段不留尾部空行。WireGuard 的解析器对空行不敏感。"""
    chunks = []
    for header, lines in sections:
        body = ([header] if header else []) + list(lines)
        while body and not body[-1].strip():
            body.pop()
        if body:
            chunks.append("\n".join(body))
    return "\n\n".join(chunks) + "\n" if chunks else ""


def section_value(lines, key):
    for raw in lines:
        line = raw.strip()
        if "=" in line:
            name, value = line.split("=", 1)
            if name.strip().lower() == key:
                return value.strip()
    return ""


def section_allowed(lines):
    allowed = []
    for raw in lines:
        line = raw.strip()
        if "=" in line:
            name, value = line.split("=", 1)
            if name.strip().lower() == "allowedips":
                allowed.extend(part.strip() for part in value.split(",") if part.strip())
    return allowed


def conf_peers(text):
    """把配置里的 `[Peer]` 段读成 `[(公钥, 段内原文)]`。"""
    return [(section_value(lines, "publickey"), lines)
            for header, lines in split_sections(text)
            if header.lower() == "[peer]"]


def taken_networks(text, network, interface):
    """已经被占用的地址：网络地址、广播地址、服务端自己、以及每个 peer 的 AllowedIPs。"""
    taken = [
        ipaddress.ip_network(network.network_address),
        ipaddress.ip_network(network.broadcast_address),
        ipaddress.ip_network(server_tunnel_address(network)),
    ]
    # 接口也可能配在网段里別的地址上（老配置）：它同样不能分给设备。
    try:
        live = ipaddress.ip_address(local_ipv4(interface))
    except (Fail, ValueError):
        live = None
    if live is not None and live in network:
        taken.append(ipaddress.ip_network(live))
    for _, lines in conf_peers(text):
        for item in section_allowed(lines):
            try:
                entry = ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue
            if entry.version == 4 and entry.overlaps(network):
                taken.append(entry)
    return taken


def allocate_address(network, taken):
    """挑网段内第一个空闲地址：从 +2 起（+0 网络、+1 服务端），到广播地址前止。

    从低到高挑而不是随机：同一份配置上的两次分配会落在同一个地址上，
    排查时「这台设备是 .2」这句话在日志和配置里始终对得上。
    """
    for number in range(int(network.network_address) + 2, int(network.broadcast_address)):
        candidate = ipaddress.IPv4Address(number)
        if any(candidate in entry for entry in taken):
            continue
        return candidate
    raise Fail("TunnelExhausted", "隧道网段里没有空闲地址了。")


def with_client_peer(text, public_key, client_address, request_id, device_id):
    """把客户端公钥写进配置；同一个公钥的旧段先删掉。

    按公钥删而不是整段重写：这台服务器上可能还挂着别的设备，整段重写等于把别人
    一起踢掉，而受害者只会看到「另一台电脑突然连不上」。重试同一个申请时删掉旧段
    再写新段也刚好是幂等的——服务器上不会堆垃圾 peer。
    """
    sections = [
        (header, lines) for header, lines in split_sections(text)
        if not (header.lower() == "[peer]" and section_value(lines, "publickey") == public_key)
    ]
    sections.append(("[Peer]", [
        # 留一条注释：半年后排查「这台设备哪来的」，只有 RequestId 能和邀请记录对上。
        "# tc-pair request=%s device=%s" % (request_id, device_id),
        "PublicKey = %s" % public_key,
        "AllowedIPs = %s/32" % client_address,
    ]))
    return render_sections(sections)


def replace_conf(interface, text):
    path = conf_file(interface)
    tmp = path.with_suffix(".conf.tcnew")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    os.replace(tmp, path)
    if os.name == "posix":
        os.chmod(path, 0o600)


def sync_interface(interface):
    """`wg-quick strip` → 临时文件 → `wg syncconf`：只应用差异，不重启接口。

    重启接口会把所有正在连的设备一起踢下线，加一台设备不该造成这种影响。
    """
    try:
        stripped = subprocess.run(
            command_of(WGQUICK_BIN, "wg-quick") + ["strip", interface],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Fail("MissingWireGuard", "这台机器上没有 wg-quick，无法热更新隧道。") from None
    need(stripped.returncode == 0 and bool(stripped.stdout), "WireGuardApplyFailed",
         "读不出接口 %s 的运行配置（wg-quick strip 没有成功）。" % interface)
    with tempfile.TemporaryDirectory(prefix="tc-pair-sync-") as directory:
        path = os.path.join(directory, "sync.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(stripped.stdout)
        try:
            done = subprocess.run(command_of(WG_BIN, "wg") + ["syncconf", interface, path],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Fail("MissingWireGuard", "这台机器上没有 wg，无法热更新隧道。") from None
    need(done.returncode == 0, "WireGuardApplyFailed", "把设备加进隧道失败（wg syncconf 没有成功）。")


def attach_client(interface, text_before, public_key, client_address, request_id, device_id):
    """改配置 + 热更新；任何一步失败都把配置**恢复原样**再报错。

    不回滚会留下「配置里有这台设备、接口上却没有」：下一次重试看到公钥已经在配置
    里会跳过同步，症状就变成「授权成功但连不上」，而且没有任何地方报错。
    """
    updated = with_client_peer(text_before, public_key, client_address, request_id, device_id)
    replace_conf(interface, updated)
    try:
        sync_interface(interface)
    except Exception:
        replace_conf(interface, text_before)
        raise


# ---------------------------------------------------------------- 申请校验

PAIR_REQUEST_FIELDS = [
    "SchemaVersion",
    "Kind",
    "InviteId",
    "ServerBinding",
    "ClientRequest",
    "DeviceName",
    "RecipientJwk",
    "RequestDigest",
    "RequestDigestAlgorithm",
    "CreatedAtUtc",
]

CLIENT_REQUEST_FIELDS = ["RequestId", "DeviceId", "CreatedAtUtc", "ClientPublicKey"]


def is_uuid(text):
    """36 位**小写** UUID 形状（与客户端 `ClientRequest::validate` 同一判据）。"""
    if len(text) != 36:
        return False
    for index, char in enumerate(text):
        if index in (8, 13, 18, 23):
            if char != "-":
                return False
        elif char not in "0123456789abcdef":
            return False
    return True


def is_wireguard_key(text):
    """43 位 base64 + 一个 `=`（32 字节）。与客户端 `ClientRequest::validate` 同一判据。"""
    if len(text) != 44 or not text.endswith("="):
        return False
    head = text[:43]
    return head.isascii() and all(c.isalnum() or c in "+/" for c in head)


def public_pem(jwk):
    """JWK → SubjectPublicKeyInfo 的 PEM 文本。openssl 只吃 PEM/DER，不吃 JWK。"""
    need(isinstance(jwk, dict) and jwk.get("kty") == "RSA", "InvalidPairRequest",
         "设备申请的接收密钥不是 RSA。")
    need(isinstance(jwk.get("n"), str) and isinstance(jwk.get("e"), str), "InvalidPairRequest",
         "设备接收密钥不完整。")
    try:
        modulus = unb64u(jwk["n"])
        exponent = unb64u(jwk["e"])
    except Fail:
        raise Fail("InvalidPairRequest", "设备接收密钥不是规范的 base64url。") from None
    # 与客户端 `RsaJwk::parse` 同一条底线：比 2048 位还短的模数不接。
    need(len(modulus) >= 256, "InvalidPairRequest", "设备接收密钥太短。")
    need(0 < len(exponent) <= 8, "InvalidPairRequest", "设备接收密钥的指数无效。")

    def integer(raw):
        # DER 的 INTEGER 是有符号的：最高位为 1 时要补一个 0x00，否则会被读成负数。
        return der(0x02, (b"\0" + raw) if raw[0] & 0x80 else raw)

    rsa_key = der(0x30, integer(modulus) + integer(exponent))
    algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    spki = der(0x30, algorithm + der(0x03, b"\0" + rsa_key))
    body = base64.b64encode(spki).decode("ascii")
    lines = [body[index:index + 64] for index in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % "\n".join(lines)


def signature_ok(message, signature, key_pem):
    """RS256 验签。失败只回布尔值：具体原因不回给提交申请的一方。"""
    with tempfile.TemporaryDirectory(prefix="tc-pair-verify-") as directory:
        os.chmod(directory, 0o700)
        key_path = write_private_file(directory, "recipient.pem", key_pem)
        signature_path = os.path.join(directory, "signature.bin")
        fd = os.open(signature_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(signature)
        code, _ = openssl_call(
            ["dgst", "-sha256", "-verify", key_path, "-signature", signature_path], message)
    return code == 0


def client_digest(client):
    """`TC-ClientRequest-v1`：七个字段按固定顺序换行拼接后的 SHA-256（小写 hex）。

    时间戳用**原字符串**参与：格式化一次就不再改，否则服务器算出的摘要与客户端
    永远不同，而错误的表现只是「摘要不匹配」。
    """
    tuple_text = "\n".join([
        "1",
        "TradeChannel.ClientRequest",
        client["RequestId"],
        client["DeviceId"],
        client["CreatedAtUtc"],
        client["ClientPublicKey"],
        "IPv4",
    ])
    return sha256_hex(tuple_text.encode("utf-8"))


def verify_pair_request(jws, now):
    """**先验签，再谈摘要**，返回已确认的载荷。

    顺序不能反：摘要谁都能算，签名才是「这份申请确实出自持有 `RecipientJwk` 私钥
    的一方」的唯一证据。先算摘要等于让任何人拿一段自造 JSON 换到一次真实的部署动作
    （往服务器配置里写一个 peer）。
    """
    parts = jws.split(".")
    need(len(parts) == 3, "InvalidPairRequest", "设备申请不是三段式签名。")
    try:
        header = json.loads(unb64u(parts[0]).decode("utf-8"))
        payload = json.loads(unb64u(parts[1]).decode("utf-8"))
    except Fail:
        # 编码不规范的 JWS 是「申请不对」，不是「服务器坏了」。
        raise Fail("InvalidPairRequest", "设备申请的编码不是规范的 base64url。") from None
    except (UnicodeDecodeError, ValueError):
        raise Fail("InvalidPairRequest", "设备申请的签名或载荷不是合法 JSON。") from None
    need(isinstance(header, dict) and header.get("alg") == "RS256", "InvalidPairRequest",
         "设备申请的签名算法不是 RS256。")
    need(isinstance(payload, dict), "InvalidPairRequest", "设备申请载荷不是对象。")
    for field in PAIR_REQUEST_FIELDS:
        need(field in payload, "InvalidPairRequest", "设备申请字段不完整。")
    need(payload.get("SchemaVersion") == 1
         and payload.get("Kind") == "TradeChannel.PairRequest"
         and payload.get("RequestDigestAlgorithm") == "TC-ClientRequest-v1",
         "InvalidPairRequest", "设备申请协议无效。")
    key_pem = public_pem(payload["RecipientJwk"])
    try:
        signature = unb64u(parts[2])
    except Fail:
        raise Fail("InvalidPairRequest", "设备申请的签名不是规范的 base64url。") from None
    need(signature_ok(("%s.%s" % (parts[0], parts[1])).encode("ascii"), signature, key_pem),
         "InvalidPairRequest", "设备申请签名校验失败。")
    inner = payload["ClientRequest"]
    need(isinstance(inner, dict), "InvalidPairRequest", "设备申请缺少客户端请求。")
    for field in CLIENT_REQUEST_FIELDS:
        need(isinstance(inner.get(field), str) and bool(inner.get(field)),
             "InvalidPairRequest", "设备申请缺少客户端请求字段。")
    # 这两个 id 会写进 `wg` 配置的注释、公钥会写进配置本身：形状必须在这里就校验。
    # 验签只证明「这份申请出自持有那把私钥的一方」，不证明它不含换行——一个
    # `RequestId` 里带上 "\n" 就等于往配置文件里注入额外的行。
    need(is_uuid(inner["RequestId"]) and is_uuid(inner["DeviceId"]), "InvalidPairRequest",
         "设备申请的标识不是标准（小写）UUID。")
    need(is_wireguard_key(inner["ClientPublicKey"]), "InvalidPairRequest",
         "设备公开密钥不是 32 字节的 base64。")
    created = parse_client_time(payload["CreatedAtUtc"])
    need(created is not None, "InvalidPairRequest", "设备申请的时间格式无效。")
    # 与客户端同一个判据：未来 5 分钟以外算那台电脑的时钟不可信。
    need(created <= now + 300, "InvalidPairRequest", "设备申请时间在未来，请检查那台电脑的时钟。")
    return payload


def invite_binding(record, server):
    """邀请里那一份 `ServerBinding`，供授权原样带回。

    新邀请在签发时就把这份抄进了记录；r37 之前签的记录没有，就从 server.json 复算
    —— 三个字段加上 `compact()` 的键排序，得到的就是当初签进去的那一份。
    """
    stored = record.get("ServerBinding")
    if isinstance(stored, dict):
        return stored
    return {
        "RemoteOwnerId": server["RemoteOwnerId"],
        "NodeId": server["NodeId"],
        "ServerPublicKey": server["ServerPublicKey"],
    }


def jwk_digest(value):
    return sha256_hex(compact(value).encode("utf-8"))


# ---------------------------------------------------------------- 授权与封装

def authorization_body(server, invite_id, facts, binding, client_response):
    """组装授权明文（管理私钥签名的那一份）。

    每一项都是客户端**硬校验**的：`RequestId`/`RequestDigest`/`ClientPublicKey` 把
    授权绑死在这一份申请上，`ServerBinding` 与邀请逐字节相同，地址必须是网段内空闲
    的单个 `/32`。少一项就变成「谁都能拿着别人的授权去连」。
    """
    return {
        "SchemaVersion": 1,
        "Kind": "TradeChannel.PairAuthorization",
        "InviteId": invite_id,
        "ServerBinding": binding,
        "RemoteOwnerId": server["RemoteOwnerId"],
        "NodeId": server["NodeId"],
        "RequestId": facts["request_id"],
        "DeviceId": facts["device_id"],
        "ClientPublicKey": facts["client_public_key"],
        "RequestDigest": facts["digest"],
        "RequestDigestAlgorithm": "TC-ClientRequest-v1",
        "ClientAddress": facts["client_address"],
        "ConfigRevision": 1,
        "IssuedAtUtc": facts["issued_at_utc"],
        # 授权的有效期与邀请的有效期是两件事：设备接入之后不该因为「当初那张码
        # 过期了」而失效。与旧版的 `Complete-TCPairOnlineEnrollment` 一致，
        # 这里给一小时——客户端不据此断开，撤设备走的是撤设备。
        "ExpiresAtUtc": facts["expires_at_utc"],
        "ClientResponse": client_response,
    }


def client_response(server, facts, network):
    """下发给客户端的隧道参数。

    客户端对这里几乎每个字段都有硬校验：`TunnelSubnet` 必须是网络地址形态、
    `ServerAddress` 必须恰为网段首 +1、`ClientAddress` 必须是网段内的 `/32`、
    `AllowedIPs` 只能是 `0.0.0.0/0`、`PersistentKeepalive` 只能是 25。
    """
    return {
        "SchemaVersion": 1,
        "Kind": "TradeChannel.ClientResponse",
        "Status": "Authorized",
        "RequestId": facts["request_id"],
        "DeviceId": facts["device_id"],
        "NodeId": server["NodeId"],
        "NodeName": server.get("NodeName", ""),
        "ClientPublicKey": facts["client_public_key"],
        "ServerPublicKey": server["ServerPublicKey"],
        "ClientAddress": facts["client_address"],
        "ServerAddress": "%s/%d" % (server_tunnel_address(network), network.prefixlen),
        "TunnelSubnet": "%s/%d" % (network.network_address, network.prefixlen),
        "AllowedIPs": ["0.0.0.0/0"],
        "AddressFamilies": ["IPv4"],
        "PublicEndpoint": server["Endpoint"],
        "PersistentKeepalive": 25,
        "ConfigRevision": 1,
        # 字符串 `"udp"` = 没有兼容档。客户端据此判定「这条线路只走标准连接」。
        "Transport": server.get("Transport") or "udp",
    }


def seal_authorization(plaintext, recipient_jwk):
    """授权明文 → JWE 紧凑序列化（5 段）。

    CEK 64 字节（前 32 = HMAC-SHA512 密钥、后 32 = AES-256 密钥），IV 16，
    tag = `HMAC-SHA512(mac, AAD‖IV‖CT‖AL)[:32]`，`AAD = b64u(header)`（RFC 7516 §5.1：
    只有受保护头参与认证，加密密钥段不在 AAD 里）。
    算法写死在这里：客户端不读报文声明的算法，只认这一对。
    """
    header = b64u(compact({
        "alg": AUTHORIZATION_ALG,
        "enc": AUTHORIZATION_ENC,
        "cty": AUTHORIZATION_CTY,
    }).encode("utf-8"))
    cek = secrets.token_bytes(CEK_LEN)
    mac_key, enc_key = cek[:MAC_KEY_LEN], cek[MAC_KEY_LEN:]
    iv = secrets.token_bytes(IV_LEN)
    ciphertext = aes_256_cbc_encrypt(enc_key, iv, plaintext.encode("utf-8"))
    encrypted_key = rsa_oaep_encrypt(public_pem(recipient_jwk), cek)
    aad = header
    # AL 是 AAD 的比特长度（64 位大端）。少了它，改掉 header 里的 alg/enc 之后
    # MAC 仍然成立——那等于让发送方自己声明「这是什么算法」。
    message = aad.encode("ascii") + iv + ciphertext + (len(aad) * 8).to_bytes(8, "big")
    tag = hmac.new(mac_key, message, hashlib.sha512).digest()[:TAG_LEN]
    return ".".join([header, b64u(encrypted_key), b64u(iv), b64u(ciphertext), b64u(tag)])


def rsa_oaep_encrypt(key_pem, message):
    """RSA-OAEP-256 加密。摘要必须是 SHA-256，MGF1 也必须跟着走 SHA-256。

    不显式指定 MGF1 摘要时 openssl 会跟着 OAEP 摘要走，但这一层不能靠「默认值
    恰好对」：客户端解密时用的是 `Oaep::new::<Sha256>()`，任何一处不一致都表现为
    「授权密文的密钥封装解不开」。
    """
    with tempfile.TemporaryDirectory(prefix="tc-pair-wrap-") as directory:
        os.chmod(directory, 0o700)
        path = write_private_file(directory, "recipient.pem", key_pem, 0o644)
        return openssl([
            "pkeyutl", "-encrypt", "-pubin", "-inkey", path,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ], message)


def aes_256_cbc_encrypt(key, iv, message):
    """AES-256-CBC。PKCS#7 填充由 openssl 默认完成——JOSE 的 A256CBC-HS512 就是这一种。"""
    return openssl(["enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()], message)


# ---------------------------------------------------------------- consume

def http_status(code):
    """错误码 → HTTP 状态。

    客户端只读信封里的 `Code`（`Ok=false` 时它不看状态码），状态码是给人和给
    中间设备看的：403 是凭据不对、404 是这张码不在这台服务器上、4xx 是这张码
    不能用、5xx 是这台服务器自己坏了。
    """
    return {
        "Forbidden": 403,
        "InviteNotFound": 404,
        "NotFound": 404,
        "InviteCancelled": 410,
        "InviteExpired": 410,
        "InviteConsumed": 409,
        "PairingMismatch": 409,
        "InviteMismatch": 409,
        "InvalidPairRequest": 400,
        "InvalidRequest": 400,
    }.get(code, 500)


def authorize_invite(state, record, invite_id, payload, now):
    """把一份**已验签**的设备申请变成授权（HTTP 消费与离线批准共用这一份）。

    先把所有判据做完、再动 WireGuard，最后才写邀请状态：签发失败时配置一个字节
    都还没改，不存在「回滚一半」的状态；状态写失败时把 conf 还原，避免留下
    「配置里有、记录里没有」的设备——那台设备以后没人撤得掉（撤设备按邀请记录找）。

    返回 `(signed, payload, facts, digest)`。
    """
    server = load_server()
    inner = payload["ClientRequest"]
    digest = client_digest(inner)
    need(constant_time_equal(digest, payload.get("RequestDigest")), "PairingMismatch",
         "设备申请摘要不匹配。")
    need(payload.get("InviteId") == invite_id, "InviteMismatch",
         "设备申请不是给这张邀请码的。")
    binding = invite_binding(record, server)
    need(payload.get("ServerBinding") == binding, "InviteMismatch",
         "设备申请里的服务器绑定与这张邀请不一致。")

    interface = str(server.get("Interface") or "")
    need(bool(interface), "InvalidState", "服务器记录里没有接口名。")
    network = tunnel_network(interface, server)
    text = read_conf(interface)
    # 客户端会一字节一字节地比这四项，缺一项都表现为「授权不属于本机申请」。
    facts = {
        "request_id": inner["RequestId"],
        "device_id": inner["DeviceId"],
        "client_public_key": inner["ClientPublicKey"],
        "digest": digest,
        "issued_at_utc": rfc3339(now),
        "expires_at_utc": rfc3339(now + 3600),
    }

    current = effective_state(record, now)
    if current == "Consumed":
        # 重放：只有**同一份申请**能重来。别的电脑拿着同一张邀请来，是被别人
        # 先占了，要报「已被使用」而不是替它改掉原来那台设备的地址。
        need(str(record.get("RequestId") or "") == facts["request_id"], "InviteConsumed",
             "这张邀请码已经被另一台电脑用掉了。")
        need(str(record.get("RecipientJwkDigest") or "") == jwk_digest(payload["RecipientJwk"]),
             "PairingMismatch", "重试用的接收密钥与首次申请不一致。")
        client_address = str(record.get("ClientAddress") or "")
        need(bool(client_address), "InvalidState", "邀请记录里没有已分配的设备地址。")
        signed = str(record.get("SignedAuthorization") or "")
        need(bool(signed), "InvalidState", "邀请记录里没有原授权。")
        facts["client_address"] = client_address
        # 地址与 peer 都沿用首次的结果；这里再走一遍 upsert 是为了让「上次
        # 卡在半路」的重试收敛（同一个公钥只会有一段，重复写不会堆垃圾）。
        attach_client(interface, text, facts["client_public_key"],
                      client_address.split("/")[0], facts["request_id"], facts["device_id"])
        return signed, payload, facts, digest

    need(current == "Open", "InviteExpired", "邀请码已过期，请让对方重新生成。")
    address = allocate_address(network, taken_networks(text, network, interface))
    facts["client_address"] = "%s/32" % address
    need(SIGNING.exists(), "NotInitialized", "管理私钥不在了，无法签发授权。")
    signed = sign_jws(SIGNING.read_text(encoding="ascii"),
                      authorization_body(server, invite_id, facts, binding,
                                         client_response(server, facts, network)))
    attach_client(interface, text, facts["client_public_key"], address,
                  facts["request_id"], facts["device_id"])
    record.update({
        "State": "Consumed",
        "ConsumedAtUtc": rfc3339(now),
        "RequestId": facts["request_id"],
        "DeviceId": facts["device_id"],
        "ClientPublicKey": facts["client_public_key"],
        "ClientAddress": facts["client_address"],
        "RecipientJwkDigest": jwk_digest(payload["RecipientJwk"]),
        # 重试要回**同一份**授权，所以留存的是签名后的明文（JWS 本身就是
        # 确定性的）；每次重新封装只是因为 JWE 的 CEK/IV 每次都不一样。
        "SignedAuthorization": signed,
    })
    try:
        write_json(INVITES, state)
    except Exception:
        # 状态没写成 = 这台设备在服务器上「不存在」：配置里留着它就没人能
        # 撤掉（撤设备是按邀请记录找设备的）。
        replace_conf(interface, text)
        raise
    return signed, payload, facts, digest


def consume(invite_id, token, raw_body):
    """一次 `POST /v1/invitations/<id>/consume`：分配地址、加 peer、回授权。

    幂等是硬要求：客户端会重试，同一个 `RequestId` 必须拿到同一份授权、同一个地址，
    并且**不得**再往服务器上堆一个 peer。
    """
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    with CONSUME_LOCK:
        state = load_invites()
        record = state["Invites"].get(invite_id)
        need(record is not None, "InviteNotFound", "这张邀请码不在这台服务器上。")
        need(constant_time_equal(record.get("Token", ""), token), "Forbidden", "邀请码里的令牌不对。")
        current = effective_state(record, now)
        # 状态先判、正文后解：一张已经作废的码不该再换来一次签名运算，
        # 而且「已被作废」比「申请格式不对」更是用户当下需要看到的那句话。
        if current == "Cancelled":
            raise Fail("InviteCancelled", "这张邀请码已被服务器主人作废，请让对方重新生成。")
        if current == "Expired":
            raise Fail("InviteExpired", "邀请码已过期，请让对方重新生成。")

        need(0 < len(raw_body) <= PAIR_LIMIT, "InvalidRequest", "申请正文为空或过长。")
        try:
            envelope = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise Fail("InvalidRequest", "申请正文不是 JSON。") from None
        need(isinstance(envelope, dict), "InvalidRequest", "申请正文不是对象。")
        jws = envelope.get("PairRequest")
        need(isinstance(jws, str) and 0 < len(jws) <= PAIR_LIMIT, "InvalidRequest",
             "申请正文里没有签过名的设备申请。")

        payload = verify_pair_request(jws, now)
        signed, payload, facts, digest = authorize_invite(state, record, invite_id, payload, now)
        return {
            "Status": "Authorized",
            "RequestId": facts["request_id"],
            "RequestDigest": digest,
            "EncryptedAuthorization": seal_authorization(signed, payload["RecipientJwk"]),
        }


def command_authorize_request(args):
    """离线批准：管理端把新电脑交回的申请带到这里，换一份加密授权。

    与 HTTP `consume` 共用 [`authorize_invite`]：地址分配、peer 写入、邀请状态、
    幂等重放全部同一套判据。区别只有「谁证明自己有权批准」——这里是 SSH 登录
    服务器本身，不是邀请码里的令牌；所以**不能**把这个子命令暴露到 18443。
    """
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    jws = (args.request or "").strip()
    need(0 < len(jws) <= PAIR_LIMIT, "InvalidRequest", "设备申请为空或过长。")
    payload = verify_pair_request(jws, now)
    invite_id = payload.get("InviteId")
    need(isinstance(invite_id, str) and bool(invite_id), "InvalidPairRequest",
         "设备申请没有指向一张邀请。")
    with CONSUME_LOCK:
        state = load_invites()
        record = state["Invites"].get(invite_id)
        need(record is not None, "InviteNotFound", "这张邀请不在这台服务器上。")
        current = effective_state(record, now)
        if current == "Cancelled":
            raise Fail("InviteCancelled", "这张邀请已被服务器主人作废，请让对方重新生成。")
        if current == "Expired":
            raise Fail("InviteExpired", "邀请已过期，请让对方重新生成。")
        signed, payload, facts, digest = authorize_invite(state, record, invite_id, payload, now)
        return {
            "inviteId": invite_id,
            "requestId": facts["request_id"],
            "deviceId": facts["device_id"],
            "deviceName": str(payload.get("DeviceName") or ""),
            "clientAddress": facts["client_address"],
            "authorization": seal_authorization(signed, payload["RecipientJwk"]),
        }


# ---------------------------------------------------------------- serve

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "TradeChannelPair/1"
    sys_version = ""

    def log_message(self, fmt, *args):  # 日志只写 stderr，且不含令牌
        sys.stderr.write("pair: " + (fmt % args) + "\n")

    def reply(self, status, payload):
        body = compact(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def fail(self, status, code):
        """失败也要是**同一种信封**：客户端先看 `Ok`，再取 `Code`。

        只回一个 HTTP 状态码不回信封的话，客户端会把它念成「协议不对」，
        而不是「邀请码不在这台服务器上」——两种完全不同的处置。
        """
        return self.reply(status, {"Ok": False, "Code": code})

    def do_GET(self):
        prefix = "/v1/invitations/"
        if not self.path.startswith(prefix):
            return self.fail(404, "NotFound")
        invite_id = self.path[len(prefix):].split("?")[0].strip("/")
        if len(invite_id) != 36:
            return self.fail(404, "NotFound")
        auth = self.headers.get("Authorization", "")
        need_token = auth[7:] if auth.startswith("Bearer ") else ""
        try:
            state = load_invites()
        except Fail:
            return self.fail(500, "InvalidState")
        record = state["Invites"].get(invite_id)
        if record is None:
            return self.fail(404, "InviteNotFound")
        if not constant_time_equal(record.get("Token", ""), need_token):
            return self.fail(403, "Forbidden")
        now = int(dt.datetime.now(dt.timezone.utc).timestamp())
        return self.reply(200, {"Ok": True, "Data": {
            # 客户端只认这四个词（`pairing::join::check_status`），`Open` 之类的
            # 内部状态词到这一层必须换掉，否则新电脑连「校验邀请」都过不去。
            "Status": client_state(record, now),
            "SignedDescriptor": record.get("SignedDescriptor", ""),
        }})

    def read_body(self):
        """读正文：必须有 `Content-Length`、不许分块。

        分块或长度未知就没法「先判大小再读」——那等于让对端决定我们要分配多少内存。
        """
        if self.headers.get("Transfer-Encoding"):
            raise Fail("InvalidRequest", "申请正文不允许分块传输。")
        length = (self.headers.get("Content-Length") or "").strip()
        need(length.isdigit(), "InvalidRequest", "申请正文缺少长度。")
        size = int(length)
        need(0 < size <= PAIR_LIMIT, "InvalidRequest", "申请正文为空或过长。")
        raw = self.rfile.read(size)
        need(len(raw) == size, "InvalidRequest", "申请正文没有读完。")
        return raw

    def do_POST(self):
        prefix = "/v1/invitations/"
        suffix = "/consume"
        if not (self.path.startswith(prefix) and self.path.endswith(suffix)):
            return self.fail(404, "NotFound")
        invite_id = self.path[len(prefix):len(self.path) - len(suffix)].strip("/")
        if len(invite_id) != 36:
            return self.fail(404, "NotFound")
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        try:
            # 正文先读完再判：判定失败时留着未读的正文直接关连接，有些系统上会发
            # RST，客户端看到的是「连不上」而不是信封里的错误码。
            body = self.read_body()
            payload = consume(invite_id, token, body)
        except Fail as error:
            return self.fail(http_status(error.code), error.code)
        except Exception as error:  # noqa: BLE001 —— 未预期异常也要落成可读的码
            sys.stderr.write("pair: consume failed: %s: %s\n"
                             % (type(error).__name__, str(error)[:200]))
            return self.fail(500, "Internal")
        return self.reply(200, {"Ok": True, "Data": payload})


def command_serve(args):
    server = load_server()
    state = read_json(INVITES, {"Invites": {}})
    need(isinstance(state, dict), "InvalidState", "邀请记录损坏。")
    port = args.port or int(server["Port"])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(CERT), str(TLSKEY))
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    httpd.daemon_threads = True
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    sys.stderr.write("pair: listening on %d\n" % port)
    sys.stderr.flush()
    httpd.serve_forever()


# ---------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(description="TradeChannel pairing service")
    sub = parser.add_subparsers(dest="action", required=True)

    init = sub.add_parser("init")
    init.add_argument("--interface", required=True)
    init.add_argument("--endpoint", required=True)
    init.add_argument("--server-key")
    init.add_argument("--node-name")

    create = sub.add_parser("create")
    create.add_argument("--lifetime", type=int, required=True)
    create.add_argument("--device", default="New computer")

    status = sub.add_parser("status")
    status.add_argument("--id", required=True)

    cancel = sub.add_parser("cancel")
    cancel.add_argument("--id", required=True)

    # 离线交接的第二步：管理端把新电脑生成的申请带回来批准。只经 SSH 调用，
    # 不进 18443；证明「有权批准」的是服务器登录本身，不是邀请码令牌。
    authorize = sub.add_parser("authorize-request")
    authorize.add_argument("--request", required=True)

    sub.add_parser("device-names")

    rename_device = sub.add_parser("rename-device")
    rename_device.add_argument("--key", required=True)
    rename_device.add_argument("--name", required=True)

    forget_device = sub.add_parser("forget-device")
    forget_device.add_argument("--key", required=True)

    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=0)

    args = parser.parse_args()
    try:
        if args.action == "init":
            payload = command_init(args)
        elif args.action == "create":
            need(600 <= args.lifetime <= 86400, "InvalidLifetime", "有效期必须在 10 分钟到 24 小时之间。")
            need(1 <= len(args.device.strip()) <= 64, "InvalidDeviceName", "设备名称须为 1 至 64 个字符。")
            payload = create_invite(args.lifetime, args.device.strip())
        elif args.action == "status":
            payload = command_status(args)
        elif args.action == "cancel":
            payload = command_cancel(args)
        elif args.action == "authorize-request":
            payload = command_authorize_request(args)
        elif args.action == "device-names":
            payload = command_device_names(args)
        elif args.action == "rename-device":
            payload = command_rename_device(args)
        elif args.action == "forget-device":
            payload = command_forget_device(args)
        else:
            command_serve(args)
            return 0
    except Fail as error:
        sys.stdout.write(compact({"ok": False, "code": error.code, "message": error.message}) + "\n")
        return 1
    except Exception as error:  # noqa: BLE001 —— 任何未预期异常都要变成一条可读的失败
        sys.stdout.write(compact({"ok": False, "code": "Internal", "message": str(error)}) + "\n")
        return 1
    sys.stdout.write(compact(dict(payload, ok=True)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
