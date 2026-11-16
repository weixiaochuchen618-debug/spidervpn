#!/usr/bin/env python3
"""r38 自测：`POST /v1/invitations/<id>/consume` 与 HTTP 状态词表。

一条命令复跑（Windows / Linux 都行，只要有 python 与 openssl）：

    python tests/r38_consume.py
    python tests/r38_consume.py --keep      # 保留临时目录，出问题时能看现场

**为什么这里要自己造一套 wg**：消费邀请的最后一步是「改 `/etc/wireguard/<iface>.conf`
再 `wg syncconf`」。测试机上没有 WireGuard，本来这段只能「读过、没跑过」。
脚本留的四个覆盖点（`TC_PAIR_WG_ROOT` / `TC_PAIR_WG_BIN` / `TC_PAIR_WGQUICK_BIN` /
`TC_PAIR_IP_BIN`）让这一整段在这里真的执行一遍：改配置、调命令、失败回滚。

覆盖的是**服务器侧**，因此客户端也是独立实现的一小份：自己用 openssl 造 RSA 密钥、
自己签申请、自己解 JWE。只有这样才能验出「两边协议是不是同一个」——复用服务器脚本
里的函数就等于自己验自己。
"""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "assets" / "tc-pair.py"
PYTHON = sys.executable
INTERFACE = "tc00000000"
# 44 位的假公钥（32 字节 0x00..0x1f 的 base64）。假 wg 会把它当成接口公钥吐回来。
SERVER_PUBLIC_KEY = base64.b64encode(bytes(range(32))).decode("ascii")
SUBNET = "10.66.0.0/24"

# 旧版的键序写法：与服务器脚本里的 `compact` 同一套（签名覆盖的是字节，不是结构）。
def compact(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64std(raw):
    return base64.b64encode(raw).decode("ascii")


def sha256_hex(raw):
    return hashlib.sha256(raw).hexdigest()


def rfc3339_micros(unix):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(unix)) + ".%06dZ" % (int(unix * 1_000_000) % 1_000_000)


def openssl(args, data=None):
    done = subprocess.run(["openssl"] + args, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)
    return done.returncode, done.stdout, done.stderr


def openssl_ok(args, data=None):
    code, stdout, stderr = openssl(args, data)
    if code != 0:
        raise RuntimeError("openssl %s 失败：%s" % (args, stderr.decode("utf-8", "replace")[:400]))
    return stdout


# ------------------------------------------------------------------ 假的 wg

FAKE_WG = r'''
"""测试用的假 wg：只实现本协议用到的那两个子命令。"""
import json
import os
import sys

ROOT = os.environ["TC_FAKE_WG_ROOT"]
args = sys.argv[1:]
with open(os.path.join(ROOT, "calls.jsonl"), "a", encoding="utf-8") as log:
    log.write(json.dumps({"tool": "wg", "args": args}) + "\n")

if args[:1] == ["pubkey"]:
    with open(os.path.join(ROOT, "server.pub"), encoding="ascii") as stream:
        sys.stdout.write(stream.read().strip())
    sys.exit(0)

if args[:1] == ["syncconf"]:
    if os.environ.get("TC_FAKE_WG_FAIL") == "1":
        sys.stderr.write("fake wg: syncconf refused\n")
        sys.exit(1)
    source, target = args[2], os.path.join(ROOT, "synced.conf")
    with open(source, encoding="utf-8") as source_stream:
        with open(target, "w", encoding="utf-8") as target_stream:
            target_stream.write(source_stream.read())
    sys.exit(0)

sys.stderr.write("fake wg: unsupported\n")
sys.exit(2)
'''

FAKE_WGQUICK = r'''
"""测试用的假 wg-quick：`strip` 只是把主配置原样吐出来。"""
import json
import os
import sys

ROOT = os.environ["TC_FAKE_WG_ROOT"]
args = sys.argv[1:]
with open(os.path.join(ROOT, "calls.jsonl"), "a", encoding="utf-8") as log:
    log.write(json.dumps({"tool": "wg-quick", "args": args}) + "\n")

if args[:1] == ["strip"]:
    with open(os.path.join(ROOT, args[1] + ".conf"), encoding="utf-8") as stream:
        sys.stdout.write(stream.read())
    sys.exit(0)

sys.stderr.write("fake wg-quick: unsupported\n")
sys.exit(2)
'''

BASE_CONF = """[Interface]
Address = 10.66.0.1/24
ListenPort = 51820
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
# 已经接入的另一台设备：地址分配必须跳过它。
PublicKey = kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK=
AllowedIPs = 10.66.0.5/32
"""


# ------------------------------------------------------------------ 环境

class Env:
    """一套隔离的现场：pair 数据根 + 假 wireguard 配置 + 假 wg 命令。"""

    def __init__(self, tag):
        self.root = Path(tempfile.mkdtemp(prefix="tc-r38-%s-" % tag))
        self.pair = self.root / "pair"
        self.wg = self.root / "wireguard"
        self.tools = self.root / "tools"
        for path in (self.pair, self.wg, self.tools):
            path.mkdir(parents=True, exist_ok=True)
        (self.tools / "fake_wg.py").write_text(FAKE_WG, encoding="utf-8")
        (self.tools / "fake_wgquick.py").write_text(FAKE_WGQUICK, encoding="utf-8")
        (self.wg / "server.pub").write_text(SERVER_PUBLIC_KEY, encoding="ascii")
        (self.wg / ("%s.key" % INTERFACE)).write_text(
            base64.b64encode(bytes(range(1, 33))).decode("ascii"), encoding="ascii")
        (self.wg / ("%s.conf" % INTERFACE)).write_text(BASE_CONF, encoding="utf-8")
        self.port = 0
        self.process = None

    # ---- 进程与命令

    def variables(self, extra=None):
        env = dict(os.environ)
        env["TC_PAIR_ROOT"] = str(self.pair)
        env["TC_PAIR_WG_ROOT"] = str(self.wg)
        # 覆盖点是「一条命令」：Windows 上没法把 .py 直接当可执行文件跑。
        env["TC_PAIR_WG_BIN"] = "%s %s" % (PYTHON, self.tools / "fake_wg.py")
        env["TC_PAIR_WGQUICK_BIN"] = "%s %s" % (PYTHON, self.tools / "fake_wgquick.py")
        # 故意指向一个不存在的 ip 命令：这条兜底分支（退回配置里的 Address）也要跑过。
        env["TC_PAIR_IP_BIN"] = str(self.tools / "no-such-ip")
        env["TC_FAKE_WG_ROOT"] = str(self.wg)
        if extra:
            env.update(extra)
        return env

    def run(self, *args, **extra):
        done = subprocess.run([PYTHON, str(SCRIPT)] + list(args), env=self.variables(extra),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if done.returncode != 0:
            raise RuntimeError("tc-pair %s 失败：%s %s"
                               % (args, done.stdout.decode("utf-8", "replace"),
                                  done.stderr.decode("utf-8", "replace")))
        return json.loads(done.stdout.decode("utf-8"))

    def init(self):
        return self.run("init", "--interface", INTERFACE, "--endpoint", "203.0.113.10:18443")

    def create(self, lifetime=1800, device="新电脑"):
        return self.run("create", "--lifetime", str(lifetime), "--device", device)

    def cancel(self, invite_id):
        return self.run("cancel", "--id", invite_id)

    def status(self, invite_id):
        return self.run("status", "--id", invite_id)

    def start(self):
        self.port = free_port()
        self.process = subprocess.Popen(
            [PYTHON, str(SCRIPT), "serve", "--port", str(self.port)],
            env=self.variables(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wait_ready(self.port)

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

    # ---- 现场文件

    def conf(self):
        return (self.wg / ("%s.conf" % INTERFACE)).read_text(encoding="utf-8")

    def write_conf(self, text):
        (self.wg / ("%s.conf" % INTERFACE)).write_text(text, encoding="utf-8")

    def synced(self):
        path = self.wg / "synced.conf"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def calls(self):
        path = self.wg / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def invites(self):
        return json.loads((self.pair / "invites.json").read_text(encoding="utf-8"))

    def save_invites(self, value):
        (self.pair / "invites.json").write_text(compact(value) + "\n", encoding="utf-8")

    def management_jwk(self):
        return json.loads((self.pair / "signing-public.json").read_text(encoding="utf-8"))

    def close(self, keep):
        self.stop()
        if not keep:
            shutil.rmtree(self.root, ignore_errors=True)


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    return context


def request(port, method, path, token, body=None):
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=tls_context(), timeout=20)
    headers = {"Authorization": "Bearer %s" % token}
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=body, headers=headers)
        reply = conn.getresponse()
        raw = reply.read()
        return reply.status, json.loads(raw.decode("utf-8"))
    finally:
        conn.close()


def raw_request(port, data):
    """不经 http.client 的裸请求：用来构造「缺 Content-Length / 分块」这类畸形报文。"""
    with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
        with tls_context().wrap_socket(sock) as tls:
            tls.sendall(data)
            chunks = []
            try:
                while True:
                    piece = tls.recv(4096)
                    if not piece:
                        break
                    chunks.append(piece)
            except OSError:
                # 服务端回完就走、连接上还剩没读的正文时，有些系统会发 RST。
                # 已经收到的字节就是答案，不用把 RST 当失败。
                pass
    return b"".join(chunks).decode("utf-8", "replace")


def wait_ready(port, budget=15.0):
    """等到「TLS 握手 + 一次真实 GET」都通了才算起好。

    只等端口通不够：监听套接字在 TLS 包装之前就已经在 listen 了。
    """
    deadline = time.time() + budget
    probe_id = str(uuid.uuid4())
    while time.time() < deadline:
        try:
            status, body = request(port, "GET", "/v1/invitations/%s" % probe_id, "x")
            if status == 404 and body.get("Code") == "InviteNotFound":
                return
            return
        except (OSError, ValueError, http.client.HTTPException):
            time.sleep(0.1)
    raise RuntimeError("邀请服务没有在 %.0f 秒内起来" % budget)


# ------------------------------------------------------------------ 邀请码

def decode_code(code):
    assert code.startswith("TCI1."), "邀请码前缀不对"
    return json.loads(unb64u(code[5:]).decode("utf-8"))


def invite_payload(descriptor_jws):
    """从描述符里取出**已签名的邀请**载荷（ServerBinding 就在这里）。"""
    parts = descriptor_jws.split(".")
    assert len(parts) == 3, "描述符不是三段式签名"
    descriptor = json.loads(unb64u(parts[1]).decode("utf-8"))
    assert descriptor["Kind"] == "TradeChannel.OnlineInvite"
    inner = descriptor["Invite"].split(".")
    assert len(inner) == 3
    return json.loads(unb64u(inner[1]).decode("utf-8"))


# ------------------------------------------------------------------ JWK → PEM

def pem_from_jwk(jwk):
    """SubjectPublicKeyInfo 的 PEM。测试自己拼 DER，不借服务器脚本的手。"""
    def der(tag, content):
        length = len(content)
        if length < 128:
            head = bytes([length])
        else:
            raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
            head = bytes([0x80 | len(raw)]) + raw
        return bytes([tag]) + head + content

    def integer(raw):
        return der(0x02, (b"\0" + raw) if raw[0] & 0x80 else raw)

    modulus = unb64u(jwk["n"])
    exponent = unb64u(jwk["e"])
    rsa = der(0x30, integer(modulus) + integer(exponent))
    algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    spki = der(0x30, algorithm + der(0x03, b"\0" + rsa))
    body = base64.b64encode(spki).decode("ascii")
    lines = [body[index:index + 64] for index in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % "\n".join(lines)


# ------------------------------------------------------------------ 客户端

class Client:
    """模拟一台新电脑：自己造密钥、自己签申请。"""

    def __init__(self, workspace, request_id=None, device_id=None, created_at=None):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.private = self.workspace / ("recipient-%s.pem" % uuid.uuid4().hex)
        openssl_ok(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(self.private)])
        self.jwk = self.jwk_of(self.private)
        # 每台设备一把**不同**的隧道公钥。共用一把会被服务器正确地当成「同一台设备」
        # 而合并成一个 peer——那样地址分配那几条断言就变成自欺。
        self.client_public_key = b64std(os.urandom(32))
        self.request_id = request_id or str(uuid.uuid4())
        self.device_id = device_id or str(uuid.uuid4())
        self.created_at = created_at or rfc3339_micros(time.time())

    @staticmethod
    def jwk_of(private_path):
        """用 openssl 取模数，指数按 65537 固定（生成时用的就是默认值）。"""
        text = openssl_ok(["rsa", "-in", str(private_path), "-noout", "-modulus"]).decode("ascii")
        assert text.startswith("Modulus="), "取不到模数：%r" % text
        modulus = bytes.fromhex(text.strip().split("=", 1)[1])
        return {"kty": "RSA", "n": b64u(modulus), "e": b64u(b"\x01\x00\x01")}

    def digest(self):
        return sha256_hex("\n".join([
            "1", "TradeChannel.ClientRequest", self.request_id, self.device_id,
            self.created_at, self.client_public_key, "IPv4"]).encode("utf-8"))

    def pair_request(self, invite_id, binding, digest=None, device_name="新电脑2", signer=None):
        body = {
            "SchemaVersion": 1,
            "Kind": "TradeChannel.PairRequest",
            "InviteId": invite_id,
            "ServerBinding": binding,
            "ClientRequest": {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ClientRequest",
                "RequestId": self.request_id,
                "DeviceId": self.device_id,
                "CreatedAtUtc": self.created_at,
                "ClientPublicKey": self.client_public_key,
                "AddressFamilies": ["IPv4"],
            },
            "DeviceName": device_name,
            "RecipientJwk": self.jwk,
            "RequestDigest": digest if digest is not None else self.digest(),
            "RequestDigestAlgorithm": "TC-ClientRequest-v1",
            "CreatedAtUtc": self.created_at,
        }
        return sign_jws(body, signer or self.private)


def sign_jws(payload, private_path):
    header = b64u(b'{"alg":"RS256","typ":"JWT"}')
    body = b64u(compact(payload).encode("utf-8"))
    message = ("%s.%s" % (header, body)).encode("ascii")
    handle, name = tempfile.mkstemp(prefix="tc-r38-msg-")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(message)
        signature = openssl_ok(["dgst", "-sha256", "-sign", str(private_path), name])
    finally:
        os.unlink(name)
    return "%s.%s.%s" % (header, body, b64u(signature))


# ------------------------------------------------------------------ 开封授权

def open_authorization(jwe, private_path, management_jwk):
    """解开 5 段 JWE，返回 (明文 JWS, 载荷 JSON)。全程用 openssl + hashlib，不用服务器代码。"""
    parts = jwe.split(".")
    assert len(parts) == 5, "授权密文不是 5 段：%d" % len(parts)
    header = json.loads(unb64u(parts[0]).decode("utf-8"))
    assert header["alg"] == "RSA-OAEP-256", header
    assert header["enc"] == "A256CBC-HS512", header
    assert header["cty"] == "TC-Pairing-v1", header

    cek = openssl_ok(["pkeyutl", "-decrypt", "-inkey", str(private_path),
                      "-pkeyopt", "rsa_padding_mode:oaep",
                      "-pkeyopt", "rsa_oaep_md:sha256",
                      "-pkeyopt", "rsa_mgf1_md:sha256"], unb64u(parts[1]))
    assert len(cek) == 64, "CEK 不是 64 字节：%d" % len(cek)
    mac_key, enc_key = cek[:32], cek[32:]
    iv, ciphertext, tag = unb64u(parts[2]), unb64u(parts[3]), unb64u(parts[4])
    assert len(iv) == 16, "IV 不是 16 字节"
    assert len(tag) == 32, "标签不是 32 字节"

    aad = ("%s.%s" % (parts[0], parts[1])).encode("ascii")
    expected = hmac.new(mac_key, aad + iv + ciphertext + (len(aad) * 8).to_bytes(8, "big"),
                        hashlib.sha512).digest()[:32]
    assert hmac.compare_digest(tag, expected), "认证标签不符：AAD/IV/CT/AL 有一处不一样"

    plaintext = openssl_ok(["enc", "-d", "-aes-256-cbc", "-K", enc_key.hex(),
                            "-iv", iv.hex()], ciphertext)
    signed = plaintext.decode("utf-8")

    # 明文必须是管理私钥签过的 JWS，而且验签要能过。
    handle, key_path = tempfile.mkstemp(prefix="tc-r38-mgmt-")
    handle2, signature_path = tempfile.mkstemp(prefix="tc-r38-sig-")
    handle3, message_path = tempfile.mkstemp(prefix="tc-r38-signed-")
    try:
        with os.fdopen(handle, "w", encoding="ascii") as stream:
            stream.write(pem_from_jwk(management_jwk))
        segments = signed.split(".")
        assert len(segments) == 3, "授权明文不是三段式 JWS"
        with os.fdopen(handle2, "wb") as stream:
            stream.write(unb64u(segments[2]))
        with os.fdopen(handle3, "wb") as stream:
            stream.write(("%s.%s" % (segments[0], segments[1])).encode("ascii"))
        code, _, stderr = openssl(["dgst", "-sha256", "-verify", key_path,
                                   "-signature", signature_path, message_path])
        assert code == 0, "授权签名验不过：%s" % stderr.decode("utf-8", "replace")[:300]
    finally:
        for path in (key_path, signature_path, message_path):
            os.unlink(path)
    return signed, json.loads(unb64u(signed.split(".")[1]).decode("utf-8"))


# ------------------------------------------------------------------ 报告

class Report:
    def __init__(self):
        self.passed = 0
        self.failed = []

    def check(self, name, condition, detail=""):
        if condition:
            self.passed += 1
            say("  [通过] %s" % name)
        else:
            self.failed.append(name)
            say("  [失败] %s%s" % (name, ("：" + detail) if detail else ""))

    def equal(self, name, actual, expected):
        self.check(name, actual == expected, "实际=%r 期望=%r" % (actual, expected))


def say(text):
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


# ------------------------------------------------------------------ 场景

def scenario_happy_path(report, keep):
    """主链路：出码 → GET 拿到 InvitationReady → POST → 授权能被独立实现解开。"""
    say("\n== 主链路（含地址分配、加 peer、授权解封）==")
    env = Env("happy")
    try:
        env.init()
        first = env.create(device="交易电脑A")
        code = decode_code(first["code"])
        env.start()

        status, body = request(env.port, "GET", "/v1/invitations/%s" % code["i"], code["k"])
        report.equal("GET 状态码", status, 200)
        report.equal("GET 信封 Ok", body.get("Ok"), True)
        # 这一条就是本轮最靠前的阻塞：以前这里回的是 `Open`，客户端直接拒。
        report.equal("GET 状态词是客户端认的那一个", body["Data"]["Status"], "InvitationReady")

        # 客户端会拿邀请码里固定的指纹去比 TLS 证书：这里顺带把「指纹确实是 DER 的
        # 哈希」也验一遍，否则真机上表现为「服务器在跑、客户端说证书对不上」。
        with socket.create_connection(("127.0.0.1", env.port), timeout=10) as sock:
            with tls_context().wrap_socket(sock) as tls:
                pin = sha256_hex(tls.getpeercert(binary_form=True))
        report.equal("TLS 证书指纹与邀请码里的 t 一致", pin, code["t"])

        invite = invite_payload(body["Data"]["SignedDescriptor"])
        report.equal("邀请里的设备名来自 create", invite["DeviceName"], "交易电脑A")
        binding = invite["ServerBinding"]

        workspace = env.root / "clients"
        client = Client(workspace)
        jws = client.pair_request(code["i"], binding)
        status, reply = request(env.port, "POST", "/v1/invitations/%s/consume" % code["i"],
                                code["k"], json.dumps({"PairRequest": jws}))
        report.equal("POST 状态码", status, 200)
        report.equal("POST 信封 Ok", reply.get("Ok"), True)
        data = reply.get("Data") or {}
        report.equal("POST Data.Status", data.get("Status"), "Authorized")
        report.equal("POST 回传 RequestId", data.get("RequestId"), client.request_id)
        report.equal("POST 回传 RequestDigest", data.get("RequestDigest"), client.digest())
        report.check("EncryptedAuthorization 是 5 段",
                     len(str(data.get("EncryptedAuthorization", "")).split(".")) == 5)

        signed, authorization = open_authorization(
            data["EncryptedAuthorization"], client.private, env.management_jwk())
        report.equal("授权 Kind", authorization.get("Kind"), "TradeChannel.PairAuthorization")
        report.equal("授权 InviteId", authorization.get("InviteId"), code["i"])
        report.equal("授权 RequestId", authorization.get("RequestId"), client.request_id)
        report.equal("授权 RequestDigest", authorization.get("RequestDigest"), client.digest())
        report.equal("授权 ClientPublicKey", authorization.get("ClientPublicKey"),
                     client.client_public_key)
        report.equal("授权 RequestDigestAlgorithm", authorization.get("RequestDigestAlgorithm"),
                     "TC-ClientRequest-v1")
        report.equal("授权 ServerBinding 与邀请逐字段相同", authorization.get("ServerBinding"), binding)

        response = authorization.get("ClientResponse") or {}
        report.equal("响应 Kind", response.get("Kind"), "TradeChannel.ClientResponse")
        report.equal("响应 Status", response.get("Status"), "Authorized")
        report.equal("响应 RequestId", response.get("RequestId"), client.request_id)
        report.equal("响应 DeviceId", response.get("DeviceId"), client.device_id)
        report.equal("响应 ClientPublicKey", response.get("ClientPublicKey"),
                     client.client_public_key)
        report.equal("响应 ServerPublicKey", response.get("ServerPublicKey"), SERVER_PUBLIC_KEY)
        report.equal("响应 TunnelSubnet", response.get("TunnelSubnet"), SUBNET)
        report.equal("响应 ServerAddress 是网段首+1", response.get("ServerAddress"), "10.66.0.1/24")
        # 10.66.0.0 网络地址、.1 服务端、.5 已被占用（夹具里的老 peer）：所以给 .2。
        report.equal("响应 ClientAddress 跳过网络/服务端/已占用", response.get("ClientAddress"),
                     "10.66.0.2/32")
        report.equal("响应 AllowedIPs", response.get("AllowedIPs"), ["0.0.0.0/0"])
        report.equal("响应 AddressFamilies", response.get("AddressFamilies"), ["IPv4"])
        report.equal("响应 PublicEndpoint", response.get("PublicEndpoint"), "203.0.113.10:18443")
        report.equal("响应 PersistentKeepalive", response.get("PersistentKeepalive"), 25)

        conf = env.conf()
        report.check("配置里出现了客户端公钥", ("PublicKey = %s" % client.client_public_key) in conf)
        report.check("配置里给的是 .2/32", "AllowedIPs = 10.66.0.2/32" in conf)
        report.check("老 peer 没有被删掉", "10.66.0.5/32" in conf)
        report.check("配置里留了 RequestId 便于排查", client.request_id in conf)
        report.check("syncconf 真的被调用过",
                     any(call["args"][:1] == ["syncconf"] for call in env.calls()))
        report.check("synced.conf 收到了主配置内容",
                     "PublicKey = %s" % client.client_public_key in env.synced())

        record = env.invites()["Invites"][code["i"]]
        report.equal("服务器记下 State", record.get("State"), "Consumed")
        report.equal("服务器记下 RequestId", record.get("RequestId"), client.request_id)
        report.equal("服务器记下 DeviceId", record.get("DeviceId"), client.device_id)
        report.equal("服务器记下 ClientAddress", record.get("ClientAddress"), "10.66.0.2/32")

        status, body = request(env.port, "GET", "/v1/invitations/%s" % code["i"], code["k"])
        report.equal("消费之后 GET 转 RetryOnly", body["Data"]["Status"], "RetryOnly")
        report.equal("CLI 侧状态词仍然是 Open 那套（Consumed）",
                     env.status(code["i"])["state"], "Consumed")

        # ---- 幂等：同一个 RequestId 重试
        status, again = request(env.port, "POST", "/v1/invitations/%s/consume" % code["i"],
                                code["k"], json.dumps({"PairRequest": jws}))
        report.equal("重放同一 RequestId 仍然成功", again.get("Ok"), True)
        signed_again, authorization_again = open_authorization(
            again["Data"]["EncryptedAuthorization"], client.private, env.management_jwk())
        report.check("重放返回的授权明文逐字节相同", signed_again == signed)
        report.equal("重放不重新分配地址", authorization_again["ClientResponse"]["ClientAddress"],
                     "10.66.0.2/32")
        report.check("授权密文本身是新的（每次封装换 CEK/IV）",
                     again["Data"]["EncryptedAuthorization"] != data["EncryptedAuthorization"])
        report.equal("重放没有在配置里留下第二个同样的 peer",
                     env.conf().count("PublicKey = %s" % client.client_public_key), 1)

        # ---- 判据先于副作用：记录残缺时，重试不许先跑一遍 `wg syncconf` 再报错
        #      （先动配置会留下「配置里有、记录里没有」的设备，那台以后撤不掉）。
        #      这里只能用「syncconf 被调用了几次」来证伪：残缺的 peer 重写一遍
        #      在文本上是幂等的，比配置内容变化抓不到这个回归。
        sync_before = [call for call in env.calls() if call["args"][:1] == ["syncconf"]]
        broken = env.invites()
        broken["Invites"][code["i"]].pop("SignedAuthorization", None)
        env.save_invites(broken)
        status, reply = request(env.port, "POST", "/v1/invitations/%s/consume" % code["i"],
                                code["k"], json.dumps({"PairRequest": jws}))
        report.equal("记录里缺原授权时重试报 InvalidState", reply.get("Code"), "InvalidState")
        sync_after = [call for call in env.calls() if call["args"][:1] == ["syncconf"]]
        report.equal("记录残缺时没有动 WireGuard（syncconf 次数不变）",
                     len(sync_after), len(sync_before))

        # ---- 地址继续往后分配：.3、.4，并且仍然跳过 .5
        other = Client(workspace)
        second = env.create(device="交易电脑B")
        second_code = decode_code(second["code"])
        status, body = request(env.port, "GET", "/v1/invitations/%s" % second_code["i"],
                               second_code["k"])
        second_binding = invite_payload(body["Data"]["SignedDescriptor"])["ServerBinding"]
        status, reply = request(env.port, "POST",
                                "/v1/invitations/%s/consume" % second_code["i"], second_code["k"],
                                json.dumps({"PairRequest": other.pair_request(
                                    second_code["i"], second_binding)}))
        report.equal("第二台设备也拿到授权", reply.get("Ok"), True)
        _, second_authorization = open_authorization(
            reply["Data"]["EncryptedAuthorization"], other.private, env.management_jwk())
        report.equal("第二台设备拿到 .3", second_authorization["ClientResponse"]["ClientAddress"],
                     "10.66.0.3/32")

        third_client = Client(workspace)
        third = env.create(device="交易电脑C")
        third_code = decode_code(third["code"])
        status, body = request(env.port, "GET", "/v1/invitations/%s" % third_code["i"],
                               third_code["k"])
        third_binding = invite_payload(body["Data"]["SignedDescriptor"])["ServerBinding"]
        status, reply = request(env.port, "POST",
                                "/v1/invitations/%s/consume" % third_code["i"], third_code["k"],
                                json.dumps({"PairRequest": third_client.pair_request(
                                    third_code["i"], third_binding)}))
        _, third_authorization = open_authorization(
            reply["Data"]["EncryptedAuthorization"], third_client.private, env.management_jwk())
        report.equal("第三台设备跳过已占用的 .5，拿到 .4",
                     third_authorization["ClientResponse"]["ClientAddress"], "10.66.0.4/32")
    finally:
        env.close(keep)


def scenario_rejections(report, keep):
    """反向用例：每一种都要给出**准确**的错误码，不能退化成「协议不对」。"""
    say("\n== 反向用例（错误码必须准确）==")
    env = Env("reject")
    try:
        env.init()
        created = env.create(device="交易电脑D")
        code = decode_code(created["code"])
        env.start()
        status, body = request(env.port, "GET", "/v1/invitations/%s" % code["i"], code["k"])
        binding = invite_payload(body["Data"]["SignedDescriptor"])["ServerBinding"]
        workspace = env.root / "clients"
        client = Client(workspace)
        path = "/v1/invitations/%s/consume" % code["i"]

        def post(token, jws, target=path):
            status, reply = request(env.port, "POST", target, token,
                                    json.dumps({"PairRequest": jws}))
            return reply.get("Code") if reply.get("Ok") is False else "Ok:%s" % reply.get("Ok")

        report.equal("错误令牌是 Forbidden",
                     post("A" * 43, client.pair_request(code["i"], binding)), "Forbidden")
        report.equal("不存在的邀请是 InviteNotFound",
                     post(code["k"], client.pair_request(code["i"], binding),
                          "/v1/invitations/%s/consume" % uuid.uuid4()), "InviteNotFound")

        # 篡改摘要（签名重新做，所以「验签过、摘要不对」这一支单独被验到）
        tampered = client.pair_request(code["i"], binding, digest="0" * 64)
        report.equal("摘要被改是 PairingMismatch", post(code["k"], tampered), "PairingMismatch")

        # 换掉 ServerBinding（指向另一台服务器）
        foreign = dict(binding, NodeId=str(uuid.uuid4()))
        report.equal("换 ServerBinding 是 InviteMismatch",
                     post(code["k"], client.pair_request(code["i"], foreign)), "InviteMismatch")

        # 签名动一个字符：必须报「申请签名不对」，不是「服务器坏了」
        broken = client.pair_request(code["i"], binding)
        segments = broken.split(".")
        segments[2] = ("A" if segments[2][0] != "A" else "B") + segments[2][1:]
        report.equal("签名被改是 InvalidPairRequest",
                     post(code["k"], ".".join(segments)), "InvalidPairRequest")

        # 别人的私钥签了「本机」的 JWK：验签公钥取自申请里的 RecipientJwk，
        # 所以这必须失败——否则任何人都能替别人提交申请。
        impostor = Client(workspace)
        forged = sign_jws(
            json.loads(unb64u(client.pair_request(code["i"], binding).split(".")[1]).decode()),
            impostor.private)
        report.equal("换个私钥签同一份载荷是 InvalidPairRequest",
                     post(code["k"], forged), "InvalidPairRequest")

        # 配置注入：RequestId 会被写进 `wg` 配置的注释。验签能过（自己的私钥签的），
        # 所以形状必须在服务器侧挡住，否则一个换行就能往里塞额外的配置行。
        injector = Client(workspace)
        injector.request_id = "abc\nAllowedIPs = 0.0.0.0/0"
        conf_before = env.conf()
        report.equal("RequestId 里带换行是 InvalidPairRequest",
                     post(code["k"], injector.pair_request(code["i"], binding)), "InvalidPairRequest")
        report.check("注入没有碰到配置文件", env.conf() == conf_before)
        bad_key = Client(workspace)
        bad_key.client_public_key = "not-a-wireguard-key"
        report.equal("隧道公钥形状不对是 InvalidPairRequest",
                     post(code["k"], bad_key.pair_request(code["i"], binding)), "InvalidPairRequest")

        # 畸形报文：缺 Content-Length / 分块。两者都必须落到 InvalidRequest。
        no_length = ("POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer %s\r\n"
                     "Content-Type: application/json\r\nConnection: close\r\n\r\n{}"
                     % (path, code["k"]))
        report.check("缺 Content-Length 是 InvalidRequest",
                     '"Code":"InvalidRequest"' in raw_request(env.port, no_length.encode()))
        chunked = ("POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer %s\r\n"
                   "Transfer-Encoding: chunked\r\nContent-Type: application/json\r\n"
                   "Connection: close\r\n\r\n2\r\n{}\r\n0\r\n\r\n" % (path, code["k"]))
        report.check("分块传输是 InvalidRequest",
                     '"Code":"InvalidRequest"' in raw_request(env.port, chunked.encode()))

        # ---- 作废
        env.cancel(code["i"])
        status, body = request(env.port, "GET", "/v1/invitations/%s" % code["i"], code["k"])
        report.equal("作废后 GET 是 Cancelled", body["Data"]["Status"], "Cancelled")
        report.equal("作废后 POST 是 InviteCancelled",
                     post(code["k"], client.pair_request(code["i"], binding)), "InviteCancelled")

        # ---- 过期（直接改状态文件：等价于「等到那张码过期」，但不用真等）
        expiring = env.create(device="交易电脑E")
        expiring_code = decode_code(expiring["code"])
        status, body = request(env.port, "GET", "/v1/invitations/%s" % expiring_code["i"],
                               expiring_code["k"])
        expiring_binding = invite_payload(body["Data"]["SignedDescriptor"])["ServerBinding"]
        state = env.invites()
        state["Invites"][expiring_code["i"]]["ExpiresAtUtc"] = "2020-01-01T00:00:00Z"
        env.save_invites(state)
        status, body = request(env.port, "GET", "/v1/invitations/%s" % expiring_code["i"],
                               expiring_code["k"])
        report.equal("过期后 GET 是 Expired", body["Data"]["Status"], "Expired")
        expiring_client = Client(workspace)
        status, reply = request(env.port, "POST",
                                "/v1/invitations/%s/consume" % expiring_code["i"],
                                expiring_code["k"],
                                json.dumps({"PairRequest": expiring_client.pair_request(
                                    expiring_code["i"], expiring_binding)}))
        report.equal("过期后 POST 是 InviteExpired", reply.get("Code"), "InviteExpired")

        # ---- 被别人先占了
        taken = env.create(device="交易电脑F")
        taken_code = decode_code(taken["code"])
        status, body = request(env.port, "GET", "/v1/invitations/%s" % taken_code["i"],
                               taken_code["k"])
        taken_binding = invite_payload(body["Data"]["SignedDescriptor"])["ServerBinding"]
        owner = Client(workspace)
        status, reply = request(env.port, "POST",
                                "/v1/invitations/%s/consume" % taken_code["i"], taken_code["k"],
                                json.dumps({"PairRequest": owner.pair_request(
                                    taken_code["i"], taken_binding)}))
        report.equal("第一台设备接入成功", reply.get("Ok"), True)
        intruder = Client(workspace)
        status, reply = request(env.port, "POST",
                                "/v1/invitations/%s/consume" % taken_code["i"], taken_code["k"],
                                json.dumps({"PairRequest": intruder.pair_request(
                                    taken_code["i"], taken_binding)}))
        report.equal("另一台电脑用同一张码是被占用了（InviteConsumed）",
                     reply.get("Code"), "InviteConsumed")
        report.check("被挡住的那台设备没有进配置",
                     intruder.client_public_key not in env.conf())
    finally:
        env.close(keep)


def scenario_rollback(report, keep):
    """`wg syncconf` 失败：必须回滚 conf，并且邀请仍然是可用的。"""
    say("\n== 失败回滚（wg syncconf 拒绝）==")
    env = Env("rollback")
    try:
        env.init()
        created = env.create(device="交易电脑G")
        code = decode_code(created["code"])
        env.start()
        status, body = request(env.port, "GET", "/v1/invitations/%s" % code["i"], code["k"])
        binding = invite_payload(body["Data"]["SignedDescriptor"])["ServerBinding"]
        client = Client(env.root / "clients")
        before = env.conf()

        # 让假 wg 罢工：只有拿到服务进程的环境变量才生效，所以重启一个带 FAIL 的服务。
        env.stop()
        env.port = free_port()
        env.process = subprocess.Popen(
            [PYTHON, str(SCRIPT), "serve", "--port", str(env.port)],
            env=env.variables({"TC_FAKE_WG_FAIL": "1"}),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wait_ready(env.port)

        status, reply = request(env.port, "POST", "/v1/invitations/%s/consume" % code["i"],
                                code["k"], json.dumps({"PairRequest": client.pair_request(
                                    code["i"], binding)}))
        report.equal("syncconf 失败报 WireGuardApplyFailed", reply.get("Code"), "WireGuardApplyFailed")
        report.equal("失败后配置逐字节回到原样", env.conf(), before)
        report.check("失败后配置里没有这台设备", client.client_public_key not in env.conf())
        record = env.invites()["Invites"][code["i"]]
        report.equal("失败后邀请没有被标成 Consumed", record.get("State"), "Open")
        status, body = request(env.port, "GET", "/v1/invitations/%s" % code["i"], code["k"])
        report.equal("失败后仍然可以再试（GET 还是 InvitationReady）",
                     body["Data"]["Status"], "InvitationReady")

        # 修好之后重试必须成功——这才说明「回滚之后能重来」这件事是真的。
        env.stop()
        env.port = free_port()
        env.start()
        status, reply = request(env.port, "POST", "/v1/invitations/%s/consume" % code["i"],
                                code["k"], json.dumps({"PairRequest": client.pair_request(
                                    code["i"], binding)}))
        report.equal("修好之后同一份申请能成功", reply.get("Ok"), True)
    finally:
        env.close(keep)


def scenario_not_ready(report, keep):
    """还没初始化时：错误码要说人话，而不是崩栈。"""
    say("\n== 边界：还没初始化 ==")
    env = Env("empty")
    try:
        done = subprocess.run([PYTHON, str(SCRIPT), "status", "--id", str(uuid.uuid4())],
                              env=env.variables(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        payload = json.loads(done.stdout.decode("utf-8"))
        report.equal("没有 invites.json 时报 InviteNotFound（不是崩栈）",
                     payload.get("code"), "InviteNotFound")
        report.equal("失败时退出码非零", done.returncode, 1)
    finally:
        env.close(keep)


def main():
    parser = argparse.ArgumentParser(description="r38 消费邀请自测")
    parser.add_argument("--keep", action="store_true", help="保留临时目录")
    parser.add_argument("--only", default="", help="只跑某个场景（happy/rejections/rollback/empty）")
    options = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if not SCRIPT.exists():
        say("找不到 %s" % SCRIPT)
        return 2
    code, _, _ = openssl(["version"])
    if code != 0:
        say("这台机器上没有 openssl，无法自测")
        return 2

    report = Report()
    scenarios = [
        ("happy", scenario_happy_path),
        ("rejections", scenario_rejections),
        ("rollback", scenario_rollback),
        ("empty", scenario_not_ready),
    ]
    for name, scenario in scenarios:
        if options.only and options.only != name:
            continue
        scenario(report, options.keep)

    say("\n---- 结果：%d 项通过，%d 项失败 ----" % (report.passed, len(report.failed)))
    if report.failed:
        for name in report.failed:
            say("  失败：%s" % name)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
