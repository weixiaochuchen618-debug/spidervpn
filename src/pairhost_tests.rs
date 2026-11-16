//! 邀请服务的契约测试：python 侧签出来的东西，本机 Rust 侧必须能验过。
//!//! 这一组测试的靶子是**协议漂移**，不是逻辑分支。邀请功能的两头（服务器脚本 / 本机客户端）
//! 是两份独立实现，任何一处字段名、时间格式、base64 变体、指纹算法不同，表现都是
//! 「服务器说签好了、客户端说不是它签的」——这种故障在真机上要花很久才能定位，
//! 而在这里是几毫秒。
//!
//! 找不到 python3 时测试**打印跳过**而不是失败：CI 机器不一定装了解释器，
//! 但凡是能跑的环境都必须跑过这一遍（`--invite-*` 的真机验收也依赖它）。

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// 被测的服务器脚本本体，与 `pairhost::SCRIPT` 同一份文件。
const SCRIPT: &str = include_str!("../assets/tc-pair.py");

/// 找一个能用的解释器。`TC_PYTHON` 优先，方便在没有 `python3` 名字的机器上指路。
fn interpreter() -> Option<String> {
    if let Ok(value) = std::env::var("TC_PYTHON") {
        let trimmed = value.trim();
        if !trimmed.is_empty() && Path::new(trimmed).exists() {
            return Some(trimmed.to_string());
        }
    }
    for name in ["python3", "python"] {
        let ok = Command::new(name)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if ok {
            return Some(name.to_string());
        }
    }
    None
}

struct Harness {
    python: String,
    root: PathBuf,
    script: PathBuf,
}

impl Harness {
    fn new(tag: &str) -> Option<Harness> {
        let python = interpreter()?;
        let root = std::env::temp_dir().join(format!("tc-pair-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("建临时目录");
        let script = root.join("tc-pair.py");
        std::fs::write(&script, SCRIPT).expect("写脚本");
        Some(Harness { python, root, script })
    }

    fn run(&self, args: &[&str]) -> Value {
        let output = Command::new(&self.python)
            .arg(&self.script)
            .args(args)
            .env("TC_PAIR_ROOT", &self.root)
            .output()
            .expect("跑不起来 python");
        assert!(
            output.status.success(),
            "脚本失败（{:?}）：{}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("脚本输出不是 JSON")
    }

    fn read(&self, name: &str) -> Value {
        let text = std::fs::read_to_string(self.root.join(name)).expect("读状态文件");
        serde_json::from_str(&text).expect("状态文件不是 JSON")
    }

    /// 允许失败的一次调用：返回 `(成功与否, 解析出的 JSON)`。
    fn attempt(&self, args: &[&str]) -> (bool, Value) {
        let output = Command::new(&self.python)
            .arg(&self.script)
            .args(args)
            .env("TC_PAIR_ROOT", &self.root)
            .output()
            .expect("跑不起来 python");
        let value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output.status.success(), value)
    }

    fn init(&self) -> Value {
        self.run(&[
            "init",
            "--interface",
            "tc00000000",
            // 203.0.113.0/24 是文档专用网段：不可能是真实服务器，也不会被误连。
            "--endpoint",
            "203.0.113.10:18443",
            "--server-key",
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
        ])
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// C1：`forget-device` 只删那一条名称记录，别的名字原样保留；重复删除幂等。
#[test]
fn qa_forget_device_removes_only_the_named_record() {
    let Some(harness) = Harness::new("forget") else {
        return;
    };
    let keep = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    let drop = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    std::fs::write(
        harness.root.join("device-names.json"),
        serde_json::json!({
            "SchemaVersion": 1,
            "Names": {
                keep: {"Name": "保留的电脑", "UpdatedAtUtc": "2026-11-12T00:00:00Z"},
                drop: {"Name": "旧电脑", "UpdatedAtUtc": "2026-11-12T00:00:00Z"},
            }
        })
        .to_string(),
    )
    .expect("写名称文件");

    let removed = harness.run(&["forget-device", "--key", drop]);
    assert_eq!(removed["removed"], true, "{removed}");
    let names = harness.read("device-names.json");
    assert!(names["Names"].get(keep).is_some(), "别的名字不能被动：{names}");
    assert!(names["Names"].get(drop).is_none(), "目标名字必须删掉：{names}");

    // 再删一次：不报错，如实说「本来就没有」。
    let again = harness.run(&["forget-device", "--key", drop]);
    assert_eq!(again["removed"], false, "{again}");

    // 形状不对的公钥在脚本侧也要被拒——即使有人绕过了 Rust 的前置校验。
    let (ok, value) = harness.attempt(&["forget-device", "--key", "short"]);
    assert!(!ok, "非法公钥必须被拒：{value}");
}

fn now_unix() -> i64 {
    crate::model::now_epoch_secs_u64() as i64
}

/// PEM → DER。测试自己解，不借服务器脚本的手：要验的正是「脚本算的是不是 DER」。
fn pem_to_der(pem: &str) -> Vec<u8> {
    use base64::Engine;
    let body: String = pem
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("PEM 解不开")
}

/// 证书指纹必须是**DER** 的哈希。
///
/// 客户端（rustls）拿到的是 TLS 握手里的 DER 字节，拿 PEM 文件的哈希去比永远不等。
/// 这个错误只有真连一次才暴露——本机契约测试要提前把它按住，否则表现是
/// 「服务器明明在跑，客户端说证书对不上」。
#[test]
fn 证书指纹取的是_DER_不是_PEM_文本() {
    let Some(harness) = Harness::new("cert") else {
        eprintln!("跳过：这台机器上没有 python3");
        return;
    };
    let initialized = harness.init();
    let pem = std::fs::read_to_string(harness.root.join("tls.crt")).expect("没有证书文件");
    let der = pem_to_der(&pem);
    let expected = crate::pairing::jwk::sha256_hex(&der);
    let reported = initialized["tlsSha256"].as_str().expect("没报证书指纹");
    assert_eq!(reported, expected, "报的证书指纹不是 DER 的哈希");
    assert_ne!(
        reported,
        crate::pairing::jwk::sha256_hex(pem.as_bytes()),
        "这是 PEM 文件的哈希 —— 客户端永远比对不上"
    );

    // 签出的邀请码里固定的也是这个值：三处（init/create/码内）必须一致。
    let created = harness.run(&["create", "--lifetime", "1800", "--device", "新电脑"]);
    assert_eq!(created["tlsSha256"].as_str().unwrap(), expected);
    let invite = crate::pairing::parse_code(created["code"].as_str().unwrap(), false, now_unix())
        .expect("解析失败");
    assert_eq!(invite.tls_sha256, expected);
}

/// 最重要的一条：本机解析器必须认服务器签出来的码，指纹算法必须**逐字节**一致。
///
/// 指纹不一致会让后面每一条校验都失败，而错误信息只会说「身份不一致」——
/// 看起来像攻击，实际是编码差异。这一条就是专门用来把这两种情况分开的。
#[test]
fn 服务器签出的邀请码本机能解析且指纹一致() {
    let Some(harness) = Harness::new("contract") else {
        eprintln!("跳过：这台机器上没有 python3（设 TC_PYTHON 可指定解释器）");
        return;
    };
    let initialized = harness.init();
    let created = harness.run(&["create", "--lifetime", "1800", "--device", "交易电脑2"]);
    let code = created["code"].as_str().expect("没有邀请码");

    let invite = crate::pairing::parse_code(code, false, now_unix()).expect("本机解析器不认这个码");

    // 服务器自己报的指纹、Rust 从 JWK 算出的指纹、邀请码里固定的指纹，三者必须相同。
    let jwk = harness.read("signing-public.json");
    let key = crate::pairing::jwk::RsaJwk::parse(&jwk).expect("公钥不是合法 JWK");
    let expected = initialized["managementFingerprint"].as_str().expect("没报指纹");
    assert_eq!(key.fingerprint(), expected, "Rust 与 python 的指纹算法不一致");
    assert_eq!(invite.management_fingerprint, expected, "邀请码里的指纹不是这把钥匙");
    assert_eq!(created["managementFingerprint"].as_str().unwrap(), expected);

    // 时间与入口按原值回读：这里错一位，界面上的倒计时就会差一截。
    assert_eq!(invite.host, "203.0.113.10");
    assert_eq!(invite.port, 18443);
    assert_eq!(invite.invite_id, created["inviteId"].as_str().unwrap());
    assert_eq!(invite.tls_sha256, created["tlsSha256"].as_str().unwrap());
    assert_eq!(invite.expires_unix, created["expiresUnix"].as_i64().unwrap());
    assert_eq!(created["deviceName"].as_str().unwrap(), "交易电脑2");
}

/// 描述符是**服务器签名的第二条链路**：邀请码只固定身份，内容要靠这份 JWS 取。
/// 它过不了，客户端连「邀请是不是真的」都判不出来。
#[test]
fn 服务器签出的描述符能被本机验签() {
    let Some(harness) = Harness::new("descriptor") else {
        eprintln!("跳过：这台机器上没有 python3");
        return;
    };
    harness.init();
    let created = harness.run(&["create", "--lifetime", "3600", "--device", "新电脑"]);
    let code = created["code"].as_str().unwrap();
    let now = now_unix();
    let invite = crate::pairing::parse_code(code, false, now).expect("解析失败");

    let state = harness.read("invites.json");
    let descriptor = state["Invites"][&invite.invite_id]["SignedDescriptor"]
        .as_str()
        .expect("服务器没有存描述符");
    let verified = crate::pairing::descriptor::verify(descriptor, &invite, now)
        .expect("描述符验签失败：两边的字段或签名算法不一致");

    assert_eq!(verified.invite_id, invite.invite_id);
    assert_eq!(verified.public_host, invite.host);
    assert_eq!(verified.port, invite.port);
    assert_eq!(verified.expires_unix, invite.expires_unix);
    // 旧版的容忍窗口是「过期后 120 秒还能用原申请重试」，两边必须一样。
    assert_eq!(verified.retry_until_unix, invite.expires_unix + 120);
    // 内嵌的邀请载荷也要有 13 个字段里最关键的那几个。
    assert_eq!(verified.invite["Kind"], "TradeChannel.PairInvite");
    assert_eq!(verified.invite["DeviceName"], "新电脑");
    assert_eq!(verified.invite["PublicEndpoint"], "203.0.113.10:18443");
}

/// 变异测试：篡改签名必须验不过。
///
/// 「验过了」这件事只有配上「改一个字节就验不过」才有意义——否则一个永远返回 Ok 的
/// 实现也能通过上面两条。
#[test]
fn 描述符改一个字节就验不过() {
    let Some(harness) = Harness::new("tamper") else {
        eprintln!("跳过：这台机器上没有 python3");
        return;
    };
    harness.init();
    let created = harness.run(&["create", "--lifetime", "3600", "--device", "新电脑"]);
    let code = created["code"].as_str().unwrap();
    let now = now_unix();
    let invite = crate::pairing::parse_code(code, false, now).expect("解析失败");
    let state = harness.read("invites.json");
    let descriptor = state["Invites"][&invite.invite_id]["SignedDescriptor"]
        .as_str()
        .unwrap()
        .to_string();

    // 改签名段的最后一个字符：结构不变、内容变了，必须被拒。
    let mut parts: Vec<String> = descriptor.split('.').map(str::to_string).collect();
    let signature = parts[2].clone();
    let flipped = if signature.ends_with('A') { "B" } else { "A" };
    parts[2] = format!("{}{}", &signature[..signature.len() - 1], flipped);
    let tampered = parts.join(".");
    assert!(
        crate::pairing::descriptor::verify(&tampered, &invite, now).is_err(),
        "签名被改过却验过了 —— 这条链路等于没有校验"
    );

    // 再把邀请码本身的有效期改到过去：过期就该拒，不能靠「描述符还新鲜」蒙过去。
    let expired = crate::pairing::parse_code(code, false, invite.expires_unix + 1);
    assert!(expired.is_err(), "过期邀请码被接受了");
}

/// 同一台服务器重复 `init` 不许换身份：换了等于把已经发出去的邀请码全作废。
#[test]
fn 重复初始化不换身份() {
    let Some(harness) = Harness::new("idempotent") else {
        eprintln!("跳过：这台机器上没有 python3");
        return;
    };
    let first = harness.init();
    let second = harness.init();
    assert_eq!(first["managementFingerprint"], second["managementFingerprint"]);
    assert_eq!(first["tlsSha256"], second["tlsSha256"]);
    assert_eq!(first["nodeId"], second["nodeId"]);
}

/// 作废过的邀请不能再被当成「待使用」：状态机错了会让界面显示「可以加入」。
#[test]
fn 作废之后状态不再是待使用() {
    let Some(harness) = Harness::new("cancel") else {
        eprintln!("跳过：这台机器上没有 python3");
        return;
    };
    harness.init();
    let created = harness.run(&["create", "--lifetime", "1800", "--device", "新电脑"]);
    let id = created["inviteId"].as_str().unwrap();
    let before = harness.run(&["status", "--id", id]);
    assert_eq!(before["state"], "Open");
    let cancelled = harness.run(&["cancel", "--id", id]);
    assert_eq!(cancelled["state"], "Cancelled");
    let after = harness.run(&["status", "--id", id]);
    assert_eq!(after["state"], "Cancelled");
    // 再作废一次是幂等的：界面会重试，重试不该报错。
    let again = harness.run(&["cancel", "--id", id]);
    assert_eq!(again["state"], "Cancelled");
}

/// 设备改名只写一份名字表：公钥 → 名字。部署创建的设备没有邀请记录，也要能起名。
#[test]
fn 设备改名按公钥写入并能读回() {
    let Some(harness) = Harness::new("names") else {
        eprintln!("跳过：这台机器上没有 python3");
        return;
    };
    let key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    let renamed = harness.run(&["rename-device", "--key", key, "--name", "东京本机"]);
    assert_eq!(renamed["name"], "东京本机");
    let names = harness.run(&["device-names"]);
    assert_eq!(names["names"][key]["Name"], "东京本机");
    let on_disk = harness.read("device-names.json");
    assert_eq!(on_disk["Names"][key]["Name"], "东京本机");
    assert!(
        !on_disk.to_string().contains(&*harness.root.to_string_lossy()),
        "名字表里不该出现绝对路径：{on_disk}"
    );
    // 再改一次是覆盖，不追加第二份。
    harness.run(&["rename-device", "--key", key, "--name", "东京主力"]);
    let names = harness.run(&["device-names"]);
    assert_eq!(names["names"].as_object().unwrap().len(), 1);
    assert_eq!(names["names"][key]["Name"], "东京主力");
}

#[test]
fn 设备改名拒绝坏公钥与坏名字() {
    let Some(harness) = Harness::new("names-bad") else {
        eprintln!("跳过：这台机器上没有 python3");
        return;
    };
    let key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    let (ok, value) = harness.attempt(&["rename-device", "--key", "short", "--name", "x"]);
    assert!(!ok, "{value}");
    assert_eq!(value["code"], "InvalidClientKey", "{value}");
    let (ok, value) = harness.attempt(&["rename-device", "--key", key, "--name", "  "]);
    assert!(!ok, "{value}");
    assert_eq!(value["code"], "InvalidDeviceName", "{value}");
    let (ok, value) = harness.attempt(&["rename-device", "--key", key, "--name", "a\nb"]);
    assert!(!ok, "{value}");
    assert_eq!(value["code"], "InvalidDeviceName", "{value}");
}
