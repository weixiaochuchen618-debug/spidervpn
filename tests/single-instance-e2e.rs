//! 单实例锁的边界：**只读命令可与界面并存**，改代理/配置的命令仍必须独占。
//! 并且：**不持锁就不自愈**——只读命令没有副作用。
//!
//! 背景（验收方实测）：界面开着时在终端跑 `--status` 会被锁拒成 exit 4
//! 「已经有一个 SpiderVPN 在运行了」。锁的目的是防两个守护同时接管代理，
//! 纯读命令不需要——而「界面开着，另开终端查状态」恰恰是最常见的用法。
//!
//! 界面用无参数启动（`no_arguments_still_opens_the_gui` 同法），它在起窗口之前就会抢到锁。

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-inst-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("data")).expect("建临时数据根");
    p
}

fn proxy_key(tag: &str) -> String {
    format!(r"Software\SpiderVPN\tests\inst-{tag}-{}", std::process::id())
}

fn run_key() -> String {
    format!(r"Software\SpiderVPN\tests\inst-run-{}", std::process::id())
}

fn spawn_cli(root: &Path, key: &str, args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .args(args)
        .env("SPIDERVPN_ROOT", root)
        .env("SPIDERVPN_PROXY_KEY", key)
        .env("SPIDERVPN_RUN_KEY", run_key())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("启动被测程序")
}

fn run(root: &Path, key: &str, args: &[&str]) -> (Option<i32>, String) {
    let mut child = spawn_cli(root, key, args);
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if child.try_wait().expect("等待被测程序").is_some() {
            let out = child.wait_with_output().expect("取输出");
            return (out.status.code(), String::from_utf8_lossy(&out.stdout).to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("被测程序 30 秒未退出（{args:?}）");
}

/// 起一个「界面」（无参数）：它先抢单实例锁，然后才建窗口，所以抢到锁是稳定可达的状态。
///
/// stdout 必须接管道：`wait_for_lock` 的判据就是它自己打印的那行「单实例名」。
fn spawn_gui(root: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .env("SPIDERVPN_ROOT", root)
        .env(
            "SPIDERVPN_PROXY_KEY",
            format!(r"Software\SpiderVPN\tests\inst-gui-{}", std::process::id()),
        )
        .env(
            "SPIDERVPN_RUN_KEY",
            format!(r"Software\SpiderVPN\tests\inst-gui-run-{}", std::process::id()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("启动被测程序（界面）")
}

fn snapshot(lines: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    lines.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// 等界面真的把锁拿走。
///
/// **判据是界面自己打印的「单实例名：…」那一行**：它在 `instance::acquire` 成功之后
/// 才写出来，所以看到它就是「锁已经在它手里」，不需要再去探。
///
/// 以前这里用「跑一条 `--use` 看它是否被拒成 exit 6」当探针，而**探针本身会抢锁**：
/// 冷启动时界面还没走到 `instance::acquire`，探针先把锁拿走，界面于是自己以 CONFLICT
/// 退出；等待方随后永远等不到 6，45 秒后报「界面 45 秒内没拿到锁」——指向的是错的代码
/// （这正是那条偶发挂起的现场）。读它自己的输出没有这个副作用，也少起几十个进程。
///
/// 界面在拿到锁之前退出时**立刻报错并带上它打印的最后几行**：那几行会直接说明原因
/// （例如「已经有一个 SpiderVPN 在运行了。」），不必再猜 45 秒。
fn wait_for_lock(gui: &mut Child) -> Vec<String> {
    let stdout = gui.stdout.take().expect("界面的 stdout 必须接管道");
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let (locked_tx, locked_rx) = mpsc::channel::<()>();
    {
        let lines = Arc::clone(&lines);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if line.contains("单实例名：") {
                    let _ = locked_tx.send(());
                }
                lines.lock().unwrap_or_else(|e| e.into_inner()).push(line);
            }
        });
    }

    // 45 秒而不是 20 秒：界面要等 WebView2 起来才拿锁，机器一忙（并发跑测试、杀软扫盘）
    // 20 秒会被真事撞上——那是环境慢，不是「界面没抢锁」，报成红只会让人去查错的代码。
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match locked_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(()) => return snapshot(&lines),
            // 输出结束 = 进程没了（或正在退出）。下面那步 `try_wait` 会给出结论；
            // 这里稍等一拍，免得在「线程已结束、进程还没被回收」的几毫秒里空转。
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if let Some(status) = gui.try_wait().expect("检查界面进程") {
            panic!(
                "界面在拿到单实例锁之前就退出了（{status}）。它打印的最后几行：\n{}",
                tail_of(&snapshot(&lines))
            );
        }
        if Instant::now() >= deadline {
            panic!(
                "界面 45 秒内没拿到单实例锁。它打印的最后几行：\n{}",
                tail_of(&snapshot(&lines))
            );
        }
    }
}

/// 断言用的那几行：只取尾部，界面的开场白有十几行，全贴出来反而挡住结论。
fn tail_of(lines: &[String]) -> String {
    let start = lines.len().saturating_sub(8);
    lines[start..].join("\n")
}

fn shutdown(mut gui: Child) {
    let _ = gui.kill();
    let _ = gui.wait();
}

fn assert_alive(gui: &mut Child) {
    assert!(gui.try_wait().expect("检查界面进程").is_none(), "界面进程必须还活着（它才是持锁方）");
}

/// 代理键当前值（ProxyEnable, ProxyServer, ProxyOverride）。
fn key_state(key: &str) -> (u32, String, String) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let k = hkcu.open_subkey(key).expect("代理键必须存在");
    (
        k.get_value::<u32, _>("ProxyEnable").unwrap_or(0),
        k.get_value::<String, _>("ProxyServer").unwrap_or_default(),
        k.get_value::<String, _>("ProxyOverride").unwrap_or_default(),
    )
}

/// 造一份「上次异常退出」的现场：还原凭据在、引擎已死、代理还指着我们（且指向的正是凭据里那条端点）。
/// 这样自愈一旦执行，代理键就一定会被改回去——正控能证明这份现场不是空壳。
fn stale_site(root: &Path, key: &str, endpoint: &str) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (k, _) = hkcu.create_subkey(key).expect("建临时代理键");
    k.set_value("ProxyEnable", &1u32).unwrap();
    k.set_value("ProxyServer", &endpoint.to_string()).unwrap();
    k.set_value("ProxyOverride", &"localhost".to_string()).unwrap();

    let data = root.join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(
        data.join("proxy-journal.json"),
        format!(
            r#"{{"schema":1,"endpoint":"{endpoint}","saved_at_secs":1.0,
                 "saved":{{"enable":false,"server":null,"bypass":null}}}}"#
        ),
    )
    .unwrap();
    // 引擎 pid 用一个确定不存在的值 = 「引擎已死」，这正是自愈的触发条件。
    std::fs::write(
        data.join("runtime.json"),
        r#"{"SchemaVersion":1,"SupervisorPid":0,"EnginePid":2147483646,
            "StartedAt":"2026-01-01T00:00:00Z","State":"Running"}"#,
    )
    .unwrap();
}

#[test]
fn status_works_while_the_ui_is_running() {
    let root = tmp_root("status");
    let key = proxy_key("status");
    let mut gui = spawn_gui(&root);
    wait_for_lock(&mut gui);
    assert_alive(&mut gui);

    let (code, out) = run(&root, &key, &["--status"]);
    assert_eq!(code, Some(0), "界面开着时 --status 必须能跑（以前被锁拒成 exit 4）：{out}");
    assert!(!out.contains("已经有一个 SpiderVPN 在运行了"), "只读命令不该再报单实例冲突：{out}");
    // 正常输出该有的那几行都在：不是"没被拒但也没干活"。
    assert!(out.contains("状态      ："), "要正常打出状态行：{out}");
    assert!(out.contains("通道自检  ："), "自检结论也要读得到：{out}");
    assert!(out.contains("控制接口  ："), "{out}");

    shutdown(gui);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn restore_still_needs_exclusive_access() {
    // `--restore` 会按凭据改系统代理（写注册表）：它必须继续独占，
    // 否则界面正在接管时另一个进程也能同时写代理设置。它**不在** SHARED_READ_COMMANDS 里。
    let root = tmp_root("restore");
    let key = proxy_key("restore");
    let mut gui = spawn_gui(&root);
    wait_for_lock(&mut gui);
    assert_alive(&mut gui);

    let (code, out) = run(&root, &key, &["--restore"]);
    assert_eq!(code, Some(6), "界面开着时 --restore 必须仍被单实例锁拒掉（冲突）：{out}");
    assert!(out.contains("已经有一个 SpiderVPN 在运行了"), "{out}");

    shutdown(gui);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn read_only_command_does_not_self_heal_without_the_lock() {
    // 自愈是状态变更（还原代理 + 消费凭据），不是读：不持锁时只读命令必须一动不动。
    // 先跑一次正控证明"这份现场真的会触发自愈"，否则下面的断言是空的。
    let alone = tmp_root("heal-alone");
    let alone_key = proxy_key("heal-alone");
    stale_site(&alone, &alone_key, "127.0.0.1:18991");
    let before = key_state(&alone_key);
    let (code, out) = run(&alone, &alone_key, &["--status"]);
    assert_eq!(code, Some(0), "{out}");
    assert_ne!(
        key_state(&alone_key),
        before,
        "正控：没人持锁时 --status 自己持锁 → 应当自愈（若这里没变，下面的断言就是空的）：{out}"
    );
    assert!(
        !alone.join("data").join("proxy-journal.json").exists(),
        "正控：自愈应把凭据消费掉"
    );
    let _ = std::fs::remove_dir_all(&alone);

    // 主断言：界面在跑（锁被占）→ 只读命令不持锁 → 不许自愈、不许消费凭据。
    // 现场必须在界面起来**之后**才铺：界面自己持锁，会在启动时把自愈跑掉。
    let root = tmp_root("heal-gui");
    let key = proxy_key("heal-gui");
    let mut gui = spawn_gui(&root);
    wait_for_lock(&mut gui);
    assert_alive(&mut gui);

    stale_site(&root, &key, "127.0.0.1:18992");
    let before = key_state(&key);
    let (code, out) = run(&root, &key, &["--status"]);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(key_state(&key), before, "不持锁时只读命令不许改系统代理：{out}");
    assert!(
        root.join("data").join("proxy-journal.json").exists(),
        "凭据也不许被消费——那是持锁实例的事：{out}"
    );
    assert!(
        root.join("data").join("runtime.json").exists(),
        "运行时记录同样不许被动：{out}"
    );

    shutdown(gui);
    let _ = std::fs::remove_dir_all(&root);
}

/// 界面在拿到锁之前退出时，等待方必须**立刻**把原因说出来，而不是等满 45 秒。
///
/// 这条钉的是那个偶发「界面 45 秒内没拿到单实例锁」的现场：界面其实已经退出（exit 6，
/// 锁被别的实例占着），等待方却还在等一个永远不会出现的结果。用「第二个界面抢同一个
/// 数据根」把那份现场稳定造出来——它必然抢不到锁，也必然立即退出。
#[test]
fn a_gui_that_exits_before_taking_the_lock_is_reported_at_once() {
    let root = tmp_root("lost-lock");
    let mut first = spawn_gui(&root);
    wait_for_lock(&mut first);
    assert_alive(&mut first);

    let mut second = spawn_gui(&root);
    let started = Instant::now();
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_for_lock(&mut second)
    }))
    .expect_err("第二个界面抢不到锁，等待方必须报错而不是一直等");
    let elapsed = started.elapsed();
    let text = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();

    assert!(
        text.contains("在拿到单实例锁之前就退出了"),
        "报的话必须说清「它已经退出」，而不是「45 秒内没拿到锁」：{text}"
    );
    assert!(
        text.contains("已经有一个 SpiderVPN 在运行了"),
        "要把它自己说的原因带出来，省得人去猜：{text}"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "必须立刻报（{elapsed:?}），不能等满 45 秒的超时"
    );

    shutdown(second);
    shutdown(first);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a3a_real_instance_lock_rejects_mixed_and_preserves_exclusive_cli_contract() {
    use std::io::Read;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;

    // The independent test executable retains the real Win32 mutex while each
    // CLI is a separate production process. No GUI timing or fake lock result.
    const ENGINE_ROLE: &str = "SPIDERVPN_A3A_TEST_ENGINE";
    if std::env::var(ENGINE_ROLE).as_deref() == Ok("1") {
        let mut buf = [0u8; 1];
        assert_eq!(std::io::stdin().read(&mut buf).unwrap(), 0);
        return;
    }
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) { unsafe { CloseHandle(self.0); } }
    }
    struct EngineGuard(Child);
    impl Drop for EngineGuard {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    let root = tmp_root("a3a-native-owner");
    let data = root.join("data");
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for b in data.to_string_lossy().as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let name = format!(r"Global\SpiderVPN-{hash:016x}");
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let raw = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
    let error = unsafe { GetLastError() };
    assert!(!raw.is_null(), "real instance mutex creation failed: {error}");
    let owner = HandleGuard(raw);
    assert_ne!(error, ERROR_ALREADY_EXISTS, "test must own a fresh mutex");

    let key = proxy_key("a3a-native-owner");
    stale_site(&root, &key, "127.0.0.1:18993");
    let mut engine = EngineGuard(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "a3a_real_instance_lock_rejects_mixed_and_preserves_exclusive_cli_contract"])
        .env(ENGINE_ROLE, "1").stdin(Stdio::piped())
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let runtime = data.join("runtime.json");
    let journal = data.join("proxy-journal.json");
    let config = data.join("config.json");
    std::fs::write(&runtime, format!(
        r#"{{"SchemaVersion":1,"SupervisorPid":{},"EnginePid":{},"StartedAt":"2026-01-01T00:00:00Z","State":"Running"}}"#,
        std::process::id(), engine.0.id())).unwrap();
    let runtime_before = std::fs::read(&runtime).unwrap();
    let journal_before = std::fs::read(&journal).unwrap();
    let proxy_before = key_state(&key);

    // No existing config: shared queries must not generate one or touch the
    // live engine's records/proxy. In particular headless may probe only: the
    // held fixture mutex has NO IPC server, so a bind by headless is detectable.
    for args in [&["--status"][..], &["--headless"][..]] {
        let (code, out) = run(&root, &key, args);
        assert_eq!(code, Some(0), "{args:?}: {out}");
        if args == ["--headless"] {
            assert!(out.contains("控制接口：不可用"), "non-owner created a control server: {out}");
            assert!(out.contains("headless：不创建窗口，仅自检"), "{out}");
        }
        assert!(!config.exists());
        assert_eq!(std::fs::read(&runtime).unwrap(), runtime_before);
        assert_eq!(std::fs::read(&journal).unwrap(), journal_before);
        assert_eq!(key_state(&key), proxy_before);
        assert_alive(&mut engine.0);
    }

    // Malformed config bytes must not be migrated/overwritten by rejected
    // combinations or ordinary conflicting write attempts.
    let config_before = b"owner-config-sentinel";
    std::fs::write(&config, config_before).unwrap();
    let mixed: &[&[&str]] = &[
        &["--plan", "--disconnect"], &["--disconnect", "--plan"],
        &["--plan", "--connect"], &["--headless", "--apply"],
        &["--status", "--guard-remove"], &["--providers", "--restore-apply"],
    ];
    let exclusive: &[&[&str]] = &[
        &["--connect"], &["--disconnect"], &["--connect", "--tun"],
        &["--restore"], &["--restore-apply"], &["--apply"],
        &["--import", "missing.json", "--engine", "sing-box.exe", "--port", "17890", "--line-name", "test", "--tun"],
        &["--split-add-process", "trader.exe", "--to", "trade"],
        &["--provider-add", "clashverge", "test", "directory", "7890", "a.example.com,b.example.com"],
        &["--guard-install", "--acknowledge-running"], &["--guard-sync", "--acknowledge-running"],
        &["--guard-remove"],
    ];
    for (cases, expected) in [(mixed, 2), (exclusive, 6)] {
        for args in cases {
            let (code, out) = run(&root, &key, args);
            assert_eq!(code, Some(expected), "{args:?}: {out}");
            if expected == 6 {
                assert!(out.contains("已经有一个 SpiderVPN 在运行了"), "{out}");
            } else {
                assert!(out.contains("不能混合主命令"), "{out}");
            }
            assert_eq!(std::fs::read(&config).unwrap().as_slice(), config_before);
            assert_eq!(std::fs::read(&runtime).unwrap(), runtime_before);
            assert_eq!(std::fs::read(&journal).unwrap(), journal_before);
            assert_eq!(key_state(&key), proxy_before);
            assert_alive(&mut engine.0);
        }
    }
    // Real ordinary process remains running until the fixture explicitly
    // releases stdin. A failed test also force-cleans only this child.
    drop(engine.0.stdin.take());
    assert!(engine.0.wait().unwrap().success());
    drop(owner);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let _ = hkcu.delete_subkey_all(&key);
    let _ = std::fs::remove_dir_all(&root);
}
