//! SpiderVPN 入口。
//!
//! 启动顺序刻意如此：**先证明隔离，再碰磁盘，最后才抢单实例锁**。
//! 任何一步失败都直接退出——宁可不启动，也不能去碰旧版的数据目录或系统代理。
// uiweb 的快照是一个很深的 json! 字面量，默认 128 层宏展开不够。
#![recursion_limit = "512"]

mod autostart;
// 自动选路（A8 第一阶段）：候选探测、网络指纹、证据过期与排名。
mod autoroute;
// AI 工具名单：内置目录 + 有效名单 + 走向口径（纯数据/纯函数，被 config/engine/界面共用）。
mod agents;
mod clipboard;
// 删除线路后没清掉的本地文件：记录、原子写、按 id 重算路径（A4 第二轮）。
mod cleanup;
mod config;
mod connect;
// 一次登录用什么凭据（服务器密码 / SSH 私钥）：解析、中文文案、两种信封的载荷形状。
// 传输层（`ssh`）只认这里的 `Auth`，永远看不到口令。
mod credential;
mod data;
mod deploy;
// 部署运行记录：磁盘形状、原子写、读取失败分类（A2/A3 部署中心的地基）。
mod deploystore;
// 任务级登录凭据（最长 24 小时、任务结束即删）：与 serverstore 的长期凭据分开。
mod deploycred;
// 部署引擎：线程、队列、lane、检查点推进、只读核对（T03）。
mod deployengine;
mod deployexport;
// 部署运行的纯逻辑层：词表、状态机、后续的推进与投影。
mod deployrun;
mod diagnose;
mod engine;
mod engine_config;
mod events;
mod exit_probe;
// 交易程序直连阻断（WFP）：名单身份、状态判定、平台层与提权通道。
// 分层见 src/guard/mod.rs 的头注释：判定不碰 FFI，FFI 不决定状态。
mod guard;
mod instance;
mod ipc;
mod isolation;
mod install_trust;
mod uninstall_safety;
mod lifecycle;
// 线路动作（测速 / 保存连接方式）的结果记录：要活过重启，启动时把被中断的动作改判。
mod lineaction;
mod model;
// 线路的「本机出口网卡」绑定（A 组网卡绑定）：按线路记，连接前决定绑谁。
mod netbind;
// 界面长操作（连接 / 断开 / 诊断）的记录：与线路动作同一套「开始落盘、启动改判」。
mod oprecord;
mod pairing;
mod pairhost;
mod pairstore;
mod perf;
mod presentation;
mod probe;
mod provider;
mod proxy;
mod recovery;
mod reminder;
mod selfcheck;
// 含私钥的文件（client.conf / tunnel.key / 线路 json）的落盘与 ACL 收紧（F1）。
mod secretfile;
mod shortcut;
mod servercmd;
// 「删除这台服务器在本机的部署资料」：判据只有一处，预览与执行都调它。
mod servercleanup;
mod serverstore;
mod ssh;
mod tray;
mod ui;
mod uiweb;
mod uiweb_form;
// 无引擎 UDP 直探（A8）：发一次真实的 WireGuard 握手，不启动引擎。
mod wgprobe;

/// R31「自动连接方式」的独立复核用例（QA 编写，只读产品逻辑、不改它）。
#[cfg(test)]
mod r31_qa_tests;

/// 邀请页的宿主侧用例：状态机与投影（r33）。
#[cfg(test)]
#[allow(non_snake_case)]
mod invite_ui_tests;

/// 邀请服务的契约测试：服务器侧脚本签出来的东西，本机必须能验过。
#[cfg(test)]
#[allow(non_snake_case)]
mod pairhost_tests;

/// R38「新电脑用邀请码真正加入」的独立复核：真 Rust 客户端 × 真 python 服务器。
#[cfg(test)]
mod r38_qa_tests;

/// R90「删除这台服务器在本机的部署资料」的独立复核（QA 编写，只读产品逻辑）。
#[cfg(test)]
mod r90_qa_tests;

use std::process::ExitCode;

/// 对外退出码。**改动即破坏脚本契约**：`--help` 里有同源说明表。
///
/// 旧值 7 / 12 已退役（7 = ping 未连接，12 = 配置/文件类）。退役不是换名字：
/// 旧脚本按 12 判「配置坏了」、按 7 判「没连上」，语义被拆到 CONFIG 与 ENVIRONMENT 两档。
pub(crate) mod exit {
    pub const OK: u8 = 0;
    /// 未分类内部错误兜底：出了没预料到的问题，不猜类别。
    pub const INTERNAL: u8 = 1;
    /// 用法错误：参数缺失、取值非法、未知开关。**这类失败绝不进图形界面**。
    pub const USAGE: u8 = 2;
    /// 配置 / 文件类，需要人工干预（改文件、重新导入线路）。
    pub const CONFIG: u8 = 3;
    /// 环境不支持或未就绪（未连接、权限不足、旧版在跑）。
    pub const ENVIRONMENT: u8 = 4;
    /// 网络类，可重试。
    pub const NETWORK: u8 = 5;
    /// 冲突，需要用户决策（同名线路、已有实例在运行）。
    pub const CONFLICT: u8 = 6;
}

fn main() -> ExitCode {
    // 控制台按 UTF-8 输出：程序里的提示是中文，默认代码页会把它们变成乱码。
    set_console_utf8();

    // 0. 参数先校验：**少了值 / 参数写错必须当场报错退出**，绝不许掉进图形界面。
    //    漏进 GUI 的后果不只是"没提示"：那个窗口会占着 exe，用户第二次升级就装不上
    //    （Copy-Item 文件被占用），看上去像"安装成功但版本没变"。
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cli_origin = events::Origin::cli();
    if let Err(msg) = validate_argv(&argv) {
        println!("  {}", msg);
        return ExitCode::from(exit::USAGE);
    }

    // `--help`：只打印用法就退出。放在隔离检查之前——它不碰磁盘、不建目录，
    // 装在只读介质上也能用；INSTALL.txt 一直承诺有这个开关，之前其实没实现。
    if argv.iter().any(|a| a == "--help") {
        print_usage();
        return ExitCode::SUCCESS;
    }

    // 1. 隔离：路径、互斥前缀、旧版运行检测。不通过就什么都不做。
    if let Err(e) = isolation::check() {
        eprintln!("隔离检查未通过：{:?}", e);
        eprintln!("安装目录：{}", isolation::install_dir().display());
        eprintln!("数据根  ：{}", isolation::data_root().display());
        eprintln!("已定版的 旧版被冻结，本程序不得与它共用任何运行时资源。");
        return ExitCode::from(exit::ENVIRONMENT);
    }

    // SEC-03：安装脚本仅负责文件复制；可信代码目录的受保护 ACL、
    // 数据目录的单独写入权限与 Win32 ACL 读回决策只在 Rust 实现。
    // 放在锁和正常初始化前：安装时程序本体尚未进入正式运行阶段。
    if let Some(vals) = arg_values("--install-seal", 1) {
        return match install_trust::seal_installed_product(
            std::path::Path::new(&vals[0]),
        ) {
            Ok(()) => {
                println!("  已核验并保护 SpiderVPN 程序目录；数据目录保持独立可写。");
                ExitCode::SUCCESS
            }
            Err(reason) => {
                eprintln!("  可信安装权限未完成：{reason}");
                ExitCode::from(exit::ENVIRONMENT)
            }
        };
    }

    // SEC-09：卸载安全闸门独立于 config.json；默认先由 Rust 清理并回读
    // 本程序自己的 WFP Provider，失败必须保留 EXE。显式 --keep-guard
    // 仅跳过这一动作，不允许跳过未还原的系统代理 journal。
    if let Some(vals) = arg_values("--uninstall-preflight", 1) {
        let keep_guard = argv.iter().any(|a| a == "--keep-guard");
        return match uninstall_safety::preflight(std::path::Path::new(&vals[0]), keep_guard) {
            Ok(()) => {
                println!("  安全卸载预检通过（交易保护：{}）。",
                    if keep_guard { "按用户要求保留" } else { "Rust 已回读确认解除" });
                ExitCode::SUCCESS
            }
            Err(msg) => {
                eprintln!("  安全卸载预检拒绝：{msg}");
                ExitCode::from(exit::ENVIRONMENT)
            }
        };
    }

    // 严格识别安装器真正生成的快捷入口，而不是模糊 Contains 安装根。
    // 不属于当前安装的 .cmd 一律不删（exit 3 = 非本安装文件）。
    if let Some(vals) = arg_values("--uninstall-owns-shortcut", 2) {
        return match uninstall_safety::owns_launcher(
            std::path::Path::new(&vals[0]), std::path::Path::new(&vals[1]),
        ) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(exit::CONFIG),
            Err(msg) => {
                eprintln!("  无法核验快捷方式归属：{msg}");
                ExitCode::from(exit::ENVIRONMENT)
            }
        };
    }

    // `--ping`：纯客户端探测，**不建目录、不抢单实例锁**。
    // 它要能在主程序运行时被调用；若先抢锁，第二个进程会被判成「重复启动」，就测不出控制面了。
    if std::env::args().any(|a| a == "--ping") {
        let name = ipc::name_for(&isolation::data_root().to_string_lossy());
        let ok = ipc::ping(&name, 500);
        // 文案里的「未连接」是契约词：脚本和人都按它判断，不要改成「不可用」一类同义词。
        println!("{}", if ok { "控制接口可用" } else { "未连接（控制接口不可用）" });
        return if ok { ExitCode::SUCCESS } else { ExitCode::from(exit::ENVIRONMENT) };
    }

    // `--guard-apply`：一次性提权子进程的内部入口。
    // 必须放在单实例锁之前——父进程正持有那把锁，子进程再抢会被误判成「重复启动」。
    if let Some(vals) = arg_values("--guard-apply", 2) {
        let req = std::path::PathBuf::from(&vals[0]);
        let res = std::path::PathBuf::from(&vals[1]);
        let backend = guard::wfp_win::WindowsWfp::new();
        let code = guard::elevate::guard_apply_main(&req, &res, &backend);
        return ExitCode::from(code as u8);
    }

    // `--desktop-shortcut`：把安装程序生成的开始菜单快捷方式复制到桌面（A7）。
    // 放在数据目录初始化之前——它只碰桌面那一个文件，配置坏了、数据根不可写时也该能用。
    // 界面上的按钮走的是同一条命令（`ipc::shortcut_json`），行为只有一份。
    if std::env::args().any(|a| a == "--desktop-shortcut") {
        return match shortcut::ensure_desktop_shortcut() {
            Ok(outcome) => {
                println!("  {}", outcome.message());
                // 桌面可能被重定向到别的盘：把实际去向写出来，用户说「没看到」时才有得查。
                if let Some(dir) = shortcut::desktop_dir() {
                    println!("  桌面目录：{}", dir.display());
                }
                ExitCode::SUCCESS
            }
            Err(message) => {
                println!("  {message}");
                ExitCode::from(exit::ENVIRONMENT)
            }
        };
    }

    // ── 部署（M5）：服务器记录与只读环境检查 ──
    //
    // 三条命令都放在数据目录初始化之前：检查不读本地配置、不写任何文件；
    // 记录只写 `data\servers\<id>\`，不需要先把整个 layout 建起来。
    // 这样在一台还没配置过线路的机器上也能用。
    //
    // 密码只从**标准输入**读一行：放进命令行会留在进程列表和命令历史里。
    let data_root = isolation::data_root();

    // `--server-forget`：删掉一条记录。
    // 这不是可选项：服务器重装后指纹会变，而 `--server-trust` 遇到指纹变化是**拒绝**的，
    // 没有这条命令，用户就被卡在「不能覆盖、也不能重来」的死角里。
    if let Some(spec) = arg_values("--server-forget", 1).map(|v| v[0].trim().to_string()) {
        let target = match ssh::Target::parse(&spec) {
            Ok(target) => target,
            Err(message) => {
                println!("  {message}");
                return ExitCode::from(exit::USAGE);
            }
        };
        return match serverstore::find_by_target(&data_root, &target) {
            Ok(Some(record)) => match serverstore::remove(&data_root, &record.id) {
                Ok(()) => {
                    println!("  已删除服务器记录：{}（{}）", record.name, record.address());
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    println!("  {}", error.message);
                    ExitCode::from(exit::CONFIG)
                }
            },
            Ok(None) => {
                println!("  本机没有 {spec} 的服务器记录，无需删除。");
                ExitCode::from(exit::CONFIG)
            }
            Err(error) => {
                println!("  {}", error.message);
                ExitCode::from(exit::CONFIG)
            }
        };
    }

    // `--server-trust`：核对指纹，然后把密码封进 DPAPI 存下来。
    if let Some(spec) = arg_values("--server-trust", 1).map(|v| v[0].trim().to_string()) {
        let target = match ssh::Target::parse(&spec) {
            Ok(target) => target,
            Err(message) => {
                println!("  {message}");
                return ExitCode::from(exit::USAGE);
            }
        };
        let Some(wanted) = arg_values("--fingerprint", 1).map(|v| v[0].trim().to_string()) else {
            println!(
                "  --server-trust 需要 --fingerprint：先运行 --server-inspect {spec} 拿到指纹，核对后再保存。"
            );
            return ExitCode::from(exit::USAGE);
        };
        // 保存前真连一次：确认服务器**现在**拿的就是这枚指纹。
        // 只信命令行给的值，等于把「确认身份」变成一道填空题。
        println!("  正在核对 {} 的主机指纹 …", target.host);
        match ssh::probe_host_key(&target, std::time::Duration::from_secs(15)) {
            Ok(actual) if actual == wanted => {}
            Ok(actual) => {
                println!("  指纹不一致：命令行给的是 {wanted}，服务器现在给的是 {actual}。未保存。");
                return ExitCode::from(exit::CONFLICT);
            }
            Err(error @ (ssh::Error::Connect(_) | ssh::Error::Timeout)) => {
                println!("  {error}");
                return ExitCode::from(exit::NETWORK);
            }
            Err(error) => {
                println!("  {error}");
                return ExitCode::from(exit::INTERNAL);
            }
        }
        let password = read_password_stdin();
        if password.is_empty() {
            println!("  需要从标准输入提供密码，例如：echo '密码' | spidervpn --server-trust {spec} --fingerprint {wanted}");
            return ExitCode::from(exit::USAGE);
        }
        let now = model::now_epoch_secs_u64() as i64;
        return match serverstore::trust(&data_root, &target, &wanted, &password, now) {
            Ok(record) => {
                println!("  已保存服务器记录：{}（{}）", record.name, record.address());
                println!("  之后可以直接运行 --server-inspect {spec}，不用再输密码。");
                ExitCode::SUCCESS
            }
            Err(error) if error.code == "ServerIdentityChanged" => {
                println!("  {}", error.message);
                ExitCode::from(exit::CONFLICT)
            }
            Err(error) => {
                println!("  {}", error.message);
                ExitCode::from(exit::CONFIG)
            }
        };
    }

    // `--invite-*`：邀请其他电脑（A1）。管理身份、邀请签发、邀请状态都在服务器上，
    // 本机只记「这台服务器是谁签的」和一串已经签好的邀请码。
    let invite_spec = arg_values("--invite-init", 1)
        .or_else(|| arg_values("--invite-create", 1))
        .or_else(|| arg_values("--invite-status", 1))
        .or_else(|| arg_values("--invite-cancel", 1))
        .map(|values| values[0].trim().to_string());
    if let Some(spec) = invite_spec {
        return ExitCode::from(run_invite(&data_root, &spec));
    }

    // `--invite-check`：拿邀请码去服务器读一次描述并验签。**只读**——不消费邀请，
    // 也不改服务器上的任何状态。这是「邀请码能不能用」的唯一权威判断。
    if let Some(code) = arg_values("--invite-check", 1).map(|values| values[0].trim().to_string()) {
        let now = model::now_epoch_secs_u64() as i64;
        let timeout = std::time::Duration::from_secs(15);
        return match pairing::read_invitation(&code, false, timeout, now) {
            Ok((status, descriptor)) => {
                let device = descriptor
                    .invite
                    .get("DeviceName")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                println!("  邀请状态：{status}");
                println!("  服务器  ：{}:{}", descriptor.public_host, descriptor.port);
                println!("  设备名  ：{device}");
                println!(
                    "  有效期至：{}",
                    pairing::rfc3339_micros(descriptor.expires_unix)
                );
                println!("  身份校验：通过（签名与邀请码固定的指纹一致）");
                ExitCode::from(exit::OK)
            }
            Err(error) => {
                println!("  {}（{}）", error.message, error.code);
                let code = match error.code.as_str() {
                    "OnlineConnectionFailed" | "InvalidOnlineResponse" => exit::NETWORK,
                    "OnlineTlsPinMismatch" | "OnlineInviteIdentityMismatch" => exit::CONFLICT,
                    "OnlineRedirectRefused" | "OnlineInviteExpired" | "InviteExpired"
                    | "InviteCancelled" => exit::CONFIG,
                    _ => exit::CONFIG,
                };
                ExitCode::from(code)
            }
        };
    }

    // `--server-inspect`：只读环境检查。
    if let Some(spec) = arg_values("--server-inspect", 1).map(|v| v[0].trim().to_string()) {
        let target = match ssh::Target::parse(&spec) {
            Ok(target) => target,
            Err(message) => {
                println!("  {message}");
                return ExitCode::from(exit::USAGE);
            }
        };
        // 给了指纹 = 一次性检查（密码走标准输入）；没给 = 先用本机记住的那条记录。
        let (target, fingerprint, password, interface) = match arg_values("--fingerprint", 1)
            .map(|v| v[0].trim().to_string())
        {
            Some(wanted) => {
                let password = read_password_stdin();
                if password.is_empty() {
                    println!("  需要从标准输入提供密码，例如：echo '密码' | spidervpn --server-inspect {spec} --fingerprint {wanted}");
                    return ExitCode::from(exit::USAGE);
                }
                (target, wanted, credential::Credential::password(password), None)
            }
            None => match serverstore::find_by_target(&data_root, &target) {
                Ok(Some(record)) => {
                    let stored = match serverstore::credential(&data_root, &record) {
                        Ok(stored) => stored,
                        Err(error) => {
                            println!("  {}", error.message);
                            println!("  请重新运行 --server-trust {spec} --fingerprint <指纹> 存一次密码。");
                            return ExitCode::from(exit::ENVIRONMENT);
                        }
                    };
                    // 记录里的可能是密码，也可能是私钥（r92）。要连服务器就得先变成
                    // 可用的 `Credential`；私钥解析失败在这里说人话，不要拖到握手。
                    let password = match stored.into_credential() {
                        Ok(password) => password,
                        Err(message) => {
                            println!("  {message}");
                            println!("  请重新运行 --server-trust {spec} --fingerprint <指纹> 存一份可用的登录资料。");
                            return ExitCode::from(exit::ENVIRONMENT);
                        }
                    };
                    // 用记录里的目标而不是用户敲的那串：大小写与写法以记录为准。
                    (
                        record.target(),
                        record.fingerprint.clone(),
                        password,
                        Some(deploy::Spec::for_record(&record.id).interface),
                    )
                }
                Ok(None) => {
                    // 第一次连这台机器：只读一次主机公钥就退出，**连密码都不问**。
                    // 先问密码再去连，等于让用户为一个根本不会发出去的凭据白输一遍。
                    println!("  正在读取 {}:{} 的主机指纹 …", target.host, target.port);
                    return match ssh::probe_host_key(&target, std::time::Duration::from_secs(15)) {
                        Ok(fingerprint) => {
                            println!("  这台服务器的主机指纹：");
                            println!("    {fingerprint}");
                            println!("  核对无误后运行：--server-trust {spec} --fingerprint {fingerprint}");
                            ExitCode::from(exit::CONFLICT)
                        }
                        Err(error @ (ssh::Error::Connect(_) | ssh::Error::Timeout)) => {
                            println!("  {error}");
                            ExitCode::from(exit::NETWORK)
                        }
                        Err(error) => {
                            println!("  {error}");
                            ExitCode::from(exit::INTERNAL)
                        }
                    };
                }
                Err(error) => {
                    println!("  {}", error.message);
                    return ExitCode::from(exit::CONFIG);
                }
            },
        };

        println!("  正在检查 {}@{}:{} …", target.user, target.host, target.port);
        let outcome =
            deploy::inspect(&target, &password, Some(&fingerprint), interface.as_deref(), std::time::Duration::from_secs(20));
        return match outcome {
            Ok(environment) => {
                println!("{}", environment.summary());
                if environment.blocking_reason().is_some() {
                    ExitCode::from(exit::ENVIRONMENT)
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(ssh::Error::HostKeyUnknown { fingerprint }) => {
                // 只有一次性检查会走到这里（记录里的指纹解不开密码时上面已经拦掉了）。
                println!("  这台服务器的主机指纹还没有确认：");
                println!("    {fingerprint}");
                println!("  请与服务器管理员核对，确认后加上 --fingerprint {fingerprint} 重新运行。");
                ExitCode::from(exit::CONFLICT)
            }
            Err(error @ ssh::Error::HostKeyMismatch { .. }) => {
                println!("  {error}");
                println!("  已停止：没有发送密码，也没有执行任何命令。");
                ExitCode::from(exit::CONFLICT)
            }
            Err(ssh::Error::Auth) => {
                println!("  用户名或密码不正确。");
                ExitCode::from(exit::ENVIRONMENT)
            }
            Err(error @ (ssh::Error::Connect(_) | ssh::Error::Timeout)) => {
                println!("  {error}");
                ExitCode::from(exit::NETWORK)
            }
            Err(error) => {
                println!("  {error}");
                ExitCode::from(exit::INTERNAL)
            }
        };
    }

    // `--server-deploy`：打印部署计划；`--server-deploy-apply`：真执行。
    //
    // 两条都要先有服务器记录（指纹 + 凭据）：部署是改系统的动作，
    // 不接受「先连上再说」——那等于把指纹确认跳过去了。
    let deploy_plan = arg_values("--server-deploy", 1).map(|v| v[0].trim().to_string());
    let deploy_apply = arg_values("--server-deploy-apply", 1).map(|v| v[0].trim().to_string());
    if deploy_plan.is_some() || deploy_apply.is_some() {
        let (apply, spec_text) = match (&deploy_plan, &deploy_apply) {
            (_, Some(spec)) => (true, spec.clone()),
            (Some(spec), None) => (false, spec.clone()),
            (None, None) => unreachable!("外层已经判过至少有一个"),
        };
        let target = match ssh::Target::parse(&spec_text) {
            Ok(target) => target,
            Err(message) => {
                println!("  {message}");
                return ExitCode::from(exit::USAGE);
            }
        };
        let record = match serverstore::find_by_target(&data_root, &target) {
            Ok(Some(record)) => record,
            Ok(None) => {
                println!("  本机没有 {spec_text} 的服务器记录。先运行 --server-trust 确认指纹并保存密码。");
                return ExitCode::from(exit::CONFIG);
            }
            Err(error) => {
                println!("  {}", error.message);
                return ExitCode::from(exit::CONFIG);
            }
        };
        let spec = deploy::Spec::for_record(&record.id);
        if let Err(message) = spec.validate() {
            println!("  {message}");
            return ExitCode::from(exit::USAGE);
        }
        if !apply {
            println!("{}", deploy::plan_text(&spec, &record.address()));
            return ExitCode::SUCCESS;
        }
        let stored = match serverstore::credential(&data_root, &record) {
            Ok(stored) => stored,
            Err(error) => {
                println!("  {}", error.message);
                println!("  请重新运行 --server-trust {spec_text} --fingerprint <指纹> 存一次密码。");
                return ExitCode::from(exit::ENVIRONMENT);
            }
        };
        let password = match stored.into_credential() {
            Ok(password) => password,
            Err(message) => {
                println!("  {message}");
                return ExitCode::from(exit::ENVIRONMENT);
            }
        };
        println!(
            "  正在部署到 {} …（会装包、写配置、重启服务，最长等 5 分钟）",
            record.address()
        );
        return match deploy::install(
            &record.target(),
            &password,
            &record.fingerprint,
            &spec,
            std::time::Duration::from_secs(300),
        ) {
            Ok(installed) => {
                println!("  部署完成：");
                println!("    接口      ：{}（地址 {}）", installed.interface, installed.interface_address);
                println!("    监听端口  ：UDP {}", installed.port);
                println!("    隧道网段  ：{}（服务端 {}）", installed.subnet, spec.address);
                println!("    服务端公钥：{}", installed.server_public_key);
                println!("  说明：服务端已就绪，但还没有任何 peer——下一步要接入客户端才会通。");
                ExitCode::SUCCESS
            }
            Err(ssh::Error::Auth) => {
                println!("  用户名或密码不正确（服务器记录里的凭据可能已失效）。");
                ExitCode::from(exit::ENVIRONMENT)
            }
            Err(error @ (ssh::Error::Connect(_) | ssh::Error::Timeout)) => {
                println!("  {error}");
                ExitCode::from(exit::NETWORK)
            }
            Err(ssh::Error::HostKeyMismatch { .. } | ssh::Error::HostKeyUnknown { .. }) => {
                println!("  服务器身份与记录不一致，已停止。");
                ExitCode::from(exit::CONFLICT)
            }
            Err(error) => {
                println!("  {error}");
                ExitCode::from(exit::INTERNAL)
            }
        };
    }

    // `--server-setup`：**一键**——检查 → 装服务端 → 装兼容连接 → 把本机接进去 → 登记线路。
    //
    // 与旧版的「一键部署」对齐：中间不需要第二条命令。唯一的例外是第一次连一台
    // 没见过的机器——必须先把主机指纹交给人确认（TOFU 是安全边界，不能自动化），
    // 那一次会停在「请核对指纹」并退 6；带上 --fingerprint 重跑就全自动。
    if let Some(spec_text) = arg_values("--server-setup", 1).map(|v| v[0].trim().to_string()) {
        let fingerprint = arg_values("--fingerprint", 1).map(|v| v[0].trim().to_string());
        return run_server_setup(&data_root, &spec_text, fingerprint.as_deref());
    }

    // `--server-transport`：装/更新服务端的兼容连接（TCP + REALITY）。
    // 不带 `-apply` 只打印计划：这一步要下载约 20 MB 组件并重启服务，不该被误触。
    let transport_apply = arg_values("--server-transport-apply", 1)
        .map(|v| v[0].trim().to_string());
    // 身份备份：导出只读；恢复分「看计划」与「真执行」两步，覆盖别人的身份还要 --force。
    let transport_export = arg_values("--server-transport-export", 1)
        .map(|v| v[0].trim().to_string());
    let backup_out = arg_values("--backup", 1).map(|v| v[0].trim().to_string());
    let transport_restore = arg_values("--server-transport-restore", 1)
        .map(|v| v[0].trim().to_string());
    let transport_restore_apply = arg_values("--server-transport-restore-apply", 1)
        .map(|v| v[0].trim().to_string());
    let force_flag = std::env::args().any(|a| a == "--force");
    if let Some(spec_text) =
        arg_values("--server-transport", 1).map(|v| v[0].trim().to_string()).or(transport_apply.clone())
    {
        let (record, password) = match server_credentials(&data_root, &spec_text) {
            Ok(pair) => pair,
            Err(code) => return ExitCode::from(code),
        };
        let spec = deploy::Spec::for_record(&record.id);
        if let Err(message) = spec.validate() {
            println!("  {message}");
            return ExitCode::from(exit::USAGE);
        }
        if transport_apply.is_none() {
            println!("{}", deploy::transport_plan_text(&spec, &record.address()));
            return ExitCode::from(exit::CONFLICT);
        }
        let identity = match deploy::new_identity() {
            Ok(identity) => identity,
            Err(message) => {
                println!("  生成传输身份失败：{message}");
                return ExitCode::from(exit::INTERNAL);
            }
        };
        println!(
            "  正在为 {} 安装兼容连接（TCP {}，组件 {}）…",
            record.address(),
            identity.port,
            deploy::TRANSPORT_VERSION
        );
        return match deploy::install_transport(
            &record.target(),
            &password,
            &record.fingerprint,
            &spec,
            &record.host,
            &identity,
            std::time::Duration::from_secs(420),
        ) {
            Ok(installed) => {
                println!("  兼容连接已就绪：");
                println!("    TCP 端口    ：{}", installed.port);
                println!("    握手域名    ：{}", installed.server_name);
                println!("    REALITY 公钥：{}", installed.public_key);
                println!("    ShortId     ：{}", installed.short_id);
                println!(
                    "    组件 {}，身份 {}",
                    match installed.component.as_str() {
                        "reused" => "复用已装",
                        _ => "本次新装",
                    },
                    match installed.identity.as_str() {
                        "reused" => "复用已有（所有已接入设备继续有效）",
                        _ => "本次新建",
                    }
                );
                println!(
                    "  下一步：运行 --server-join {spec_text} 登记线路（会同时生成兼容连接那条）。"
                );
                ExitCode::SUCCESS
            }
            Err(error) => ExitCode::from(ssh_exit_code(&error)),
        };
    }

    // `--server-transport-export`：把兼容连接身份（含私钥）离线备份一份。
    // **只读**：不下载、不写服务器、不重启服务。
    if let Some(spec_text) = transport_export {
        let (record, password) = match server_credentials(&data_root, &spec_text) {
            Ok(pair) => pair,
            Err(code) => return ExitCode::from(code),
        };
        println!("  正在从 {} 读取兼容连接身份（只读）…", record.address());
        let exported = match deploy::export_transport(
            &record.target(),
            &password,
            &record.fingerprint,
            std::time::Duration::from_secs(60),
        ) {
            Ok(exported) => exported,
            Err(error) => return ExitCode::from(ssh_exit_code(&error)),
        };
        let Some(exported) = exported else {
            println!("  这台服务器上没有兼容连接身份（没装或已被移除）。");
            return ExitCode::from(exit::CONFIG);
        };
        let backup = deploy::TransportBackup {
            target: record.address(),
            host: record.host.clone(),
            created_at: provider::now_rfc3339(),
            identity: exported.identity,
            identity_sha256: exported.identity_sha256,
        };
        let path = match backup_out {
            Some(text) => std::path::PathBuf::from(text),
            None => {
                let dir = data_root.join("exports");
                if let Err(error) = std::fs::create_dir_all(&dir) {
                    println!("  建不了导出目录 {}：{error}", dir.display());
                    return ExitCode::from(exit::CONFIG);
                }
                dir.join(format!(
                    "transport-{}-{}.json",
                    record.host.replace([':', '.'], "-"),
                    model::now_epoch_secs_u64()
                ))
            }
        };
        let text = match serde_json::to_string_pretty(&backup.to_json()) {
            Ok(text) => text,
            Err(error) => {
                println!("  序列化备份失败：{error}");
                return ExitCode::from(exit::INTERNAL);
            }
        };
        if let Err(error) = std::fs::write(&path, text) {
            println!("  写不了备份文件 {}：{error}", path.display());
            return ExitCode::from(exit::CONFIG);
        }
        println!("  已导出：{}", path.display());
        println!("    服务器      ：{}", backup.target);
        println!("    TCP 端口    ：{}", backup.identity.port);
        println!("    握手域名    ：{}", backup.identity.server_name);
        println!("    REALITY 公钥：{}", backup.identity.public_key);
        println!("    身份 SHA256 ：{}", backup.identity_sha256);
        println!("  注意：这个文件里有 REALITY 私钥，等同于这台服务器的兼容连接身份。");
        if !path.starts_with(&data_root) {
            println!("        该路径不在数据根内，访问权限由你选的目录决定，请自行确认。");
        }
        println!("        请离线保存，不要提交到代码仓库、不要发到聊天或工单里。");
        return ExitCode::SUCCESS;
    }

    // `--server-transport-restore[-apply]`：把备份写回服务器。
    // 不带 -apply 只打印计划：覆盖身份会让所有已接入设备失效，不该被误触。
    if let Some(file_text) = transport_restore.clone().or(transport_restore_apply.clone()) {
        let path = std::path::PathBuf::from(&file_text);
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) => {
                println!("  读不了备份文件 {}：{error}", path.display());
                return ExitCode::from(exit::CONFIG);
            }
        };
        let value: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(error) => {
                println!("  备份文件不是合法 JSON：{error}");
                return ExitCode::from(exit::CONFIG);
            }
        };
        let backup = match deploy::TransportBackup::from_json(&value) {
            Ok(backup) => backup,
            Err(message) => {
                println!("  {message}");
                return ExitCode::from(exit::CONFIG);
            }
        };
        if transport_restore_apply.is_none() {
            println!("  计划：把这份身份写回 {}", backup.target);
            println!("    备份时间    ：{}", backup.created_at);
            println!("    TCP 端口    ：{}", backup.identity.port);
            println!("    握手域名    ：{}", backup.identity.server_name);
            println!("    REALITY 公钥：{}", backup.identity.public_key);
            println!("    身份 SHA256 ：{}", backup.identity_sha256);
            println!("  恢复会重写服务器上的 transport.env 并重启兼容连接服务。");
            println!("  如果服务器上已有一份不同的身份，会让所有已接入设备失效，需要 --force。");
            println!("  确认后运行：--server-transport-restore-apply {}", path.display());
            return ExitCode::from(exit::CONFLICT);
        }
        let (record, password) = match server_credentials(&data_root, &backup.target) {
            Ok(pair) => pair,
            Err(code) => return ExitCode::from(code),
        };
        let spec = deploy::Spec::for_record(&record.id);
        println!("  正在把身份写回 {} 并重启兼容连接…", record.address());
        return match deploy::restore_transport(
            &record.target(),
            &password,
            &record.fingerprint,
            &spec,
            &record.host,
            &backup,
            force_flag,
            std::time::Duration::from_secs(420),
        ) {
            Ok(installed) => {
                println!("  兼容连接已恢复：");
                println!("    TCP 端口    ：{}", installed.port);
                println!("    握手域名    ：{}", installed.server_name);
                println!("    REALITY 公钥：{}", installed.public_key);
                println!(
                    "    身份        ：{}",
                    if installed.identity == "reused" {
                        "复用已有"
                    } else {
                        "本次写入"
                    }
                );
                println!("  下一步：在这台服务器对应的线路里点「测一次」，确认真的能连。");
                ExitCode::SUCCESS
            }
            Err(error) => ExitCode::from(ssh_exit_code(&error)),
        };
    }

    // `--server-join`：把**这台电脑**接进刚部署好的服务器——服务端写 peer、
    // 本机写 client.conf 并登记一条线路。做完这一步，这台电脑才有能连的东西。
    if let Some(spec_text) = arg_values("--server-join", 1).map(|v| v[0].trim().to_string()) {
        let target = match ssh::Target::parse(&spec_text) {
            Ok(target) => target,
            Err(message) => {
                println!("  {message}");
                return ExitCode::from(exit::USAGE);
            }
        };
        let record = match serverstore::find_by_target(&data_root, &target) {
            Ok(Some(record)) => record,
            Ok(None) => {
                println!("  本机没有 {spec_text} 的服务器记录。先运行 --server-trust 确认指纹并保存密码。");
                return ExitCode::from(exit::CONFIG);
            }
            Err(error) => {
                println!("  {}", error.message);
                return ExitCode::from(exit::CONFIG);
            }
        };
        let spec = deploy::Spec::for_record(&record.id);
        if let Err(message) = spec.validate() {
            println!("  {message}");
            return ExitCode::from(exit::USAGE);
        }
        let stored = match serverstore::credential(&data_root, &record) {
            Ok(stored) => stored,
            Err(error) => {
                println!("  {}", error.message);
                println!("  请重新运行 --server-trust {spec_text} --fingerprint <指纹> 存一次密码。");
                return ExitCode::from(exit::ENVIRONMENT);
            }
        };
        let password = match stored.into_credential() {
            Ok(password) => password,
            Err(message) => {
                println!("  {message}");
                return ExitCode::from(exit::ENVIRONMENT);
            }
        };

        // 本机密钥只在本机生成：私钥永远不出这台电脑。已有 client.conf 就复用，
        // 否则重跑一次就多一个用不上的 peer。
        let dir = data_root.join("servers").join(&record.id);
        let (client_private, client_public) = servercmd::client_tunnel_key(&dir);
        println!("  正在把这台电脑登记到 {} …", record.address());
        let ack = match deploy::add_peer(
            &record.target(),
            &password,
            &record.fingerprint,
            &spec,
            &client_public,
            std::time::Duration::from_secs(120),
        ) {
            Ok(ack) => ack,
            Err(ssh::Error::Auth) => {
                println!("  用户名或密码不正确（服务器记录里的凭据可能已失效）。");
                return ExitCode::from(exit::ENVIRONMENT);
            }
            Err(error @ (ssh::Error::Connect(_) | ssh::Error::Timeout)) => {
                println!("  {error}");
                return ExitCode::from(exit::NETWORK);
            }
            Err(error) => {
                println!("  {error}");
                return ExitCode::from(exit::INTERNAL);
            }
        };

        // 本机配置与线路：与「用邀请码加入」走同一段代码（`pairing::line`），
        // 两条路写出来的线路文件必须是同一种形状。
        let conf = deploy::client_conf(&spec, &ack.server_public, &record.host, &client_private);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            println!("  创建服务器目录失败：{e}");
            return ExitCode::from(exit::CONFIG);
        }
        if let Err(e) = crate::secretfile::write(&dir.join("client.conf"), &conf) {
            println!("  写 client.conf 失败（设置文件访问权限也会在这一步）：{e}");
            return ExitCode::from(exit::CONFIG);
        }
        let parsed = match pairing::line::parse_client_conf(&conf) {
            Ok(parsed) => parsed,
            Err(error) => {
                println!("  生成的客户端配置没有通过自检：{}", error.message);
                return ExitCode::from(exit::INTERNAL);
            }
        };

        // 服务端装了兼容连接就一起登记：UDP 被拦的网络里，那条是唯一的出路。
        // 读失败不拦着 join——标准连接那条已经能用了，但必须说出来，不能装作没有。
        let compatible = match deploy::read_transport(
            &record.target(),
            &password,
            &record.fingerprint,
            std::time::Duration::from_secs(30),
        ) {
            Ok(Some(installed)) => Some(installed.compatible(&record.host)),
            Ok(None) => {
                println!(
                    "  提示：服务器上没有兼容连接（TCP），只登记标准连接。需要时运行 --server-transport {spec_text} --apply。"
                );
                None
            }
            Err(error) => {
                println!("  提示：读不到服务器上的兼容连接参数（{error}），只登记标准连接。");
                None
            }
        };

        let lines = match servercmd::register_lines(
            &data_root,
            &record.host,
            &parsed,
            compatible.as_ref(),
            None,
            &cli_origin,
        ) {
            Ok(lines) => lines,
            Err(message) => {
                println!("  {message}");
                return ExitCode::from(exit::CONFIG);
            }
        };
        println!("  已完成：");
        println!("    服务端 peer：{}", ack.client_public);
        for line in &lines {
            println!("    本机线路  ：{}", line.describe());
        }
        println!("    客户端配置：{}", dir.join("client.conf").display());
        println!("  现在可以在界面上连接这条线路，或用 --connect 试一次。");
        return ExitCode::SUCCESS;
    }

    // 2. 数据目录：只用自己的根，建不出来就不启动（半个数据目录比没有更糟）。
    let layout = match data::ensure_layout(&isolation::data_root()) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("数据目录初始化失败：{}", e);
            eprintln!("目标：{}", isolation::data_root().display());
            return ExitCode::from(exit::CONFIG);
        }
    };

    // 只读命令不得在启动预处理阶段触发 schema 迁移或兼容线路合并。
    // 此判断必须早于 merge_compatible_lines（它内部通过 config::load 会执行落盘迁移）。
    let readonly_cmd = READONLY_COMMANDS.iter().any(|flag| std::env::args().any(|a| a == *flag));

    // 2.5 老数据结构收口：把「同一台服务器的两条线路」并成一条（幂等，失败不拦启动）。
    //
    // 上一版给每台服务器登记两条线路（`自建 · host` + `自建 · host（兼容连接）`），
    // 而线路卡片上的「标准/兼容」开关对前者是按不动的。现在改成一条线路两套方式，
    // 这里把已经产生的成对线路并掉；并之前先把参数落成附属文件，任何一步失败就停在那里。
    if !readonly_cmd {
        match servercmd::merge_compatible_lines(&layout.root) {
            Ok(0) => {}
            Ok(count) => println!("  已合并 {count} 条重复的兼容连接线路"),
            Err(error) => eprintln!("  合并重复线路失败（不影响启动）：{error}"),
        }
    }

    // 3. 单实例：名字必须带本程序前缀，不能和旧版共用。
    let mutex_name = format!(
        "{}{}",
        isolation::Rewrite::MUTEX_PREFIX,
        // 按数据根区分实例，等价于旧版按 ProviderKey 区分的思路，但空间独立。
        simple_hash(&layout.root.to_string_lossy())
    );
    // 锁的目的是「防两个守护同时接管代理」，纯读命令不需要它：界面开着时在终端查状态是最常见的用法，
    // 拒掉它（exit 4）只会被当成出错。所以只读命令抢不到锁时**不持锁继续走**，其它逻辑一字不动。
    let shared_read = is_shared_read(&argv);
    let guard = match instance::acquire(&mutex_name) {
        Ok(g) => Some(g),
        Err(instance::AcquireError::AlreadyRunning) if shared_read => None,
        Err(instance::AcquireError::AlreadyRunning) => {
            println!("已经有一个 SpiderVPN 在运行了。");
            return ExitCode::from(exit::CONFLICT);
        }
        Err(instance::AcquireError::Failed(code)) => {
            eprintln!("单实例锁创建失败，错误码 {}", code);
            return ExitCode::from(exit::INTERNAL);
        }
    };

    println!("{} {}", isolation::Rewrite::PRODUCT_NAME, env!("CARGO_PKG_VERSION"));
    println!("  安装目录：{}", isolation::install_dir().display());
    println!("  数据根  ：{}", layout.root.display());
    println!("  日志/采样/浏览器数据：{}, {}, {}",
        layout.logs.display(), layout.perf.display(), layout.webview.display());
    println!("  单实例名：{}", mutex_name);
    println!("  计划任务：{}*（默认不创建）", isolation::Rewrite::SCHEDULED_TASK_PREFIX);

    // 启动自愈：上次异常退出（强杀 / 注销 / 断电）会留下「凭据在、引擎已死、代理还指着我们」。
    // 不在这里修，用户下次开机就是断网。除了纯预览命令（--plan/--restore 只回答「会改什么」），
    // 一律先自愈再继续——它不依赖任何回调，是异常退出的主防线。
    // 注销/关机钩子：尽力而为，抓不到强杀（那靠下面的自愈）。
    lifecycle::install(&layout.root);
    let preview_only = std::env::args().any(|a| a == "--plan" || a == "--restore");
    // **不持锁就不自愈**：自愈是状态变更（还原系统代理、消费上次退出的提示），不是读。
    // 不持锁说明另一个实例在管这件事，`--status` 这种只读命令不能替它做决定。
    // 这与"还原是幂等的所以没事"无关：只要将来有人把它改成非幂等（加日志/计数器/上报），
    // 那个假设就碎了，而只读命令有副作用这件事本身就不该成立。
    if guard.is_some() && !preview_only {
        if let Some(msg) = take_startup_issue(&layout.root) {
            println!("  上次退出未完成清理：{msg}");
        }
        if let Some(msg) = connect::heal_stale(
            &proxy::ProxyStore::system(),
            &layout.root.join("proxy-journal.json"),
            &layout.root.join("runtime.json"),
        ) {
            println!("  {msg}");
        }
    }

    // `--import <profile.json> --engine <引擎exe> [--port N] [--line-name 名称]`：
    // 把 旧版的线路文件转成本程序自己的引擎配置，并写好线路。
    // 放在读线路配置之前：配置被改坏时，导入恰恰是唯一的修复手段，不能被坏配置挡在外面。
    if std::env::args().any(|a| a == "--import") {
        let profile = match arg_values("--import", 1) {
            Some(v) => std::path::PathBuf::from(&v[0]),
            None => {
                println!("  --import 缺少线路文件路径");
                return ExitCode::from(exit::CONFIG);
            }
        };
        let engine = match arg_values("--engine", 1) {
            Some(v) if !v[0].trim().is_empty() => v[0].clone(),
            _ => {
                println!("  --import 需要 --engine <引擎程序路径>");
                return ExitCode::from(exit::USAGE);
            }
        };
        let port = match arg_values("--port", 1) {
            Some(v) => match v[0].parse::<u16>() {
                Ok(p) => match engine_config::validate_probe_room(p) {
                    Ok(()) => p,
                    Err(e) => {
                        println!("  {e}");
                        return ExitCode::from(exit::USAGE);
                    }
                },
                Err(_) => {
                    println!("  {}", engine_config::bad_port_msg(&v[0]));
                    return ExitCode::from(exit::USAGE);
                }
            },
            None => DEFAULT_PORT,
        };
        let line_name = arg_values("--line-name", 1).map(|v| v[0].clone());
        // `--tun` 只影响本次生成与写入的模式；不带它就是原来的代理模式。
        let mode = if std::env::args().any(|a| a == "--tun") { config::Mode::Tun } else { config::Mode::Proxy };
        match import_profile(
            &layout.root,
            &profile,
            &engine,
            port,
            line_name.as_deref(),
            mode,
            &cli_origin,
        ) {
            Ok((cfg, updated)) => {
                if let Some(line) = cfg.current_line() {
                    println!("  已生成引擎配置：{}", line.engine_config_path(&layout.root).display());
                    println!(
                        "  端口：{}  模式：{}  线路：{}（{}，共 {} 条）",
                        port,
                        cfg.mode.label(),
                        line.name,
                        if updated { "已更新" } else { "新增" },
                        cfg.lines.len()
                    );
                }
                if let Some(e) = &cfg.engine {
                    println!("  引擎：{}", e.binary);
                }
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                // 「探测端口被占」需要用户换端口（决策），不是「配置坏了」。
                // 文案与退出码都从 import_failure 取：界面显示同一句，不得各自加前缀。
                let (code, text) = import_failure(&e);
                eprintln!("{text}");
                return ExitCode::from(code);
            }
        }
    }

    // 只探测一次，后面（提示、计划、管道上下文）共用这个结果。
    let legacy_running = isolation::legacy_running();
    if legacy_running {
        // 两个都会接管系统代理的程序不能同时生效：提示，但不夺权。
        println!("  检测到旧版客户端正在运行：本程序不会接管系统代理。");
    }

    // 线路配置。没有配置就不算变更——比用一个占位端口好，
    // 占位端口会让系统代理指向一个不存在的服务，用户以为网断了。
    // 配置读不出来时不立刻退出：`--disconnect` 恰恰是配置坏了之后唯一的出路。
    // 把它一起锁死，用户就停在「代理指向本程序、引擎还在跑」且无从收尾的状态（T13）。
    let disconnect_only = std::env::args().any(|a| a == "--disconnect");
    // 只读命令绝不写盘：老配置在内存里迁成多线路格式照常展示，落盘留给第一个写命令。
    // （`--status` 跑一趟就把用户配置改了，既违反「默认根只读」，也让验收的「跑前跑后一致」失效。）
    // 读配置时顺带完成 schema 1 → 2 的迁移（只做一次，且只在写命令上）。提示也只在真落盘时打。
    let cfg_path = layout.root.join(config::DEFAULT_PATH);
    let loaded = if readonly_cmd {
        // 只读命令：内存里迁好就用，文件一个字节都不动。
        config::load_readonly(&cfg_path).map(|o| o.map(|cfg| config::Loaded { cfg, upgraded: false }))
    } else {
        config::load_with_migration(&cfg_path, true)
    };
    let cfg = match loaded {
        Ok(Some(loaded)) => {
            if loaded.upgraded {
                println!("  已把配置升级为多线路格式（schema 2）");
            }
            Some(loaded.cfg)
        }
        Ok(None) => None,
        Err(e) => {
            if !disconnect_only {
                // 双击启动（无参数）= GUI：没有控制台，必须弹框，否则用户只看到"点了没反应"。
                let gui = std::env::args().count() == 1;
                let code = report_fatal_config_error(&cfg_path, &e, gui, &message_box);
                return ExitCode::from(code as u8);
            }
            println!("  配置不可用（{}）：继续按还原凭据断开。", e);
            None
        }
    };
    let endpoint: Option<String> = cfg
        .as_ref()
        .and_then(|c| c.current_line())
        .map(|l| l.proxy_endpoint.clone());
    let wants_status = std::env::args().any(|a| a == "--status");
    if let Some(c) = &cfg {
        // 只显示名字：id 是把名字小写化的内部标识，并排显示会被当成重复或错字。
        match c.current_line() {
            Some(l) => println!("  线路：{}  端点：{}", l.name, l.proxy_endpoint),
            None => println!("  线路：尚未配置"),
        }
    } else {
        println!("  线路：尚未配置（{}）", layout.root.join(config::DEFAULT_PATH).display());
    }
    // 缺线路 → exit 13（与 `--connect` 一致）；配置文件缺失/损坏不算「缺线路」，那走它自己的码。
    // `--set-line <id> <name> <host:port>`：新增/更新**一条**线路（不再覆盖整个配置）。
    if let Some(vals) = arg_values("--set-line", 3) {
        let mut cfg = match cfg {
            Some(c) => c,
            None => config::AppConfig {
                schema: config::SCHEMA,
                mode: config::Mode::Proxy,
                auto_start: false,
                auto_connect: false,
                close_to_tray: false,
                quality_warning: true,
                auto_trust_first_connection: true,
                selected: String::new(),
                lines: Vec::new(),
                split: config::SplitConfig::default(),
                agents: config::AgentsConfig::default(),
                exits: config::Exits::default(),
                engine: None,
            },
        };
        let id = vals[0].trim().to_string();
        let name = vals[1].trim().to_string();
        let endpoint = vals[2].trim().to_string();
        // 连接方式：更新已有线路 → 保留原选择；新线路 → 若引擎配置文件本身已是 Tcp 形状
        // （少见：文件先在、配置后写），按文件形状记成兼容连接，与 --import 同一条规则。
        let previous = cfg.lines.iter().find(|l| l.id == id).and_then(|l| l.transport);
        let transport = previous.or_else(|| {
            let engine_path =
                layout.root.join("lines").join(format!("{}.json", config::safe_file_stem(&id)));
            std::fs::read_to_string(engine_path)
                .ok()
                .and_then(|t| engine_config::tcp_shaped(&t).then_some(config::Transport::Tcp))
        });
        // 新导入的线路还没有任何验证依据：「自动」先按标准连接走，等真的连通过再记。
        let line = config::LineConfig {
            id,
            name,
            proxy_endpoint: endpoint,
            transport,
            verified_transport: None,
        };
        if let Err(e) = config::validate_endpoint(&line.proxy_endpoint) {
            println!("  {}", e);
            return ExitCode::from(exit::CONFIG);
        }
        // 与 --import 同一条上限：65532（给探测入站留出 +3），文案是定稿。
        // 同一处也试绑一次探测端口：这里写进去的端口就是以后连接要用的端口。
        if let Some(p) = selfcheck::port_from_endpoint(&line.proxy_endpoint) {
            // 端口不合法是用法/取值错误；端口被占是冲突（要换端口），两者分开报。
            if let Err(e) = engine_config::validate_probe_room(p) {
                println!("  {e}");
                return ExitCode::from(exit::USAGE);
            }
            if let Err(e) = engine_config::validate_probe_port_free(p) {
                println!("  {IMPORT_CONFLICT_PREFIX}{e}");
                return ExitCode::from(exit::CONFLICT);
            }
        }
        if line.id.is_empty() || line.name.is_empty() {
            println!("  id 与名称都不能为空");
            return ExitCode::from(exit::CONFIG);
        }
        let updated = upsert_line(&mut cfg, line.clone());
        cfg.selected = line.id.clone();
        match config::save_with_origin(&layout.root.join(config::DEFAULT_PATH), &cfg, &cli_origin) {
            Ok(()) => {
                println!(
                    "  已{}线路：{}  端点 {}（共 {} 条）",
                    if updated { "更新" } else { "新增" },
                    line.name,
                    line.proxy_endpoint,
                    cfg.lines.len()
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                println!("  {}", e);
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    // `--lines`：列出全部线路，标出当前选中。
    if std::env::args().any(|a| a == "--lines") {
        match &cfg {
            Some(c) if !c.lines.is_empty() => {
                for line in &c.lines {
                    println!(
                        "  {} {}  {}  {}{}",
                        if c.is_selected(line) { "*" } else { " " },
                        line.name,
                        line.proxy_endpoint,
                        line.effective_transport().label(),
                        // 三档必须分开说（旧版的 UserChoice / 自动 / PolicyDefault）：
                        // 「已选」= 用户固定；「自动」= 没固定、但这条线路验证过某种方式；
                        // 「默认」= 什么依据都没有，跑的是策略默认的标准连接。
                        if line.transport.is_some() {
                            "（已选）"
                        } else if line.verified_transport.is_some() {
                            "（自动）"
                        } else {
                            "（默认）"
                        }
                    );
                }
            }
            _ => println!("  尚未配置线路"),
        }
        return ExitCode::SUCCESS;
    }

    // `--set-transport udp|tcp|auto`：切当前线路的连接方式——**只存下次要用的那份，不动当前连接**
    // （旧版的原文：「已保存下次默认方式，当前连接保持」）。所以这里不检查「连接中」：
    // 换默认方式与正在跑的引擎无关，而线路文件本身也不改写（兼容连接是连接时派的）。
    // `auto` = 取消固定，回到「采用这条线路已验证的方式」。
    if let Some(v) = arg_values("--set-transport", 1) {
        let want = v[0].trim().to_string();
        // `auto` = 取消固定，采用这条线路**已验证**的方式（旧版的「自动」）。
        // 没有具体方式可校验，所以下面跳过 `check_transport`。
        let auto = want.eq_ignore_ascii_case("auto");
        let transport = config::Transport::from_name(&want);
        if !auto && transport.is_none() {
            println!(
                "  --set-transport 只能是 auto、{} 或 {}（收到：{}）",
                config::Transport::Udp.id(),
                config::Transport::Tcp.id(),
                want
            );
            // 认不出的取值 = 用法错误；缺配置才是 CONFIG（下面那条不动）。
            return ExitCode::from(exit::USAGE);
        };
        let mut cfg = match cfg {
            Some(c) => c,
            None => {
                println!("  {NO_CONFIG_FOR_SETTINGS}");
                return ExitCode::from(exit::CONFIG);
            }
        };
        let Some(line) = cfg.current_line().cloned() else {
            println!("  未配置线路，无法设置连接方式。请先导入线路或用 --set-line 写入一条。");
            return ExitCode::from(exit::CONFIG);
        };
        // 切换前先按连接时的同一套规则派生一次：缺参数就在这儿拒绝，而不是等用户点连接才失败。
        // 同时也是「不许留半截配置」的保证——派生不过去，config.json 一个字节都不写。
        // `auto` 没有具体方式可派生，跳过这一关（它只是取消固定，不新增任何参数依赖）。
        if let Some(t) = transport {
            if let Err(e) =
                engine_config::check_transport(&line.engine_config_path(&layout.root), t)
            {
                println!("  {e}");
                return ExitCode::from(exit::CONFIG);
            }
        }
        if let Some(l) = cfg.lines.iter_mut().find(|l| l.id == line.id) {
            // `None` 就是「自动」：不动 `verified_transport`，那是既有依据。
            l.transport = transport;
        }
        match config::save_with_origin(&layout.root.join(config::DEFAULT_PATH), &cfg, &cli_origin) {
            Ok(()) => {
                println!(
                    "  {}",
                    match transport {
                        Some(t) => format!("已保存下次默认连接方式：{}（当前连接保持）", t.label()),
                        None => "已改为自动选择（采用这条线路已验证的方式），当前连接保持".to_string(),
                    }
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                println!("  {}", e);
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    // `--exits`：列两个出口的可选成员与当前值（只读，读线路的引擎配置）。
    if std::env::args().any(|a| a == "--exits") {
        match cfg.as_ref().and_then(|c| c.current_engine_path(&layout.root)) {
            Some(p) => match engine_config::read_exits_from_file(&p) {
                Ok(Some(info)) => {
                    println!("  日常出口：{}（可选：{}）", info.daily, info.daily_members.join(", "));
                    println!("  交易出口：{}（可选：{}）", info.trade, info.trade_members.join(", "));
                }
                Ok(None) => println!("  线路文件里没有日常/交易两个出口选择器"),
                Err(e) => println!("  {e}"),
            },
            None => println!("  {}（还没有线路的引擎配置，先导入线路）", NO_CONFIG_FOR_SETTINGS),
        }
        return ExitCode::SUCCESS;
    }

    // `--diagnose`：节点端口可达性诊断（只读：不需要连接、不需要引擎、不写任何文件）。
    //
    // 只探 TCP：WireGuard 的 peer 是 UDP 端点，拿 TCP 去探它是错的——把它列出来说明"不适用"，
    // 绝不因此报"服务器离线"（旧版的规矩，也是本命令存在的意义）。
    if std::env::args().any(|a| a == "--diagnose") {
        // 诊断是只读的，不写任何设置：所以不复用"无法修改设置"那句（它在这里是假话），
        // 但开头仍用同一句「未配置线路」，用户看到的还是同一类问题。
        let Some(line) = cfg.as_ref().and_then(|c| c.current_line()) else {
            println!("  未配置线路，无法诊断。请先导入线路或用 --set-line。");
            return ExitCode::from(exit::CONFIG);
        };
        let path = line.engine_config_path(&layout.root);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                println!("  读不到线路的引擎配置（{}）：{e}", path.display());
                return ExitCode::from(exit::CONFIG);
            }
        };
        let obj = match serde_json::from_str::<serde_json::Value>(
            text.strip_prefix('\u{feff}').unwrap_or(&text),
        ) {
            Ok(serde_json::Value::Object(o)) => o,
            Ok(_) => {
                println!("  线路的引擎配置顶层不是 JSON 对象（{}）", path.display());
                return ExitCode::from(exit::CONFIG);
            }
            Err(e) => {
                println!("  线路的引擎配置不是合法 JSON（{}）：{e}", path.display());
                return ExitCode::from(exit::CONFIG);
            }
        };
        let plan = diagnose::plan(&obj, line.effective_transport());
        let probes = diagnose::probe_all(&plan);
        println!("  诊断：{}（{}）", line.name, line.effective_transport().label());
        for out in diagnose::render(&plan, &probes) {
            println!("    {out}");
        }
        // 交易保护小节：与界面诊断页同一份实现（`diagnose::guard_lines`）。
        let guard_status = guard::status(cfg.as_ref(), &layout.root, legacy_running);
        for out in diagnose::guard_lines(&guard_status) {
            println!("    {out}");
        }
        // 全不可达（或压根没有可探的目标）= 诊断失败；纯 UDP 未验证**不算**失败。
        if plan.tcp.is_empty() || !diagnose::any_reachable(&probes) {
            // stderr 必须说清「探的是谁」，否则脚本只能拿到一个退出码。
            // 诊断失败是网络类（可重试），不是配置类。
            if plan.tcp.is_empty() {
                eprintln!(
                    "  诊断未通过：没有可探测的 TCP 目标（{}）。",
                    plan.no_target
                        .as_deref()
                        .unwrap_or("线路配置里既没有中转地址也没有 peer 地址")
                );
            } else {
                let targets: Vec<String> = plan
                    .tcp
                    .iter()
                    .map(|t| format!("{}:{}", t.host, t.port))
                    .collect();
                eprintln!("  诊断未通过：{} 均不可达。", targets.join("、"));
            }
            return ExitCode::from(exit::NETWORK);
        }
        return ExitCode::SUCCESS;
    }

    // `--exit-set trade|daily <成员>`：写进配置并立刻应用到线路的引擎配置。
    if let Some(vals) = arg_values("--exit-set", 2) {
        let which = vals[0].trim().to_ascii_lowercase();
        let member = vals[1].trim().to_string();
        if which != "trade" && which != "daily" {
            println!("  --exit-set 只能设 trade 或 daily（收到：{which}）");
            return ExitCode::from(exit::CONFIG);
        }
        let Some(mut nc) = cfg.clone() else {
            println!("  {NO_CONFIG_FOR_SETTINGS}");
            return ExitCode::from(exit::CONFIG);
        };
        // 端口占用/连接中：与其它写命令一致，连接中不许改。
        if ipc::connection_busy(&layout.root) {
            println!("  请先断开再改出口：连接中改动配置会让引擎实际行为与配置不一致");
            return ExitCode::from(exit::CONFIG);
        }
        if which == "trade" {
            nc.exits.trade = Some(member.clone());
        } else {
            nc.exits.daily = Some(member.clone());
        }
        // 先改线路引擎配置、再写 config：成员不合法在第一步就被拦，此时 config 还没写——
        // 非法成员必须是**零副作用**（config 与 lines\<id>.json 一个字节都不动）。
        let Some(line_path) = nc.current_engine_path(&layout.root) else {
            println!("  {NO_CONFIG_FOR_SETTINGS}");
            return ExitCode::from(exit::CONFIG);
        };
        if let Err(e) = engine_config::apply_exits_to_file(&line_path, &nc.exits) {
            println!("  {e}");
            return ExitCode::from(exit::CONFIG);
        }
        if let Err(e) = config::save_with_origin(&layout.root.join(config::DEFAULT_PATH), &nc, &cli_origin) {
            println!("  {e}");
            return ExitCode::from(exit::CONFIG);
        }
        println!(
            "  已设置{}：{}",
            if which == "trade" { "交易出口" } else { "日常出口" },
            member
        );
        if let Ok(Some(info)) = engine_config::read_exits_from_file(&line_path) {
            println!("  日常出口：{}（可选：{}）", info.daily, info.daily_members.join(", "));
            println!("  交易出口：{}（可选：{}）", info.trade, info.trade_members.join(", "));
        }
        return ExitCode::SUCCESS;
    }

    // `--history`：操作记录（只读）。与界面「记录」页读的是同一个文件、同一套文案。
    if std::env::args().any(|a| a == "--history") {
        let ev = events::read(&layout.root, events::READ_LIMIT);
        if ev.is_empty() {
            println!("  还没有操作记录（连接、改线路、改接管方式等动作会记在这里）");
        } else {
            println!("  操作记录：最近 {} 条，最新在前（时间为 UTC）", ev.len());
            for e in &ev {
                println!(
                    "  {}  {}  {}  {}  [来源：{} | 发起：{} | 对象：{}]",
                    e.ts,
                    if e.ok { "成功" } else { "失败" },
                    e.action,
                    e.detail,
                    e.src.as_deref().unwrap_or("未知来源"),
                    e.actor.as_deref().unwrap_or("未知发起者"),
                    e.obj.as_deref().unwrap_or("未知对象")
                );
            }
        }
        return ExitCode::SUCCESS;
    }

    // `--providers`：已登记的服务商（只读）。服务商是独立注册表，不是线路。
    if std::env::args().any(|a| a == "--providers") {
        let reg = provider::load(&layout.root);
        if reg.providers.is_empty() {
            println!("  尚未登记服务商（--provider-discover 发现外部客户端，或 --provider-add 手动登记）");
        } else {
            for p in &reg.providers {
                println!(
                    "  [槽位 {}] {}（{}）SOCKS=127.0.0.1:{} 交易端口={} 域名 {} 个  出站 {} / {}",
                    p.slot, p.name, p.kind, p.daily_port, p.trade_port(),
                    p.bootstrap_domains.len(), p.daily_tag(), p.trade_tag()
                );
            }
        }
        return ExitCode::SUCCESS;
    }

    // `--provider-discover`：只读发现，不登记。两个客户端都探一遍。
    if std::env::args().any(|a| a == "--provider-discover") {
        let mut found = false;
        match provider::discover_clash_verge() {
            Ok(d) => {
                found = true;
                println!("  发现 Clash Verge：{}", d.directory);
                println!("    入口：{}", d.entry_note);
                println!("    上游域名（{} 个）：{}", d.bootstrap_domains.len(), d.bootstrap_domains.join(", "));
                println!("    登记：--provider-add clashverge <名称> \"{}\" {}", d.directory, d.daily_port);
            }
            Err(e) => println!("  Clash Verge：{e}"),
        }
        match provider::discover_batvpn() {
            Ok(d) => {
                found = true;
                println!("  发现 BatVPN：{}", d.directory);
                println!("    入口：{}", d.entry_note);
                println!("    上游域名（{} 个）：{}", d.bootstrap_domains.len(), d.bootstrap_domains.join(", "));
                println!("    登记：--provider-add batvpn <名称> \"{}\" {}", d.directory, d.daily_port);
            }
            Err(e) => println!("  BatVPN：{e}"),
        }
        if !found {
            println!("  两个客户端都没发现可用的配置");
        }
        return ExitCode::SUCCESS;
    }

    // `--provider-add <kind> <名称> <目录> <端口> [逗号分隔的上游域名]`：登记并投影到当前线路。
    if let Some(vals) = arg_values("--provider-add", 4) {
        let kind = provider::normalize_kind(&vals[0]);
        let name = vals[1].trim().to_string();
        let directory = vals[2].trim().to_string();
        let daily_port: u16 = match vals[3].trim().parse() {
            Ok(p) if p > 0 => p,
            _ => {
                println!("  端口必须是 1–65532 的数字（收到：{}）", vals[3]);
                return ExitCode::from(exit::CONFIG);
            }
        };
        // 可选的第 5 个参数：逗号分隔的上游域名（完整域名，不能是订阅链接）。
        let args_all: Vec<String> = std::env::args().collect();
        let idx = args_all.iter().position(|a| a == "--provider-add").unwrap_or(0);
        let domains: Vec<String> = args_all
            .get(idx + 5)
            .filter(|s| !s.starts_with("--"))
            .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
            .unwrap_or_default();
        if domains.iter().any(|d| d.contains("://")) {
            println!("  不能填写订阅链接：这里只登记客户端已落地的本机端口与上游域名");
            return ExitCode::from(exit::CONFIG);
        }
        // 登记会改写当前线路的引擎配置（注入 socks 出站与域名直连规则），连接中拒绝。
        if ipc::connection_busy(&layout.root) {
            println!("  请先断开再登记服务商：登记会更新当前线路的引擎配置");
            return ExitCode::from(exit::CONFIG);
        }
        let Some(line_path) = cfg.as_ref().and_then(|c| c.current_engine_path(&layout.root)) else {
            println!("  {NO_CONFIG_FOR_SETTINGS}（先导入线路再登记服务商）");
            return ExitCode::from(exit::CONFIG);
        };
        // 校验/查重/投影/落盘只在 `provider::register` 一处（界面走同一个函数）：
        // 两条入口各写一遍，迟早点出两种校验顺序和两套错误文案。
        let input = provider::RegisterInput { kind, name, directory, daily_port, bootstrap_domains: domains };
        match provider::register_with_origin(&layout.root, &line_path, input, &cli_origin) {
            Ok(p) => {
                println!(
                    "  已登记服务商：{}（槽位 {}），出站 {} / {}",
                    p.name,
                    p.slot,
                    p.daily_tag(),
                    p.trade_tag()
                );
                println!("  设为日常出口：--exit-set daily {}", p.daily_tag());
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                println!("  {e}");
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    // `--provider-remove <槽位>`：删除并同步移除线路里的对应出站。
    if let Some(vals) = arg_values("--provider-remove", 1) {
        let slot: u8 = match vals[0].trim().parse() {
            Ok(s) => s,
            _ => {
                println!("  槽位是数字 1–4（收到：{}）", vals[0]);
                return ExitCode::from(exit::CONFIG);
            }
        };
        if ipc::connection_busy(&layout.root) {
            println!("  请先断开再删除服务商");
            return ExitCode::from(exit::CONFIG);
        }
        let line_path = cfg.as_ref().and_then(|c| c.current_engine_path(&layout.root));
        match provider::unregister_with_origin(
            &layout.root,
            line_path.as_deref(),
            slot,
            &cli_origin,
        ) {
            Ok(()) => {
                println!("  已删除槽位 {slot} 的服务商");
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                println!("  {e}");
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    // `--split-*`：分流规则的增删查（写命令，会触发迁移与落盘）。连接中禁止改。
    if std::env::args().any(|a| a == "--split-list") {
        match &cfg {
            Some(c) => {
                print_split(&c.split);
                print_split_scope_hint(c, &layout.root);
            }
            None => println!("  {}", NO_CONFIG_FOR_SETTINGS),
        }
        return ExitCode::SUCCESS;
    }

    let split_ops: [(&str, bool, bool); 4] = [
        // (参数名, 是进程还是域名, 是加还是删)
        ("--split-add-process", true, true),
        ("--split-add-domain", false, true),
        ("--split-remove-process", true, false),
        ("--split-remove-domain", false, false),
    ];
    for (flag, is_process, is_add) in split_ops {
        let Some(v) = arg_values(flag, 1) else { continue };
        let cfg_now = match cfg.clone() {
            Some(c) => c,
            None => {
                println!("  {NO_CONFIG_FOR_SETTINGS}");
                return ExitCode::from(exit::CONFIG);
            }
        };
        if ipc::connection_busy(&layout.root) {
            // 与线路操作同一条规则：半接管状态下改分流，会让引擎里的规则与还原凭据对不上。
            // 这是「现在不行、断开再来」，属状态未就绪，不是配置坏了。
            println!("  请先断开再改分流规则：连接中改动配置会让引擎实际行为与配置不一致");
            return ExitCode::from(exit::ENVIRONMENT);
        }
        // 输入校验（与界面共用同一套）：挡"永远匹配不上却不报错"的写法。
        // 拒绝时 exit 2（用法错误），且配置一个字节都不改（校验在写盘之前）。
        let check = if is_process {
            config::SplitConfig::validate_process(&v[0])
        } else if is_add {
            config::SplitConfig::validate_domain(&v[0])
        } else if v[0].contains('/') || v[0].contains("://") {
            Err("域名不要带协议或路径".to_string())
        } else {
            Ok(())
        };
        if let Err(e) = check {
            println!("  {}", e);
            return ExitCode::from(exit::USAGE);
        }
        let mut nc = cfg_now;
        // `--to direct|trade|daily`（可省略，缺省 direct）
        let target = match split_target_arg() {
            Ok(t) => t,
            Err(e) => {
                println!("  {e}");
                return ExitCode::from(exit::USAGE);
            }
        };
        let changed = if is_process {
            if is_add {
                nc.split.add_process(&v[0], target)
            } else {
                nc.split.remove_process(&v[0])
            }
        } else if is_add {
            nc.split.add_domain(&v[0], target)
        } else {
            nc.split.remove_domain(&v[0])
        };
        let label = if is_process { "进程" } else { "域名" };
        if !changed {
            // 加重复项 / 删不存在的项：不是错误，但要说清"什么都没变"。
            println!("  {}「{}」{}（配置未改动）", label, v[0].trim(), if is_add { "已存在" } else { "本来就没有" });
            print_split(&nc.split);
            return ExitCode::SUCCESS;
        }
        match config::save_with_origin(&layout.root.join(config::DEFAULT_PATH), &nc, &cli_origin) {
            Ok(()) => {
                println!(
                    "  已{}分流{}：{}{}",
                    if is_add { "添加" } else { "删除" },
                    label,
                    v[0].trim(),
                    if is_add { format!("  → {}", target.label()) } else { String::new() }
                );
                print_split(&nc.split);
                print_split_scope_hint(&nc, &layout.root);
                // 立刻同步到**选中线路**的引擎配置：否则"先导入、后加分流"这条最自然的顺序
                // 规则永远进不了引擎（这正是之前那个缺陷）。失败只提示，连接前还会再补一次。
                if let Some(line_path) = nc.current_engine_path(&layout.root) {
                    // **两份名单一起传**：只传分流会把 AI 工具名单的规则删掉。
                    match engine_config::apply_rules_to_file(&line_path, &nc.split, &nc.agents) {
                        Ok(true) => println!("  已更新线路引擎配置：{}", line_path.display()),
                        Ok(false) => {}
                        Err(e) => println!("  （线路引擎配置暂未更新：{e}；连接时会重新应用）"),
                    }
                }
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                println!("  {}", e);
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    // `--use <id 或名字>`：切换选中。按名字匹配，大小写不敏感。
    if let Some(v) = arg_values("--use", 1) {
        let mut cfg = match cfg {
            Some(c) => c,
            None => {
                println!("  {NO_CONFIG_FOR_SETTINGS}");
                return ExitCode::from(exit::CONFIG);
            }
        };
        // 与 --exit-set / --split-* 同一条规则：连接中改选中线路，还原凭据里的端点
        // 与实际引擎会对不上——断开时就会按错的端点“还原”。
        if ipc::connection_busy(&layout.root) {
            println!("  请先断开再切换线路：连接中改动配置会让还原凭据与实际引擎对不上");
            return ExitCode::from(exit::CONFIG);
        }
        // 先把要用的字段取出来，再改 selected：不能一边借着 lines，一边改 cfg。
        let found = cfg
            .find_line(&v[0])
            .map(|l| (l.id.clone(), l.name.clone(), l.proxy_endpoint.clone()));
        match found {
            Some((id, name, ep)) => {
                cfg.selected = id;
                match config::save_with_origin(&layout.root.join(config::DEFAULT_PATH), &cfg, &cli_origin) {
                    Ok(()) => {
                        println!("  已切换到线路：{}  {}", name, ep);
                        return ExitCode::SUCCESS;
                    }
                    Err(e) => {
                        println!("  {}", e);
                        return ExitCode::from(exit::CONFIG);
                    }
                }
            }
            None => {
                println!("  找不到线路：{}", v[0].trim());
                print_line_candidates(&cfg);
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    // `--remove-line <id 或名字>`：删掉这条线路和它自己的引擎配置。
    if let Some(v) = arg_values("--remove-line", 1) {
        let mut cfg = match cfg {
            Some(c) => c,
            None => {
                println!("  {NO_CONFIG_FOR_SETTINGS}");
                return ExitCode::from(exit::CONFIG);
            }
        };
        // 同上：删线路会同时删引擎配置，连接中做这件事必然让还原凭据悬空。
        if ipc::connection_busy(&layout.root) {
            println!("  请先断开再删除线路：连接中改动配置会让还原凭据与实际引擎对不上");
            return ExitCode::from(exit::CONFIG);
        }
        let Some(target) = cfg.find_line(&v[0]).cloned() else {
            println!("  找不到线路：{}", v[0].trim());
            print_line_candidates(&cfg);
            return ExitCode::from(exit::CONFIG);
        };
        cfg.lines.retain(|l| l.id != target.id);
        // 删的是当前选中（或选中已失效）→ 回退到第一条；一条不剩就清空 selected。
        if cfg.selected == target.id || cfg.find_line(&cfg.selected).is_none() {
            cfg.selected = cfg.lines.first().map(|l| l.id.clone()).unwrap_or_default();
        }
        let engine_path = target.engine_config_path(&layout.root);
        match config::save_with_origin(&layout.root.join(config::DEFAULT_PATH), &cfg, &cli_origin) {
            Ok(()) => {
                // 引擎配置跟着删；删不掉只提示，不回滚配置（线路已经不在列表里了）。
                if engine_path.exists() {
                    if let Err(e) = std::fs::remove_file(&engine_path) {
                        println!("  （线路已删，但引擎配置删不掉：{e}）");
                    }
                }
                println!(
                    "  已删除线路：{}（剩 {} 条）",
                    target.name,
                    cfg.lines.len()
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                println!("  {}", e);
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    // `--set-autostart on|off` / `--set-autoconnect on|off`    // `--set-autostart on|off` / `--set-autoconnect on|off`：两个开关落到 config.json，
    // 自启那项还要同步 HKCU Run 键（纯 HKCU，不需要管理员）。
    if let Some(v) = arg_values("--set-autostart", 1) {
        let on = match parse_on_off(&v[0]) {
            Some(b) => b,
            None => {
                println!("  用法：--set-autostart on|off");
                return ExitCode::from(exit::CONFIG);
            }
        };
        let mut new_cfg = match &cfg {
            Some(c) => c.clone(),
            None => {
                println!("  {NO_CONFIG_FOR_SETTINGS}");
                return ExitCode::from(exit::CONFIG);
            }
        };
        new_cfg.auto_start = on;
        // 自启项指向「安装根下的启动入口」，所以必须知道 exe 在哪。
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                println!("  取不到本程序路径，无法设置开机自启：{e}");
                return ExitCode::from(exit::CONFIG);
            }
        };
        // 两件事都做，但**不假装原子**：一个成了另一个没成，就把事实说出来。
        let key_r = autostart::sync(on, &exe);
        let save_r = config::save_with_origin(&layout.root.join(config::DEFAULT_PATH), &new_cfg, &cli_origin);
        match (key_r, save_r) {
            (Ok(()), Ok(())) => {
                // 回读校验：注册表是外部状态，写完要确认真的落了（改了没生效比报错更难查）。
                let actual = autostart::current_in(&autostart::key_path());
                if on != actual.is_some() {
                    println!(
                        "  自启项回读校验未通过（{}）：期望{}，实际 {}",
                        autostart::key_path(),
                        if on { "已写入" } else { "已删除" },
                        actual.clone().unwrap_or_else(|| "无".to_string())
                    );
                    return ExitCode::from(exit::CONFIG);
                }
                println!(
                    "  已{}开机自启（HKCU Run: {} = {}）",
                    if on { "开启" } else { "关闭" },
                    autostart::key_path(),
                    actual.unwrap_or_else(|| "无".to_string())
                );
                return ExitCode::SUCCESS;
            }
            (Err(e), Ok(())) => {
                println!("  配置已保存，但同步自启项失败：{e}");
                return ExitCode::from(exit::CONFIG);
            }
            (Ok(()), Err(e)) => {
                println!("  自启项已改，但配置保存失败：{e}");
                return ExitCode::from(exit::CONFIG);
            }
            (Err(e1), Err(e2)) => {
                println!("  自启项与配置都没改成：{e1}；{e2}");
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    if let Some(v) = arg_values("--set-autoconnect", 1) {
        let on = match parse_on_off(&v[0]) {
            Some(b) => b,
            None => {
                println!("  用法：--set-autoconnect on|off");
                return ExitCode::from(exit::CONFIG);
            }
        };
        let mut new_cfg = match &cfg {
            Some(c) => c.clone(),
            None => {
                println!("  {NO_CONFIG_FOR_SETTINGS}");
                return ExitCode::from(exit::CONFIG);
            }
        };
        new_cfg.auto_connect = on;
        // 这个开关不碰注册表：它只在下次启动时决定要不要自动点一次「连接」。
        match config::save_with_origin(&layout.root.join(config::DEFAULT_PATH), &new_cfg, &cli_origin) {
            Ok(()) => {
                println!("  已{}启动后自动连接", if on { "开启" } else { "关闭" });
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                println!("  {}", e);
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    if let Some(v) = arg_values("--set-closetotray", 1) {
        let on = match parse_on_off(&v[0]) {
            Some(b) => b,
            None => {
                println!("  用法：--set-closetotray on|off");
                return ExitCode::from(exit::CONFIG);
            }
        };
        let mut new_cfg = match &cfg {
            Some(c) => c.clone(),
            None => {
                println!("  {NO_CONFIG_FOR_SETTINGS}");
                return ExitCode::from(exit::CONFIG);
            }
        };
        new_cfg.close_to_tray = on;
        // 只落配置：托盘能不能起来要等窗口起来才知道（起不来会自动退回断开并退出）。
        match config::save_with_origin(&layout.root.join(config::DEFAULT_PATH), &new_cfg, &cli_origin) {
            Ok(()) => {
                println!(
                    "  已{}关窗缩到托盘（{}）",
                    if on { "开启" } else { "关闭" },
                    if on { "关窗后连接保持，退出请用托盘菜单" } else { "关窗即断开并退出" }
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                println!("  {}", e);
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    // `--status`：一屏看清当前状态（只读）。
    if wants_status {
        let snap = proxy::ProxySnapshot::read();
        let jp = layout.root.join("proxy-journal.json");
        let has_journal = jp.exists();
        let ours = endpoint.as_deref().map(|ep| snap.server.as_deref() == Some(ep)).unwrap_or(false);
        // 状态与动作必须来自同一个投影：与 IPC `status`、界面首屏同源。
        // 否则同一台机器会出现「命令行说已连接、界面说需要处理」两套说法，
        // 而在这个场景里（守护已退出、引擎还在跑、代理仍指向本程序）说「已连接」会让人
        // 放着不处理，说「未连接」会让他以为网络干净去重新连接——两种都会误导交易。
        // control_available 取这一次 ping 的实测值：本次 CLI 没起服务端，守护不在时它就该是 false。
        let pipe = ipc::name_for(&layout.root.to_string_lossy());
        let ctrl = ipc::ping(&pipe, 300);
        let ev = ipc::evidence(&layout.root, cfg.is_some(), ctrl);
        // 状态与界面同源：界面把「已连接但自检未通过」标注成「已连接（通道未通）」，
        // CLI 只说「已连接」就等于让用户以为通道能用。同一份投影只在这个函数里。
        let check = selfcheck::load(&layout.root);
        let pres = presentation::present_with_check(
            &ev,
            check.as_ref().map(|c| c.sentence()).as_deref(),
        );
        // 「线路 / 端点」就在上面横幅那一行（用户最常看），这里只给数量，别重复。
        println!("  线路数    ：{}", cfg.as_ref().map(|c| c.lines.len()).unwrap_or(0));
        // 接管方式紧跟端点：同样是「怎么接管」，用户看一眼就知道自己现在选的是哪条路。
        // 显示**实际生效**的模式：连接中读运行时配置（引擎真正吃的那份），否则读线路文件。
        // 只读线路文件会骗人——接管方式可以在连接前切换，那时两份入站已经不同了。
        let shown_mode = cfg.as_ref().map(|c| engine_config::shown_mode(&layout.root, c.mode));
        println!("  模式      ：{}", shown_mode.map(|m| m.label()).unwrap_or("未配置"));
        // 默认直连之后，用户最容易的困惑是"连上了为什么浏览器没走节点"——这两个出口必须一眼可见。
        let exits = cfg
            .as_ref()
            .and_then(|c| c.current_engine_path(&layout.root))
            .and_then(|p| engine_config::read_exits_from_file(&p).ok().flatten());
        match exits {
            Some(info) => {
                println!("  日常出口  ：{}", if info.daily.is_empty() { "（未设置）" } else { &info.daily });
                println!("  交易出口  ：{}", if info.trade.is_empty() { "（未设置）" } else { &info.trade });
            }
            None => {
                println!("  日常出口  ：（无引擎配置）");
                println!("  交易出口  ：（无引擎配置）");
            }
        }
        // 两个开关与界面上的复选框同源，命令行也能一眼核对。
        println!("  开机自启  ：{}", on_off(cfg.as_ref().map(|c| c.auto_start).unwrap_or(false)));
        println!("  自动连接  ：{}", on_off(cfg.as_ref().map(|c| c.auto_connect).unwrap_or(false)));
        // 关窗行为直接说人话：用户最关心的是「关掉窗口会不会断网」。
        println!(
            "  关窗行为  ：{}",
            if cfg.as_ref().map(|c| c.close_to_tray).unwrap_or(false) {
                "缩到托盘（保持连接）"
            } else {
                "断开并退出"
            }
        );
        println!("  系统代理  ：启用={} 服务器={}", snap.enable, snap.server.as_deref().unwrap_or("(无)"));
        println!("  代理归属  ：{}", if ours { "已指向本程序" } else { "不是本程序设置" });
        println!("  还原凭据  ：{}", if has_journal { "存在" } else { "无" });
        println!("  控制接口  ：{}", if ctrl { "可用" } else { "不可用" });
        // 状态与建议动作放在最后，且都取自演示层产物：`--status` 和 `--headless`
        // 必须说同一句话，否则用户会同时收到「已连接」和「需要处理」两种结论。
        println!("  状态      ：{}", pres.title);
        println!("  建议动作  ：{}", action_zh(pres.action));
        // 只读上次连接留下的结论，**不在这里探测**：`--status` 要快且无副作用，
        // 而一次真实探测要连外网、最坏等 5 秒。
        println!(
            "  通道自检  ：{}",
            check.as_ref().map(|c| c.verdict()).unwrap_or_else(|| "未检测".to_string())
        );
        return ExitCode::SUCCESS;
    }

    // `--guard-status`：只读投影。没有配置时也要能回答「无法确认」，而不是假装没有这个能力。
    if std::env::args().any(|a| a == "--guard-status") {
        let st = guard::status(cfg.as_ref(), &layout.root, legacy_running);
        print_guard_status(&st);
        return ExitCode::SUCCESS;
    }

    // 显式交易保护动作：与界面/管道共用 guard 模块，行为只有一份。
    let guard_action = std::env::args().find_map(|a| match a.as_str() {
        "--guard-install" => Some(guard::elevate::GuardAction::Install),
        "--guard-sync" => Some(guard::elevate::GuardAction::Sync),
        "--guard-remove" => Some(guard::elevate::GuardAction::Remove),
        "--guard-verify" => Some(guard::elevate::GuardAction::Verify),
        _ => None,
    });
    if let Some(action) = guard_action {
        let Some(c) = cfg.as_ref() else {
            println!("  找不到配置文件（config.json），无法确定交易保护名单。");
            return ExitCode::from(exit::CONFIG);
        };
        // P0-13：只有用户明确加了 `--acknowledge-running` 才算「已读过提示、仍要启用」。
        // 闸门本身在 guard 模块里，与界面确认框共用同一份判据（不在这里再判一次）。
        let acknowledge_running = std::env::args().any(|a| a == "--acknowledge-running");
        let result = match action {
            guard::elevate::GuardAction::Install => {
                guard::install_explicit(c, &layout.root, legacy_running, acknowledge_running)
            }
            guard::elevate::GuardAction::Sync => {
                guard::sync_explicit(c, &layout.root, legacy_running, acknowledge_running)
            }
            guard::elevate::GuardAction::Remove => {
                guard::remove_status(c, &layout.root, legacy_running)
            }
            guard::elevate::GuardAction::Verify => {
                guard::verify_status(c, &layout.root, legacy_running)
            }
        };
        return match result {
            Ok(st) => {
                print_guard_status(&st);
                ExitCode::SUCCESS
            }
            Err(message) => {
                println!("  {message}");
                ExitCode::from(guard_failure_code(&message))
            }
        };
    }

    // `--connect` / `--disconnect`：真正拉起/停止引擎并增删系统代理。
    let wants_connect = std::env::args().any(|a| a == "--connect");
    let wants_disconnect = std::env::args().any(|a| a == "--disconnect");
    if wants_connect || wants_disconnect {
        // 断开路径不依赖配置：要停的引擎 pid 来自 runtime.json，要还原的值来自还原凭据，
        // 两者都在配置之外。配置缺失/损坏时仍然必须能断开（T13）。
        // 连接路径相反——没有线路和引擎就没有「连什么」可言，照旧拒绝。
        // 连接需要「连什么」：没有配置就没有线路和引擎，直接拒绝。
        // 断开相反——pid 在 runtime.json、还原值在凭据里，配置缺失也必须能断开（T13）。
        if wants_connect {
            if let Err((code, msg)) = config_gate(cfg.as_ref(), "连接") {
                println!("  {msg}");
                // 连接没发起也要留痕：「还没配好」是最常见的一种失败，
                // 记录里只有成功的连接，会让人以为自己从没点过。
                events::record(&layout.root, events::CONNECT, false, &msg, &cli_origin);
                return ExitCode::from(code);
            }
        }
        let cfg_ref = cfg.as_ref();
        if wants_connect {
            // 和 WebView 共用 Rust 预检：引擎已在运行时禁止重新生成
            // runtime-engine.json / 探测凭据，避免磁盘与实际 sing-box 状态分叉。
            let preflight_store = proxy::ProxyStore::system();
            if let Some(c) = cfg_ref {
                match connect::preflight_before_prepare(
                    c, &layout.root, &preflight_store, &probe::pid_alive, legacy_running,
                ) {
                    Ok(true) => {
                        let _ = connect::record_already_connected(c, &layout.root, &cli_origin);
                        println!("  已处于目标状态，未做改动。");
                        return ExitCode::SUCCESS;
                    }
                    Ok(false) => {}
                    Err(msg) => {
                        println!("  {msg}");
                        events::record(&layout.root, events::CONNECT, false, &msg, &cli_origin);
                        return ExitCode::from(exit::CONFIG);
                    }
                }
            }
        }
        // 探测计划：探测端口（线路端口 +3）被占 → 摘掉探测入站再起引擎
        // （引擎对绑不上的入站是整体 FATAL，不摘掉连"日常能通"都保不住），自检届时报「跳过」。
        // 凭据在这里生成一次，配置注入与自检共用同一份事实。
        let probe_plan = if wants_connect {
            endpoint.as_deref().map(selfcheck::plan_probe)
        } else {
            None
        };
        let probe_creds: Option<(&str, &str)> = match &probe_plan {
            Some(selfcheck::ProbePlan::Dial { username, password, .. }) => {
                Some((username.as_str(), password.as_str()))
            }
            _ => None,
        };
        // 引擎要听在自检要拨的那个端口上：计划可能已从 `+3` 回落到动态端口，
        // 这里传下去，避免两处各算一次把端口分叉。
        let probe_port: Option<u16> = match &probe_plan {
            Some(selfcheck::ProbePlan::Dial { port, .. }) => Some(*port),
            _ => None,
        };
        // 引擎的 `-c` 指向**当前这条线路**的配置；连接前把分流规则应用一遍，
        // 保证引擎看到的规则一定等于 config.json 里的最新事实（哪怕有人手改过）。
        // prepare 出错时**不能**退回线路文件起引擎：那上面的探测入站没有 users，
        // 直接起等于在 127.0.0.1 上开一个无认证的口——宁可拒绝连接。
        // （线路文件没有探测入站的老配置仍按原文件起，行为与之前一致。）
        let mut prepare_refused = false;
        // 引擎二进制：配置的那份（存在才算）→ 随包自带的副本。空配置但安装目录自带引擎时
        // 也能连——否则「装完就能用」这句承诺是假的。
        let engine_binary = cfg_ref
            .map(|c| c.engine.as_ref().map(|e| e.binary.clone()).unwrap_or_default())
            .and_then(|configured| crate::engine::resolve_for(&layout.root, &configured));
        let engine_cfg = cfg_ref.and_then(|c| {
            let (binary, _origin) = engine_binary.clone()?;
            let p = c.current_engine_path(&layout.root)?;
            let transport = c.current_line().map(|l| l.effective_transport()).unwrap_or_default();
            let settings = config::EngineSettings {
                binary: binary.to_string_lossy().to_string(),
            };
            // 出口网卡：线路指定就绑它，否则绑系统默认（防 TUN 把到服务器的连接绕回隧道）。
            // 指定了但**这块网卡现在不在这台电脑上**时必须拒绝：绑一张不存在的网卡
            // 会让引擎直接起不来；而静默退回默认网卡等于把交易流量放到用户没选的出口上。
            let (bind_interface, stale_interface) = crate::netbind::for_connect(
                &layout.root,
                c.current_line().map(|l| l.id.as_str()).unwrap_or(""),
            );
            if let Some(name) = stale_interface {
                prepare_refused = true;
                println!(
                    "  这条线路指定的出口网卡「{name}」不在这台电脑上，拒绝连接：\
                     请在「连接方式与网络」里重新选择，或改为跟随系统默认。"
                );
                return None;
            }
            match engine_config::prepare_engine_config(
                &p,
                &c.split,
                &c.agents,
                transport,
                c.mode,
                &layout.root.join("runtime-engine.json"),
                &bind_interface,
                probe_creds,
                probe_port,
            ) {
                Ok(effective) => Some(settings.to_engine(&effective)),
                // 即使是老线路，配置准备失败也不再静默使用原文件。
                // 否则可能缺少最新分流、DNS 或接口绑定约束。
                Err(err) => {
                    prepare_refused = true;
                    println!("  引擎配置准备失败，拒绝连接：{err}");
                    None
                }
            }
        });
        if prepare_refused {
            // 连接方式/TUN 入站与线路文件不匹配 = 配置问题，不是网络重试能解决的。
            return ExitCode::from(exit::CONFIG);
        }
        let store = proxy::ProxyStore::system();
        let log_dir = layout.logs.clone();
        let guard = crate::guard::ProductionGuard::new(&layout.root, legacy_running);
        let d = connect::Deps {
            store: &store,
            apply: &connect::write_proxy,
            spawn: &|e: &engine::EngineConfig| {
                // 管理员进程的任意引擎模式都必须拒绝 config.json
                // 指定外部可执行文件；不能靠把 TUN 改成 Proxy 绕过。
                // 使用实际 HKLM 提权判定，不受测试用 FORCE_NONADMIN 钩子影响。
                // 普通权限代理模式保持原有自定义引擎行为。
                if probe::is_elevated() {
                    let frontend = std::env::current_exe()
                        .map_err(|err| format!("无法确认 SpiderVPN 主程序身份：{err}"))?;
                    engine::validate_privileged_engine(
                        std::path::Path::new(&e.binary), &frontend,
                    )?;
                }
                engine::start(e, &log_dir).map(|h| h.pid)
            },
            kill: &|pid: i64| engine::stop(pid, 3_000),
            alive: &probe::pid_alive,
            elevated: &probe::elevated,
            journal_path: &layout.root.join("proxy-journal.json"),
            runtime_path: &layout.root.join("runtime.json"),
            now: crate::model::now_epoch_secs(),
            guard: guard.as_ref().map(|g| g.context()),
        };
        let r = if wants_connect {
            match (&cfg_ref, &engine_cfg) {
                (Some(c), Some(e)) => connect::connect_with_origin(c, e, &d, legacy_running, &cli_origin)
                    // TUN 起不来最常见的原因就是没提权——只在这一种失败上补提示。
                    .map_err(|m| connect::explain(m, c.mode)),
                (Some(c), None) => {
                    // 两种「缺东西」要分开说：缺线路和缺引擎是两回事，混在一起说会让人改错地方。
                    if c.lines.is_empty() {
                        let msg = "未配置线路，无法连接。请先导入线路或用 --set-line 写入一条。";
                        println!("  {msg}");
                        events::record(&layout.root, events::CONNECT, false, msg, &cli_origin);
                        return ExitCode::from(exit::CONFIG);
                    }
                    let configured = c
                        .engine
                        .as_ref()
                        .map(|e| e.binary.clone())
                        .unwrap_or_default();
                    let msg = ipc::engine_missing_message(&configured);
                    println!("  {msg}");
                    // 记录里的失败原因与屏幕上那句**逐字一致**：排障时两边对不上最费时间。
                    events::record(&layout.root, events::CONNECT, false, &msg, &cli_origin);
                    return ExitCode::from(exit::CONFIG);
                }
                (None, _) => unreachable!("上面已拦截：连接必须有配置"),
            }
        } else {
            connect::disconnect_with_origin(cfg_ref, &d, &cli_origin)
        };
        // 断开成功（含「本来就是断开态」）之后，上一次连接的自检结论就变成了假证据：
        // 在断开状态下报一句「通道自检通过」，和本单元要消灭的那类误导是同一件事。
        if wants_disconnect && r.is_ok() {
            // 保留 last-check.json：断开后仍要显示「上次结论 + 时间」，不能再冒充当前。
            // 只清运行时引擎配置，避免留下“正在连接”的痕迹。
            connect::discard_runtime_config(&layout.root);
            selfcheck::clear_latency(&layout.root);
        }
        // 口径：`runtime-engine.json` 存在 ⟺ 连接正在运行。
        // 判定与界面共用同一个函数（`ipc::settle_runtime_engine`），
        // 免得两条路径各写一套、又出现"界面删了 CLI 没删"（D8）。
        if wants_connect {
            ipc::settle_runtime_engine(&layout.root, &r);
        }
        match r {
            Ok(connect::Outcome::AlreadyDone) => {
                println!("  已处于目标状态，未做改动。");
                return ExitCode::SUCCESS;
            }
            Ok(connect::Outcome::Done(mut steps)) => {
                // 连接成功不等于通道可用：代理写对了、引擎也起来了，流量仍可能被送进直连。
                // 只有真的经交易出口拿回一个响应，这一句「已连接」才有证据。
                // 自检失败**不改**连接结果（很可能只是这个域名被用户网络屏蔽），但必须说出来。
                if wants_connect {
                    if let Some(plan) = &probe_plan {
                        // 凭据记进 runtime.json：自检从那里取（凭据只落在运行时记录里，不进日志）。
                        if let selfcheck::ProbePlan::Dial { username, password, .. } = plan {
                            if let Err(e) = selfcheck::record_probe_creds(
                                &layout.root.join("runtime.json"),
                                username,
                                password,
                            ) {
                                eprintln!("探测凭据记录失败：{e}");
                            }
                        }
                        let c =
                            selfcheck::check_and_record(&layout.root, plan, selfcheck::CLI_TIMEOUT_MS);
                        println!("  {}", c.sentence());
                        // B1：出口 IP 观测。自检只证明「转发通了」，这里回答「从哪个 IP 出去」。
                        // 拿不到就不说——绝不编一个地址出来。
                        if c.ok {
                            if let Some(line) = cfg_ref.and_then(|c| c.current_line()) {
                                // 「自动」的依据：这条线路**真的**用当前方式连通过了。记不下来只写
                                // 日志，连接结论与退出码都不受影响（自检结论已落在 last-check.json）。
                                let id = line.id.clone();
                                if let Err(e) = config::record_verified_transport(
                                    &layout.root,
                                    &id,
                                    line.effective_transport(),
                                ) {
                                    eprintln!("记录已验证的连接方式失败：{e}");
                                }
                                if let Some(rec) = exit_probe::probe_and_record(
                                    &layout.root,
                                    line,
                                    plan,
                                    2_500,
                                ) {
                                    println!("  {}", exit_probe_line(&rec));
                                }
                            }
                        }
                        // BUG-501 的兜底：标准连接没过、而这条线路其实有兼容连接参数时，
                        // 给一句能自救的话。结论行与退出码都不动。
                        if let Some(hint) = selfcheck::transport_alternative_hint(cfg_ref, &layout.root, &c) {
                            println!("  {hint}");
                        }
                        // steps 是事务摘要：只说结论与（跳过时的）原因，失败原因不在这里重复。
                        steps.push(c.step_text());
                    }
                }
                println!("  完成：{}", steps.join("；"));
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                // 连接失败时代理已回滚，上一轮留下的「通过」不再成立。
                if wants_connect {
                    selfcheck::clear(&layout.root);
                    // 「已验证的连接方式」同理：这次没连上，它就只是一条旧证据，
                    // 「自动」不该再拿它当依据。清不掉只说一句日志，不改退出码。
                    if let Some(line) = cfg_ref.and_then(|c| c.current_line()) {
                        let id = line.id.clone();
                        if let Err(e) = config::clear_verified_transport(&layout.root, &id) {
                            eprintln!("清除已验证的连接方式失败：{e}");
                        }
                    }
                }
                println!("  失败：{}", e);
                return ExitCode::from(exit::NETWORK);
            }
        }
    }

    // `--plan`：只读预览，打印「接管会改什么」，不写任何值。
    if std::env::args().any(|a| a == "--plan") {
        if let Err((code, msg)) = config_gate(cfg.as_ref(), "计算代理变更") {
            println!("  {msg}");
            return ExitCode::from(code);
        }
        // 矩阵定稿：缺 engine.binary 也算「配置不完整」→ CONFIG（与 --connect 一致）。
        if engine_missing(cfg.as_ref()) {
            println!("  未配置引擎（config.json 的 engine.binary），无法计算代理变更。");
            return ExitCode::from(exit::CONFIG);
        }
        let ep = current_endpoint(cfg.as_ref());
        let snap = proxy::ProxySnapshot::read();
        let plan = proxy::plan_connect(&snap, &ep, legacy_running);
        println!("  当前代理：可用读取={} 启用={} 服务器={}",
            snap.readable, snap.enable, snap.server.as_deref().unwrap_or("(无)"));
        if let Some(b) = &plan.blocked {
            println!("  已阻止：{}", b);
            return ExitCode::from(exit::NETWORK);
        }
        if plan.changes.is_empty() {
            println!("  无需改动。");
        } else {
            println!("  将改动 {} 项（本次为预览，未写入）：", plan.changes.len());
            for c in &plan.changes {
                println!("    {:<14} {:>18} -> {}", c.key, format!("[{}]", c.from), c.to);
            }
        }
        for w in &plan.warnings {
            println!("  注意：{}", w);
        }
        return ExitCode::SUCCESS;
    }

    // `--apply`：真正落笔。**默认永远是预览**，只有显式传这个参数才写系统代理。
    // 顺序不可颠倒：先落还原凭据，再改注册表。反过来一旦中途失败就没有退路了。
    if std::env::args().any(|a| a == "--apply") {
        if let Err((code, msg)) = config_gate(cfg.as_ref(), "落笔代理变更") {
            println!("  {msg}");
            return ExitCode::from(code);
        }
        let ep = current_endpoint(cfg.as_ref());
        let snap = proxy::ProxySnapshot::read();
        let plan = proxy::plan_connect(&snap, &ep, legacy_running);
        if let Some(b) = &plan.blocked {
            println!("  已阻止：{}", b);
            return ExitCode::from(exit::NETWORK);
        }
        if plan.changes.is_empty() {
            println!("  无需改动，未写入。");
            return ExitCode::SUCCESS;
        }
        let jp = layout.root.join("proxy-journal.json");
        let journal = proxy::ProxyJournal::from_snapshot(&snap, &ep, crate::model::now_epoch_secs());
        if let Err(e) = proxy::write_journal(&jp, &journal) {
            // 没有还原凭据就不许动系统代理：这是本程序最重要的一条纪律。
            println!("  拒绝落笔：无法写入还原凭据（{}）", e);
            return ExitCode::from(exit::CONFIG);
        }
        let store = proxy::ProxyStore::system();
        if let Err(e) = store.apply(&plan.changes) {
            println!("  写入失败：{}", e);
            println!("  可执行 --restore-apply 按凭据还原");
            return ExitCode::from(exit::ENVIRONMENT);
        }
        // 写完立刻回读校验：注册表是外部状态，不能假设写成功就等于生效。
        let after = store.read();
        let mut bad = Vec::new();
        if after.enable != true {
            bad.push("ProxyEnable 未生效".to_string());
        }
        if after.server.as_deref() != Some(ep.as_str()) {
            bad.push(format!("ProxyServer 未生效（现在是 {:?}）", after.server));
        }
        if bad.is_empty() {
            println!("  已落笔 {} 项，回读校验通过。", plan.changes.len());
            return ExitCode::SUCCESS;
        }
        println!("  已写入但校验未通过：{}", bad.join("；"));
        println!("  可执行 --restore-apply 按凭据还原");
        return ExitCode::from(exit::ENVIRONMENT);
    }

    // `--restore-apply`：按凭据真正还原。
    //
    // 这里**复用** connect::restore_from_journal：连接失败的自动回滚在「读不到当前代理」时
    // 会盲还原，手工命令若是拒绝（exit 8），就成了「自动回滚救不了的地方它也救不了」——
    // 而三处错误提示都拿这条命令当最后兜底。兜底必须更强，不能更弱。
    if std::env::args().any(|a| a == "--restore-apply") {
        let jp = layout.root.join("proxy-journal.json");
        if !jp.exists() {
            println!("  没有还原凭据，未执行任何写入。");
            return ExitCode::SUCCESS;
        }
        let store = proxy::ProxyStore::system();
        match connect::restore_from_journal(&store, &jp, "") {
            Ok(true) => {
                println!("  已按还原凭据还原系统代理，凭据已清除。");
                return ExitCode::SUCCESS;
            }
            Ok(false) => {
                println!("  无需还原（当前值与接管前一致，或已被别人改动），凭据已清除。");
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                // 还原失败时凭据要留着：下次还能再试，删了就真没线索了。
                println!("  还原失败：{e}（凭据已保留，可修好后再执行一次）");
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    // `--restore`：按还原凭据预览「怎么改回去」。同样是只读。
    if std::env::args().any(|a| a == "--restore") {
        let jp = layout.root.join("proxy-journal.json");
        match proxy::read_journal(&jp) {
            Ok(None) => {
                println!("  没有找到还原凭据（{}），无需还原。", jp.display());
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                println!("  还原凭据不可用：{}", e);
                return ExitCode::from(exit::CONFIG);
            }
            Ok(Some(j)) => {
                let snap = proxy::ProxySnapshot::read();
                let rp = proxy::plan_restore(&j, &snap, &j.endpoint);
                if let Some(b) = &rp.blocked {
                    println!("  已阻止：{}", b);
                    return ExitCode::from(exit::NETWORK);
                }
                if rp.changes.is_empty() {
                    println!("  无需还原（当前值与接管前一致，或已被别人改动）。");
                } else {
                    println!("  将还原 {} 项（本次为预览，未写入）：", rp.changes.len());
                    for c in &rp.changes {
                        println!("    {:<14} {:>18} -> {}", c.key, format!("[{}]", c.from), c.to);
                    }
                }
                for w in &rp.warnings {
                    println!("  注意：{}", w);
                }
                return ExitCode::SUCCESS;
            }
        }
    }

    // 4. 控制接口：先起服务端，再探测。名字由数据根派生，天然与旧版隔离。
    let pipe_name = ipc::name_for(&layout.root.to_string_lossy());

    // 部署引擎：进程内单例。管道与界面**共用同一个句柄**——两条入口必须看到同一份
    // 排队与活动，否则界面说「正在跑」、管道说「没在跑」。
    //
    // `deploy_engine` 必须活到 `main` 结束：它一被 drop 就会给监督线程发 Shutdown
    // （见 `Engine::drop`），部署会停在半路。别把它塞进任何块作用域里。
    let deploy_engine = deployengine::Engine::start(
        layout.root.clone(),
        std::sync::Arc::new(deployengine::ProdOps::new(events::Origin::auto())),
        events::Origin::auto(),
    );

    // 启动恢复（T04）：上一个进程留下的 `Running`/`Queued` 记录必须在这里改判成
    // `NeedsAttention`，否则页面会一直说「正在部署」。
    //
    // 位置是判据的一部分：`instance::acquire` 已经拿到命名互斥（本进程独占记录目录），
    // 而引擎里此刻还一条 pass 都没有——所以「执行者不是本进程」就等于「那个进程死了」。
    // 只在持锁时做：抢不到锁的只读命令（`--status` 一类）不该替真正的实例改记录。
    if guard.is_some() {
        let report = deploy_engine.recover_all();
        if report.rewritten > 0 {
            println!(
                "  部署恢复：{} 条被中断的任务已改判为「需要处理」",
                report.rewritten
            );
        }
        if !report.is_clean() {
            println!("  部署恢复：{}", report.error);
        }
        // 线路动作的恢复（A6 第二轮）：上一个进程留下的 `Pending` 测速/保存不是
        // 「没有发生」，而是「结果没人知道」——改判成「待核对」，界面上才有人管。
        match lineaction::recover_pending(&layout.root) {
            Ok(0) => {}
            Ok(count) => println!("  线路动作：{count} 条被中断的操作已改判为「待核对」"),
            Err(error) => println!("  线路动作恢复失败：{error}"),
        }
        // 连接/断开的恢复（A5/A6）：这两个动作改系统代理、起停引擎，中断后
        // 「做没做成」必须由界面核对待处理，不能当成没发生。诊断只读，改判为失败即可。
        match oprecord::recover_pending(&layout.root) {
            Ok(0) => {}
            Ok(count) => println!("  界面操作：{count} 条被中断的操作已改判（连接/断开待核对）"),
            Err(error) => println!("  界面操作恢复失败：{error}"),
        }
        // 记录裁剪（r79）：**只在启动时**跑一次，不是每帧。
        //
        // 被删的只有「已完成 / 已取消 + 超过 7 天 + 没有未读提醒 + 没归档」那一批：
        // 界面本来就看不到它们（底部队列只留 24 小时，也没有记录页），所以用户无感；
        // 换来的是 `runs\` 目录与「每帧重读全部记录」的开销有上界。
        //
        // 读不到提醒时整轮不裁（`prune_records` 返回 None）：不知道哪些记录还被提醒
        // 引用，就先别删。删了会在「查看」上留下一个指向空记录的提醒。
        match deployengine::prune_records(&layout.root) {
            None => println!("  部署记录：读不到提醒，这一轮不裁剪"),
            Some(outcome) => {
                if outcome.removed > 0 {
                    println!(
                        "  部署记录：按保留策略清理了 {} 条旧记录（保留最近 {} 条 / {} 天）",
                        outcome.removed, outcome.keep, outcome.keep_days
                    );
                    // 记一笔：用户**看不到**这次删除（那批记录本来就不在界面上），
                    // 但「我的记录去哪了」必须能查到。
                    events::record(
                        &layout.root,
                        events::PRUNE_RECORDS,
                        true,
                        &format!("清理 {} 条，保留 {} 条", outcome.removed, outcome.kept),
                        &events::Origin::auto(),
                    );
                }
                if !outcome.error.is_empty() {
                    // 该清而没清干净：照实说，也照实记。
                    println!("  部署记录：{}", outcome.error);
                    events::record(
                        &layout.root,
                        events::PRUNE_RECORDS,
                        false,
                        &outcome.error,
                        &events::Origin::auto(),
                    );
                }
            }
        }
    }
    println!("  控制管道：{}", pipe_name);

    // 管道和界面共用同一份上下文：同一次点击，无论从哪儿发来，看到的必须是同一套事实。
    let ipc_ctx = ipc::Ctx {
        legacy_running,
        cfg: cfg.clone(),
        root: layout.root.clone(),
        log_dir: layout.logs.clone(),
        source: events::Source::Pipe,
        transaction_gate: std::sync::Arc::new(std::sync::Mutex::new(())),
        engine: Some(deploy_engine.handle()),
    };

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let n = pipe_name.clone();
        let s = stop.clone();
        let c = ipc_ctx.clone();
        // 监听失败不致命：没有控制接口时状态会显示为「未连接」，而不是假装已连接。
        std::thread::spawn(move || {
            if let Err(e) = ipc::serve(n, s, c) {
                eprintln!("控制接口监听失败：{}", e);
            }
        });
    }
    let control_ready = ipc::wait_ready(&pipe_name, 1_500);
    println!("  控制接口：{}", if control_ready { "可用" } else { "不可用" });

    // 5. 状态投影：读**自己数据根**里的记录（不是旧版的），再结合真实探测。
    //    「是否已配置」取本程序自己的 config.json，与管道 `status`、界面首屏同源；
    //    旧版的 deployment.json 本程序永不写，用它当依据会让配好线路后仍显示「尚未配置」。
    let ev = ipc::evidence(&layout.root, cfg.is_some(), control_ready);
    let pres = presentation::present(&ev);
    println!("  当前状态：{} — {}", pres.title, pres.detail);

    // `--headless`：只做隔离、目录、状态自检后退出。CI、冒烟测试和这台机器的
    // 无交互会话都用它——没有它就只能靠「窗口弹没弹出来」判断，那是不可测的。
    if std::env::args().any(|a| a == "--headless") {
        // **自检命令一律 exit 0**：它不执行动作，「尚未配置」是合法状态，写进输出就够。
        // 让 CI 在新机器上直接失败没有意义；13 只留给需要线路才能执行动作的命令。
        println!("  （headless：不创建窗口，仅自检）");
        let line_desc = cfg
            .as_ref()
            .and_then(|c| c.current_line())
            .map(|l| l.name.clone())
            .unwrap_or_else(|| "尚未配置".to_string());
        let engine_desc = if engine_missing(cfg.as_ref()) { "尚未配置" } else { "已配置" };
        let n = cfg.as_ref().map(|c| c.lines.len()).unwrap_or(0);
        println!("  自检：线路={line_desc}（共 {n} 条）  引擎={engine_desc}");
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        return ExitCode::SUCCESS;
    }

    // 界面按钮不自己做判断：把命令原文交给协议层执行，再把新的状态推回页面。
    // 走同一段代码，才不会长出「界面能做、命令行不能做」这种分叉。
    // 界面的导入走的是与命令行同一个 import_profile。长命令会在工作线程执行，
    // 因此上下文用 Arc<Mutex>；事务门本身也在 Ctx 里，与管道共享。
    let ui_ctx = std::sync::Arc::new(std::sync::Mutex::new(ipc_ctx.clone()));
    ui_ctx.lock().unwrap_or_else(|e| e.into_inner()).source = events::Source::Ui;
    let ui_budget_ctx = std::sync::Arc::clone(&ui_ctx);
    let ui_root = layout.root.clone();
    // 托盘能不能起来，要等 ui::run 里建完才知道；这里先给出共享槽位，状态 JSON 从它取值。
    let tray_ok = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let tray_ok_ui = tray_ok.clone();
    let ui_handler = move |raw: &str| -> String {
        let is_long = ipc::is_long_command(raw);
        let is_short_write = ipc::is_short_write_command(raw);
        let transaction_gate = {
            let ctx = ui_ctx.lock().unwrap_or_else(|e| e.into_inner());
            (is_long || is_short_write).then(|| std::sync::Arc::clone(&ctx.transaction_gate))
        };
        let _transaction_guard = match transaction_gate.as_ref() {
            Some(gate) if is_long => Some(gate.lock().unwrap_or_else(|e| e.into_inner())),
            Some(gate) => match gate.try_lock() {
                Ok(guard) => Some(guard),
                Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => {
                    return serde_json::json!({
                        "ok": false,
                        "errorCode": "busy",
                        "error": "当前有其他操作正在进行，配置修改未执行，请稍后重试"
                    }).to_string();
                }
            },
            None => None,
        };
        let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
        let cmd = parsed.as_ref().and_then(|v| v.get("cmd")).and_then(|c| c.as_str());
        if cmd == Some("pick-file") {
            let st = handle_ui_pick_file(&ui_ctx.lock().unwrap_or_else(|e| e.into_inner()), raw);
            return inject_bool(st, "trayAvailable", tray_ok_ui.load(std::sync::atomic::Ordering::Relaxed));
        }
        if cmd == Some("save-file") {
            let st = handle_ui_save_file(&ui_ctx.lock().unwrap_or_else(|e| e.into_inner()), raw);
            return inject_bool(st, "trayAvailable", tray_ok_ui.load(std::sync::atomic::Ordering::Relaxed));
        }
        if cmd == Some("pick-exe") {
            let st = handle_ui_pick_exe(&ui_ctx.lock().unwrap_or_else(|e| e.into_inner()), raw);
            return inject_bool(st, "trayAvailable", tray_ok_ui.load(std::sync::atomic::Ordering::Relaxed));
        }
        if cmd == Some("inspect-import") {
            let st = handle_ui_inspect_import(&ui_ctx.lock().unwrap_or_else(|e| e.into_inner()), raw);
            return inject_bool(st, "trayAvailable", tray_ok_ui.load(std::sync::atomic::Ordering::Relaxed));
        }
        if cmd == Some("import") {
            let st = handle_ui_import(
                &ui_root,
                &mut ui_ctx.lock().unwrap_or_else(|e| e.into_inner()),
                raw,
            );
            return inject_bool(st, "trayAvailable", tray_ok_ui.load(std::sync::atomic::Ordering::Relaxed));
        }
        if cmd == Some("settings") {
            // 复选框是即时生效的：落盘 + 同步 Run 键 + 回推状态，一次做完。
            let st = handle_ui_settings(
                &ui_root,
                &mut ui_ctx.lock().unwrap_or_else(|e| e.into_inner()),
                raw,
            );
            return inject_bool(st, "trayAvailable", tray_ok_ui.load(std::sync::atomic::Ordering::Relaxed));
        }
        // **锁内只克隆，锁外再执行**。
        //
        // 以前写的是 `&ui_ctx.lock()…`：那个 MutexGuard 会一路活到 `handle_line_with`
        // 返回，于是 SSH 类的命令（`server-devices` 连不上要 20 秒）把整把锁攥在手里。
        // 而快照侧每次 `fetch` 也要这把锁（`snapshot(&fetch)` → `ui_handler`），
        // 结果 UI 线程被堵在锁上：点击后 24 秒页面不动、快照停摆，还自己弹
        // 「数据过期（已 N 秒未更新）」——把自己锁死，再怪数据。
        //
        // `Ctx` 是 Clone，且 `transaction_gate` 是 `Arc`：克隆出来的副本仍指向同一道门，
        // 串行化语义不变（两个入口同时连接/断开照样互斥）。
        let call_ctx = {
            let guard = ui_ctx.lock().unwrap_or_else(|e| e.into_inner());
            guard.clone()
        };
        let cmd_reply = ipc::handle_line_with(raw, &call_ctx);
        // use/remove 会改线路配置：重读一次，别让界面状态停在旧数据上。
        if let Ok(Some(c)) = config::load(&ui_root.join(config::DEFAULT_PATH)) {
            ui_ctx.lock().unwrap_or_else(|e| e.into_inner()).cfg = Some(c);
        }
        let mut state = status_state(&ui_ctx.lock().unwrap_or_else(|e| e.into_inner()));
        // 失败原因必须让用户看见：点了按钮界面毫无变化，比明说失败更糟。
        let failed = serde_json::from_str::<serde_json::Value>(&cmd_reply)
            .ok()
            .and_then(|v| {
                if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                    None
                } else {
                    v.get("error").and_then(|x| x.as_str()).map(|s| s.to_string())
                }
            });
        if let (Some(e), Some(obj)) = (failed, state.as_object_mut()) {
            obj.insert("detail".to_string(), serde_json::Value::String(format!("操作失败：{e}")));
        }
        // 线路类命令的回包带整份列表：转交给页面（界面不用再查一次）。
        // 合并逻辑与键表同在 `uiweb`（`UI_REPLY_KEYS` 挨着它的消费方），这里只调用。
        if let Ok(reply) = serde_json::from_str::<serde_json::Value>(&cmd_reply) {
            crate::uiweb::merge_ui_command_reply(&mut state, &reply);
        }
        // 服务商结论取决于当前线路的真实投影与出口选择；任何命令之后都重读一次，
        // 避免「设为日常出口」后卡片仍停在“等待准备”。读取失败按空列表投影。
        let pp = ipc::providers_payload(&ui_root);
        if let Some(obj) = state.as_object_mut() {
            obj.insert("providers".to_string(), pp["providers"].clone());
            obj.insert("entryNote".to_string(), pp["entryNote"].clone());
        }
        inject_bool(
            state.to_string(),
            "trayAvailable",
            tray_ok_ui.load(std::sync::atomic::Ordering::Relaxed),
        )
    };
    let ui_budget = move |raw: &str| -> f64 {
        ipc::operation_budget(raw, &ui_budget_ctx.lock().unwrap_or_else(|e| e.into_inner()))
    };

    // 关窗必须先断开：窗口没了、引擎还在跑、代理还指着我们，是最糟的残留状态。
    // 清理失败也要让窗口关得掉，只是把失败反映到退出码上。
    let close_cfg = cfg.clone();
    let close_root = layout.root.clone();
    let on_close = move || cleanup_on_close(close_cfg.clone(), close_root.clone());

    // 关窗行为来自配置（缺省 false = 断开并退出）；托盘起不来时 ui::run 会自动退回这个行为。
    let close_to_tray = cfg.as_ref().map(|c| c.close_to_tray).unwrap_or(false);

    // 「现在还有没有部署没跑完」——T09 的关窗/托盘退出判定要用它。
    // 计数取引擎里的**活动 + 排队**（见 `deployengine::busy_sentence`：排队那条也算）。
    let deploy_engine_ui = deploy_engine.handle();
    let deploying = move || {
        let shared = deploy_engine_ui.shared();
        deployengine::busy_sentence(shared.active_count(), shared.queued_count())
    };

    // 开界面之前把已有私钥文件的权限收紧一次（F1）。升级上来的 client.conf / tunnel.key /
    // 线路 json 继承的是 `BUILTIN\Users:(RX)`，而新代码路径不会重写它们。失败只报出来、
    // 不拦启动（文件可能属于别的账户，当前进程没有 WRITE_DAC），但绝不静默。
    for failure in secretfile::tighten_data_root(&layout.root) {
        eprintln!("  收紧私钥文件权限失败：{failure}");
    }

    // 任务级登录凭据「最长 24 小时」。过期清理不能只靠「有人去读它」：一条停在
    // NeedsAttention 上没人管的部署，可能再也不会被打开——那份 DPAPI 信封就会一直
    // 躺在磁盘上，而界面上写着它会过期。启动扫描是唯一兜得住这种情况的地方。
    let swept = deploycred::sweep_expired(&layout.root);
    if swept > 0 {
        eprintln!("  已清理 {swept} 份过期的任务登录资料（超过 24 小时）");
    }

    if let Err(e) = ui::run(
        &layout.root.to_string_lossy(),
        &layout.webview.to_string_lossy(),
        close_to_tray,
        tray_ok,
        Box::new(deploying),
        Box::new(ui_handler),
        Box::new(ui_budget),
        Box::new(on_close),
    ) {
        eprintln!("界面启动失败：{}", e);
        return ExitCode::from(exit::ENVIRONMENT);
    }

    ExitCode::SUCCESS
}

/// 关窗清理的看门狗上限。
///
/// 引擎停止自身有硬上限（3 秒温和 + 2 秒强制后确认 = 5 秒），所以实际最坏也就 5 秒左右关窗。
/// 看门狗必须比内部上限大一点：两者取等号的话，「引擎杀不掉」和「意料之外的卡死」会塌成
/// 同一个「超时」，真正的失败原因就丢了。真卡住时照样退出——关不掉的窗口比没清理更糟。
const SHUTDOWN_WATCHDOG_MS: u64 = 6_000;

/// 关窗清理：真正断开（停引擎 → 还原代理 → 删记录），再把结果换算成退出码。
///
/// 空闲时（没配置、没有运行时记录）是一次空操作，返回 0。
fn cleanup_on_close(cfg: Option<config::AppConfig>, root: std::path::PathBuf) -> i32 {
    let (tx, rx) = std::sync::mpsc::channel();
    let root_for_log = root.clone();
    std::thread::spawn(move || {
        let store = proxy::ProxyStore::system();
        let journal_path = root.join("proxy-journal.json");
        let runtime_path = root.join("runtime.json");
        let d = connect::Deps {
            store: &store,
            apply: &connect::write_proxy,
            // 关窗只做停止与还原，绝不启动引擎；真被调用说明逻辑错了。
            spawn: &|_e: &engine::EngineConfig| Err::<i64, String>("关窗清理不应启动引擎".to_string()),
            // 温和期与 CLI/IPC 的断开保持一致：不给够这段时间，引擎来不及撤销自己的系统改动。
            kill: &|pid: i64| engine::stop(pid, 3_000),
            alive: &probe::pid_alive,
            elevated: &probe::elevated,
            journal_path: &journal_path,
            runtime_path: &runtime_path,
            now: crate::model::now_epoch_secs(),
            // 关窗清理不弹 UAC；用户显式断开走 IPC/CLI 路径。
            guard: None,
        };
        let _ = tx.send(connect::shutdown_cleanup(
            cfg.as_ref(),
            &d,
            &events::Origin::auto(),
        ));
    });
    let reason = match rx.recv_timeout(std::time::Duration::from_millis(SHUTDOWN_WATCHDOG_MS)) {
        Ok(Ok(_)) => return 0,
        Ok(Err(e)) => e,
        Err(_) => format!("等待超过 {} 毫秒仍未完成", SHUTDOWN_WATCHDOG_MS),
    };
    eprintln!("关窗清理未完成：{}", reason);
    eprintln!("系统代理可能仍指向本程序的端点，请执行 --restore-apply 还原。");
    // 窗口已经关了，用户看不到 eprintln：落一行到数据根，下次启动回显。
    note_startup_issue(&root_for_log, &reason);
    14
}

/// 处理界面发来的导入请求，返回新的状态 JSON。
///
/// 抽成独立函数是为了能测：wry 的闭包在单测里调不到，而「用户点了导入之后到底写了什么」
/// 恰恰是最该被测试盯住的一段——它同时决定线路、模式和引擎配置三份落盘内容。
fn handle_ui_import(root: &std::path::Path, ctx: &mut ipc::Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let field = |k: &str| -> String {
        parsed
            .as_ref()
            .and_then(|v| v.get(k))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let prof = field("profile");
    let eng = field("engine");
    let name = field("name");
    let on_conflict = field("onConflict");
    // 提交前先做一次只读校验：字段不对就当场指出是哪一项、应该选什么，不进入写入路径。
    let problems = inspect_import_problems(&prof, &eng);
    if !problems.is_empty() {
        let mut st = status_state(ctx);
        if let Some(o) = st.as_object_mut() {
            o.insert("importDone".to_string(), serde_json::Value::Bool(true));
            o.insert("problems".to_string(), serde_json::Value::Array(problems));
            o.insert("detail".to_string(), serde_json::Value::String("请先修正标出的文件".to_string()));
        }
        return st.to_string();
    }
    if on_conflict == "ask" || on_conflict == "save-as" {
        let existing = config::load(&root.join(config::DEFAULT_PATH)).ok().flatten();
        let same = if name.is_empty() {
            None
        } else {
            existing
                .as_ref()
                .and_then(|c| c.find_line(&name))
                .map(|l| (l.id.clone(), l.name.clone()))
        };
        if let Some((id, found_name)) = same {
            // 确认前一个字节都不写：引擎配置也在这条分支之后才生成。
            let mut st = status_state(ctx);
            if let Some(o) = st.as_object_mut() {
                let message = format!("同名线路已存在：{found_name}。请选择替换、另存为或取消。");
                o.insert("ok".to_string(), serde_json::Value::Bool(false));
                o.insert("errorCode".to_string(), serde_json::json!("conflict"));
                o.insert("error".to_string(), serde_json::Value::String(message.clone()));
                o.insert("detail".to_string(), serde_json::Value::String(message));
                o.insert("conflict".to_string(), serde_json::json!({ "id": id, "name": found_name }));
                o.insert("importDone".to_string(), serde_json::Value::Bool(false));
            }
            return st.to_string();
        }
    }
    if on_conflict == "save-as" && name.is_empty() {
        let mut st = status_state(ctx);
        if let Some(o) = st.as_object_mut() {
            o.insert("importDone".to_string(), serde_json::Value::Bool(true));
            o.insert(
                "detail".to_string(),
                serde_json::Value::String("另存为需要一个新线路名".to_string()),
            );
        }
        return st.to_string();
    }
    // 认不出的模式按代理（`Mode::from_name`）：一个拼错的值不该让导入失败，
    // 也不该把用户悄悄切到要管理员权限的接管方式上。
    let mode = config::Mode::from_name(&field("mode"));
    // 端口回落只写这一处：页面留空就不带 port，这里补 17890——加端口之前的老用法零变化。
    // 非法值（非数字/越界）同样回落：页面已经挡过一次，能走到这里的是手改命令的调用方。
    let port = parsed
        .as_ref()
        .and_then(|v| v.get("port"))
        .and_then(|x| x.as_u64())
        .and_then(|n| u16::try_from(n).ok())
        .filter(|p| (1..=65532).contains(p))
        .unwrap_or(DEFAULT_PORT);

    let mut st = status_state(ctx);
    let note = match import_profile(
        root,
        std::path::Path::new(&prof),
        &eng,
        port,
        if name.is_empty() { None } else { Some(name.as_str()) },
        mode,
        &ctx.origin(None),
    ) {
        Ok((nc, updated)) => {
            // 导入后必须重载上下文，否则界面显示的还是导入前那条线路（模式也一样）。
            let line = nc.current_line().cloned().unwrap_or(config::LineConfig {
                id: String::new(),
                name: String::new(),
                proxy_endpoint: String::new(),
                transport: None,
                verified_transport: None,
            });
            ctx.cfg = Some(nc.clone());
            st = status_state(ctx);
            format!(
                "已{}线路：{}（{}，{}）",
                if updated { "更新" } else { "导入" },
                line.name,
                line.proxy_endpoint,
                nc.mode.label()
            )
        }
        // 界面的 `.msg` 与 CLI 的 stderr 取同一句（import_failure），不得加「导入失败：」前缀。
        Err(e) => import_failure(&e).1,
    };
    if let Some(o) = st.as_object_mut() {
        o.insert("detail".to_string(), serde_json::Value::String(note));
        o.insert("importDone".to_string(), serde_json::Value::Bool(true));
        o.insert("problems".to_string(), serde_json::Value::Array(Vec::new()));
        // 导入后列表立刻反映新线路（且已选中它），界面不用再查一次。
        o.insert(
            "lines".to_string(),
            ipc::lines_payload(ctx.cfg.as_ref())["lines"].clone(),
        );
    }
    st.to_string()
}

/// 只读校验导入表单。返回的每一项都同时说明「哪个字段、为什么、怎么改」。
fn inspect_import_problems(profile: &str, engine: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    if profile.trim().is_empty() {
        out.push(serde_json::json!({
            "field": "profile",
            "why": "还没有选择线路文件",
            "fix": "点击「选择线路文件」，选中服务商提供的 dual-mode.json"
        }));
    } else {
        let path = std::path::Path::new(profile.trim());
        if !path.is_file() {
            out.push(serde_json::json!({
                "field": "profile",
                "why": format!("文件不存在：{}", path.display()),
                "fix": "重新选择线路文件；不要填目录或订阅链接"
            }));
        } else {
            match std::fs::read_to_string(path) {
                Err(e) => out.push(serde_json::json!({
                    "field": "profile",
                    "why": format!("线路文件读不出来：{e}"),
                    "fix": "确认文件没有被占用，或换一份线路文件"
                })),
                Ok(text) => {
                    if let Err(e) = engine_config::generate(
                        &text,
                        DEFAULT_PORT,
                        config::Mode::Proxy,
                        &config::SplitConfig::default(),
                        // 只读校验：只关心线路文件本身能不能生成，不掺入用户名单
                        // （否则一份坏名单会让「选不了线路文件」这句提示指向错误的原因）。
                        &config::AgentsConfig::default(),
                        &config::Exits::default(),
                    ) {
                        out.push(serde_json::json!({
                            "field": "profile",
                            "why": e,
                            "fix": "选择服务商提供的线路 JSON；不要选择普通说明文件"
                        }));
                    }
                }
            }
        }
    }
    if engine.trim().is_empty() {
        out.push(serde_json::json!({
            "field": "engine",
            "why": "还没有选择引擎程序",
            "fix": "点击「选择引擎程序」，选中 sing-box.exe"
        }));
    } else if !std::path::Path::new(engine.trim()).is_file() {
        out.push(serde_json::json!({
            "field": "engine",
            "why": format!("引擎程序不存在：{}", engine.trim()),
            "fix": "选择线路配套的 sing-box.exe，不要选目录"
        }));
    }
    out
}

/// `pick-file` 的宿主侧实现。文件选择器通过参数注入，测试不会真的弹窗。
fn handle_ui_pick_file_with<F>(ctx: &ipc::Ctx, raw: &str, picker: F) -> String
where
    F: Fn(&str) -> Result<Option<String>, String>,
{
    handle_ui_pick_file_with_probe(ctx, raw, picker, &ipc::probe_engine_binary)
}

/// 同上的可测形态：**引擎探测也注入**。
///
/// 不给它留注入点的话，「选完引擎真的写进配置」这条只能靠这台机器上有一份真 sing-box
/// 才能验——那种用例换台机器就红，最后会被删掉，等于没测。
fn handle_ui_pick_file_with_probe<F>(
    ctx: &ipc::Ctx,
    raw: &str,
    picker: F,
    probe: &dyn Fn(&std::path::Path) -> Result<String, String>,
) -> String
where
    F: Fn(&str) -> Result<Option<String>, String>,
{
    let slot = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("slot").and_then(|x| x.as_str()).map(str::to_string))
        .unwrap_or_else(|| "profile".to_string());
    // 三个槽位，**必须逐个列出**：写成 `if engine {…} else {profile}` 的话，
    // `slot:"key"` 会被静默归一化成线路 JSON 过滤器——症状是「文件选择器里明明有
    // 那个 .pem 却看不见」，很容易被当成权限问题查半天。
    let slot = match slot.as_str() {
        "engine" => "engine",
        "key" => "key",
        // 管理恢复包（r94）：入口在下一条注释里；漏了它 `.tcrecovery` 会被
        // 静默套上 `*.json` 过滤器（症状是「文件明明在，却看不见」）。
        "recovery" => "recovery",
        _ => "profile",
    };
    let mut st = status_state(ctx);
    let pick_id = format!(
        "pick-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    let picked = picker(slot);
    // 先把「用户到底选了哪个文件」留一份：下面 `picked` 会被消费掉，而引擎那一步还要用。
    let chosen = match &picked {
        Ok(Some(path)) => Some(path.clone()),
        _ => None,
    };
    // 「选择恢复包文件」不只给路径：导入页要的是**内容**。在这里一次读掉，
    // 页面不必再发一条 read-file；上限与旧版一致（128 KiB），超了就说清楚。
    let mut recovery_text: Option<String> = None;
    if slot == "recovery" {
        if let Some(path) = &chosen {
            match std::fs::read(path) {
                Ok(bytes) if bytes.len() > crate::recovery::RECOVERY_MAX_BYTES => {
                    let message = format!(
                        "恢复包超过 {} KiB，没有读取。",
                        crate::recovery::RECOVERY_MAX_BYTES / 1024
                    );
                    if let Some(o) = st.as_object_mut() {
                        o.insert("ok".to_string(), serde_json::Value::Bool(false));
                        o.insert("error".to_string(), serde_json::Value::String(message.clone()));
                        o.insert("message".to_string(), serde_json::Value::String(message));
                    }
                    return st.to_string();
                }
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(text) => recovery_text = Some(text),
                    Err(_) => {
                        let message = "这个恢复包不是 UTF-8 文本。".to_string();
                        if let Some(o) = st.as_object_mut() {
                            o.insert("ok".to_string(), serde_json::Value::Bool(false));
                            o.insert("error".to_string(), serde_json::Value::String(message.clone()));
                            o.insert("message".to_string(), serde_json::Value::String(message));
                        }
                        return st.to_string();
                    }
                },
                Err(error) => {
                    let message = format!("读不了这个恢复包：{path}（{error}）");
                    if let Some(o) = st.as_object_mut() {
                        o.insert("ok".to_string(), serde_json::Value::Bool(false));
                        o.insert("error".to_string(), serde_json::Value::String(message.clone()));
                        o.insert("message".to_string(), serde_json::Value::String(message));
                    }
                    return st.to_string();
                }
            }
        }
    }
    let file_pick = match picked {
        Ok(Some(path)) => {
            let mut value = serde_json::json!({
                "pickId": pick_id, "slot": slot, "path": path,
                "source": "picker", "cancelled": false
            });
            if let Some(text) = recovery_text {
                if let Some(object) = value.as_object_mut() {
                    object.insert("text".to_string(), serde_json::Value::String(text));
                }
            }
            value
        }
        Ok(None) => serde_json::json!({
            "pickId": pick_id, "slot": slot, "source": "picker", "cancelled": true
        }),
        Err(e) => {
            if let Some(o) = st.as_object_mut() {
                o.insert("ok".to_string(), serde_json::Value::Bool(false));
                o.insert("error".to_string(), serde_json::Value::String(e.clone()));
                o.insert("message".to_string(), serde_json::Value::String(e));
            }
            return st.to_string();
        }
    };
    if let Some(o) = st.as_object_mut() {
        o.insert("filePick".to_string(), file_pick);
    }
    // 选的是**引擎程序**：选完就地验一遍并写进配置（与 `set-engine` 命令共用
    // `ipc::apply_engine_choice`）。页面只发一条命令，不必自己拆成两步——
    // 「对话框里选通了、配置却没写」正是这一轮要补的洞。
    if slot == "engine" {
        if let Some(path) = chosen {
            match ipc::apply_engine_choice(ctx, &path, probe) {
                Ok((binary, version)) => {
                    if let Some(o) = st.as_object_mut() {
                        o.insert("ok".to_string(), serde_json::Value::Bool(true));
                        o.insert(
                            "message".to_string(),
                            serde_json::Value::String(format!("已选用引擎：{version}")),
                        );
                        o.insert(
                            "engineSet".to_string(),
                            serde_json::json!({
                                "Binary": binary, "Version": version,
                                "Message": format!("已选用引擎：{version}"),
                            }),
                        );
                    }
                }
                Err(e) => {
                    if let Some(o) = st.as_object_mut() {
                        o.insert("ok".to_string(), serde_json::Value::Bool(false));
                        o.insert("error".to_string(), serde_json::Value::String(e.clone()));
                        o.insert("message".to_string(), serde_json::Value::String(e.clone()));
                        o.insert(
                            "engineSet".to_string(),
                            serde_json::json!({ "Binary": "", "Version": "", "Message": e }),
                        );
                    }
                }
            }
        }
    }
    st.to_string()
}

fn handle_ui_pick_file(ctx: &ipc::Ctx, raw: &str) -> String {
    handle_ui_pick_file_with(ctx, raw, |slot| ui::pick_file(slot))
}

/// 「另存为」：页面只给槽位、内容与建议文件名，路径由系统对话框决定。
///
/// 与 `pick-file` 同一条规矩：**回包是整份状态 + `fileSave`**，不走
/// `merge_ui_command_reply`。所以 `fileSave` 不必进 `UI_REPLY_KEYS`。
fn handle_ui_save_file_with<F>(ctx: &ipc::Ctx, raw: &str, saver: F) -> String
where
    F: Fn(&str, &str, &str) -> Result<Option<String>, String>,
{
    let value = serde_json::from_str::<serde_json::Value>(raw).unwrap_or(serde_json::Value::Null);
    let slot = value
        .get("slot")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let text = value
        .get("text")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let suggested = value
        .get("suggestedName")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("SpiderVPN-management.tcrecovery");
    let mut st = status_state(ctx);
    if slot != "recovery" {
        let message = "这个保存槽位不支持。".to_string();
        if let Some(object) = st.as_object_mut() {
            object.insert("ok".to_string(), serde_json::Value::Bool(false));
            object.insert("error".to_string(), serde_json::Value::String(message.clone()));
            object.insert("message".to_string(), serde_json::Value::String(message));
        }
        return st.to_string();
    }
    if text.is_empty() {
        let message = "没有可保存的内容。".to_string();
        if let Some(object) = st.as_object_mut() {
            object.insert("ok".to_string(), serde_json::Value::Bool(false));
            object.insert("error".to_string(), serde_json::Value::String(message.clone()));
            object.insert("message".to_string(), serde_json::Value::String(message));
        }
        return st.to_string();
    }
    if text.len() > crate::recovery::RECOVERY_MAX_BYTES {
        let message = format!(
            "恢复包超过 {} KiB，没有保存。",
            crate::recovery::RECOVERY_MAX_BYTES / 1024
        );
        if let Some(object) = st.as_object_mut() {
            object.insert("ok".to_string(), serde_json::Value::Bool(false));
            object.insert("error".to_string(), serde_json::Value::String(message.clone()));
            object.insert("message".to_string(), serde_json::Value::String(message));
        }
        return st.to_string();
    }
    let file_save = match saver(slot, text, suggested) {
        Ok(Some(path)) => serde_json::json!({
            "slot": slot, "path": path, "cancelled": false, "saved": true,
        }),
        Ok(None) => serde_json::json!({
            "slot": slot, "cancelled": true, "saved": false,
        }),
        Err(message) => {
            if let Some(object) = st.as_object_mut() {
                object.insert("ok".to_string(), serde_json::Value::Bool(false));
                object.insert("error".to_string(), serde_json::Value::String(message.clone()));
                object.insert("message".to_string(), serde_json::Value::String(message));
            }
            return st.to_string();
        }
    };
    if let Some(object) = st.as_object_mut() {
        object.insert("fileSave".to_string(), file_save);
    }
    st.to_string()
}

fn handle_ui_save_file(ctx: &ipc::Ctx, raw: &str) -> String {
    handle_ui_save_file_with(ctx, raw, |slot, text, suggested| {
        ui::save_file(slot, text, suggested)
    })
}

fn process_name_from_pick(path: &str) -> Result<String, String> {
    let path = std::path::Path::new(path);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| "所选文件没有可用的程序文件名".to_string())?;
    if path.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("exe")) != Some(true) {
        return Err("请选择 .exe 程序文件".to_string());
    }
    crate::config::SplitConfig::validate_process(name)?;
    Ok(name.to_string())
}

/// `pick-exe` 复用同一个系统文件选择器，但回包另带规则真正需要的进程名和目标组。
/// 选择器通过参数注入，自动化不会打开或伪造系统对话框。
///
/// 这里传 `picker("process")`：和「选引擎」共用 `.exe` 过滤器，但标题是「选择交易程序」，
/// 并且在独立线程上打开（见 `ui::pick_file` 的 `"process"` 分支）。
fn handle_ui_pick_exe_with<F>(ctx: &ipc::Ctx, raw: &str, picker: F) -> String
where
    F: Fn(&str) -> Result<Option<String>, String>,
{
    let target = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("target").and_then(|x| x.as_str()).map(str::to_string))
        .unwrap_or_else(|| "trade".to_string());
    let pick_id = format!(
        "pick-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    if !matches!(target.as_str(), "direct" | "trade" | "daily") {
        let mut st = status_state(ctx);
        if let Some(o) = st.as_object_mut() {
            o.insert("ok".to_string(), serde_json::Value::Bool(false));
            o.insert("error".to_string(), serde_json::json!("进程目标组不合法"));
            o.insert("message".to_string(), serde_json::json!("进程目标组不合法"));
        }
        return st.to_string();
    }
    // **先弹选择器，再算状态**：`status_state` 要读线路/部署/保护证据，放在对话框
    // 前面会让「点浏览」先卡几秒才看见窗口。选择器本身也在独立线程上打开（ui.rs）。
    let file_pick = match picker("process") {
        Ok(Some(path)) => match process_name_from_pick(&path) {
            Ok(process_name) => serde_json::json!({
                "pickId": pick_id, "slot": "process", "target": target,
                "path": path, "processName": process_name,
                "source": "picker", "cancelled": false
            }),
            Err(e) => {
                let mut st = status_state(ctx);
                if let Some(o) = st.as_object_mut() {
                    o.insert("ok".to_string(), serde_json::Value::Bool(false));
                    o.insert("error".to_string(), serde_json::Value::String(e.clone()));
                    o.insert("message".to_string(), serde_json::Value::String(e));
                }
                return st.to_string();
            }
        },
        Ok(None) => serde_json::json!({
            "pickId": pick_id, "slot": "process", "target": target,
            "source": "picker", "cancelled": true
        }),
        Err(e) => {
            let mut st = status_state(ctx);
            if let Some(o) = st.as_object_mut() {
                o.insert("ok".to_string(), serde_json::Value::Bool(false));
                o.insert("error".to_string(), serde_json::Value::String(e.clone()));
                o.insert("message".to_string(), serde_json::Value::String(e));
            }
            return st.to_string();
        }
    };
    let mut st = status_state(ctx);
    if let Some(o) = st.as_object_mut() {
        o.insert("filePick".to_string(), file_pick);
    }
    st.to_string()
}

fn handle_ui_pick_exe(ctx: &ipc::Ctx, raw: &str) -> String {
    handle_ui_pick_exe_with(ctx, raw, |slot| ui::pick_file(slot))
}

fn handle_ui_inspect_import(ctx: &ipc::Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let field = |k: &str| {
        parsed
            .as_ref()
            .and_then(|v| v.get(k))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let problems = inspect_import_problems(&field("profile"), &field("engine"));
    let mut st = status_state(ctx);
    if let Some(o) = st.as_object_mut() {
        o.insert("problems".to_string(), serde_json::Value::Array(problems));
        o.insert("inspectDone".to_string(), serde_json::Value::Bool(true));
    }
    st.to_string()
}

/// 处理界面发来的设置请求（两个复选框），返回新的状态 JSON。
///
/// 与导入同理抽成函数：点一下复选框就要「落盘 + 同步 Run 键 + 回推状态」，
/// 这段最该被测试盯住，而 wry 的闭包进不了单测。
fn handle_ui_settings(root: &std::path::Path, ctx: &mut ipc::Ctx, raw: &str) -> String {
    let exe = std::env::current_exe().unwrap_or_default();
    handle_ui_settings_in(root, ctx, raw, &autostart::key_path(), &exe)
}

/// 可测的核：Run 键路径与 exe 路径都由调用方给，测试才能指到临时键上。
fn handle_ui_settings_in(
    root: &std::path::Path,
    ctx: &mut ipc::Ctx,
    raw: &str,
    run_key: &str,
    exe: &std::path::Path,
) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let flag = |k: &str, cur: bool| -> bool {
        parsed.as_ref().and_then(|v| v.get(k)).and_then(|x| x.as_bool()).unwrap_or(cur)
    };

    let mut st = status_state(ctx);
    let note = match ctx.cfg.clone() {
        None => "未配置线路：请先导入线路再改设置".to_string(),
        Some(mut nc) => {
            let was_auto_start = nc.auto_start;
            nc.auto_start = flag("autoStart", nc.auto_start);
            nc.auto_connect = flag("autoConnect", nc.auto_connect);
            // 线路变差提醒：只影响首页那条横幅与标题语气，不动测量本身。
            nc.quality_warning = flag("qualityWarning", nc.quality_warning);
            // 自动记住首次服务器身份：只影响「第一次接触一台服务器」那一支
            // （`servercmd::setup`），已有记录与指纹变化都不受它影响。
            nc.auto_trust_first_connection =
                flag("autoTrust", nc.auto_trust_first_connection);
            // 关窗行为也在这里改：界面即时生效，不动注册表。
            nc.close_to_tray = flag("closeToTray", nc.close_to_tray);
            // 只有自启项真的变了才动注册表：点「自动连接」不该顺手重写 Run 键。
            let key_r = if nc.auto_start == was_auto_start {
                Ok(())
            } else if nc.auto_start {
                autostart::enable_in(run_key, &autostart::launcher_target(exe))
            } else {
                autostart::disable_in(run_key)
            };
            let save_r = config::save_with_origin(
                &root.join(config::DEFAULT_PATH),
                &nc,
                &ctx.origin(None),
            );
            match (key_r, save_r) {
                (Ok(()), Ok(())) => {
                    ctx.cfg = Some(nc);
                    st = status_state(ctx);
                    "设置已保存".to_string()
                }
                (Err(e), Ok(())) => {
                    // 配置存下了、自启项没改成：界面上必须看得见这句。
                    ctx.cfg = Some(nc);
                    st = status_state(ctx);
                    format!("设置已保存，但同步自启项失败：{e}")
                }
                (_, Err(e)) => format!("设置保存失败：{e}"),
            }
        }
    };
    if let Some(o) = st.as_object_mut() {
        o.insert("detail".to_string(), serde_json::Value::String(note));
    }
    st.to_string()
}

/// 界面要的状态：与命名管道 `status` 命令同源。
fn status_state(ctx: &ipc::Ctx) -> serde_json::Value {
    serde_json::from_str(&ipc::handle_line_with(r#"{"cmd":"status"}"#, ctx))
        .unwrap_or_else(|_| fault_state())
}

/// 状态投影不可用时的兜底：宁可显示「需要处理」，也不要给用户一张空白卡片。
fn fault_state() -> serde_json::Value {
    serde_json::json!({
        "ok": false,
        "state": "Fault",
        "title": "状态不可用",
        "detail": "状态投影失败，请查看诊断信息。",
        "action": "None",
        "enabled": false
    })
}

/// 把控制台输出代码页切到 UTF-8。失败无所谓（重定向到文件时本来就没代码页）。
fn set_console_utf8() {
    const CP_UTF8: u32 = 65001;
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleOutputCP(code_page: u32) -> i32;
        fn SetConsoleCP(code_page: u32) -> i32;
    }
    unsafe {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
    }
}



/// 导入时「端口被占」的错误前缀。外层据此把退出码映射成 `CONFLICT`（换端口是用户决策），
/// 其余导入失败仍是 `CONFIG`。前缀会原样显示，所以它就是给人看的那句话。
const IMPORT_CONFLICT_PREFIX: &str = "端口冲突：";

/// 导入失败的唯一出口：返回（退出码，给人看的那句话）。
///
/// CLI 打到 stderr、界面放进 `.msg`，两处**必须是同一个字符串**——同一个失败在两边
/// 措辞不同，排障时对不上，用户也会以为是两个问题。所以两侧都不许再加前缀或缩进。
fn import_failure(err: &str) -> (u8, String) {
    let code = if err.starts_with(IMPORT_CONFLICT_PREFIX) {
        exit::CONFLICT
    } else {
        exit::CONFIG
    };
    (code, err.to_string())
}

/// 带值的参数表：(flag, 需要的值个数, 用法, 例子)。**这里是唯一来源**——
/// 加新命令时必须同时加进来，否则漏值会掉进 GUI。
const VALUED_ARGS: &[(&str, usize, &str, &str)] = &[
    ("--import", 1, "--import <线路文件路径>", "--import C:////path////dual-mode.json --engine C:////path////sing-box.exe"),
    ("--engine", 1, "--engine <引擎 exe 路径>", "--engine C:////path////sing-box.exe"),
    ("--port", 1, "--port <1..=65532>", "--port 17890"),
    ("--line-name", 1, "--line-name <线路名>", "--line-name 示例线路"),
    ("--set-line", 3, "--set-line <id> <名称> <host:port>", "--set-line L1 示例线路 127.0.0.1:17890"),
    ("--use", 1, "--use <线路 id 或名字>", "--use 示例线路"),
    ("--set-transport", 1, "--set-transport udp|tcp|auto", "--set-transport tcp"),
    ("--remove-line", 1, "--remove-line <线路 id 或名字>", "--remove-line 备用线路A"),
    ("--set-autostart", 1, "--set-autostart on|off", "--set-autostart on"),
    ("--set-autoconnect", 1, "--set-autoconnect on|off", "--set-autoconnect on"),
    ("--set-closetotray", 1, "--set-closetotray on|off", "--set-closetotray on"),
    ("--split-add-process", 1, "--split-add-process <进程名，例如 TDXW.exe>", "--split-add-process TDXW.exe"),
    ("--split-add-domain", 1, "--split-add-domain <域名，例如 qq.com>", "--split-add-domain qq.com"),
    ("--split-remove-process", 1, "--split-remove-process <进程名>", "--split-remove-process TDXW.exe"),
    ("--split-remove-domain", 1, "--split-remove-domain <域名>", "--split-remove-domain qq.com"),
    ("--to", 1, "--to direct|trade|daily", "--split-add-process TDXW.exe --to trade"),
    ("--exit-set", 2, "--exit-set trade|daily <成员>", "--exit-set daily direct"),
    ("--provider-add", 4, "--provider-add <kind> <名称> <目录> <端口> [逗号分隔域名]", "--provider-add clashverge Clash C:\\... 7890 a.example.com"),
    ("--provider-remove", 1, "--provider-remove <槽位 1-4>", "--provider-remove 1"),
    // 部署（M5）：先只做**只读**的环境检查。密码走标准输入，不放进命令行。
    ("--server-inspect", 1, "--server-inspect <用户名@主机[:端口]>", "--server-inspect root@203.0.113.10"),
    ("--server-trust", 1, "--server-trust <用户名@主机[:端口]> --fingerprint SHA256:…", "--server-trust root@203.0.113.10 --fingerprint SHA256:abc…"),
    ("--server-forget", 1, "--server-forget <用户名@主机[:端口]>", "--server-forget root@203.0.113.10"),
    ("--server-deploy", 1, "--server-deploy <用户名@主机[:端口]>（只打印计划）", "--server-deploy root@203.0.113.10"),
    ("--server-deploy-apply", 1, "--server-deploy-apply <用户名@主机[:端口]>（真执行）", "--server-deploy-apply root@203.0.113.10"),
    ("--server-join", 1, "--server-join <用户名@主机[:端口]>（把本机接进去）", "--server-join root@203.0.113.10"),
    ("--server-setup", 1, "--server-setup <用户名@主机[:端口]>（一键：部署并接入本机）", "--server-setup root@203.0.113.10"),
    ("--server-transport", 1, "--server-transport <用户名@主机[:端口]>（兼容连接预览）", "--server-transport root@203.0.113.10"),
    ("--server-transport-apply", 1, "--server-transport-apply <用户名@主机[:端口]>（装兼容连接）", "--server-transport-apply root@203.0.113.10"),
    ("--server-transport-export", 1, "--server-transport-export <用户名@主机[:端口]>（只读导出身份备份）", "--server-transport-export root@203.0.113.10"),
    ("--server-transport-restore", 1, "--server-transport-restore <备份文件>（只打印恢复计划）", "--server-transport-restore C:\\transport.json"),
    ("--server-transport-restore-apply", 1, "--server-transport-restore-apply <备份文件>（真写入，覆盖需 --force）", "--server-transport-restore-apply C:\\transport.json --force"),
    // 邀请服务（A1）：管理身份、邀请签发、状态与作废都在服务器上完成。
    ("--invite-init", 1, "--invite-init <用户名@主机[:端口]>（初始化邀请服务）", "--invite-init root@203.0.113.10"),
    ("--invite-create", 1, "--invite-create <用户名@主机[:端口]> [--lifetime 秒] [--device 名字]", "--invite-create root@203.0.113.10 --lifetime 1800"),
    ("--invite-status", 1, "--invite-status <用户名@主机[:端口]> --invite-id <id>", "--invite-status root@203.0.113.10 --invite-id 9f1c2a44-…"),
    ("--invite-cancel", 1, "--invite-cancel <用户名@主机[:端口]> --invite-id <id>", "--invite-cancel root@203.0.113.10 --invite-id 9f1c2a44-…"),
    ("--invite-id", 1, "--invite-id <邀请 id>（配合 --invite-status / --invite-cancel）", "见 --invite-create 的输出"),
    ("--invite-check", 1, "--invite-check <邀请码>（去服务器读一次并验签，只读）", "--invite-check TCI1.eyJ2Ijox…"),
    ("--lifetime", 1, "--lifetime <秒，600–86400>（默认 1800）", "--invite-create root@1.2.3.4 --lifetime 7200"),
    ("--device", 1, "--device <新电脑的名称>（默认「新电脑」）", "--invite-create root@1.2.3.4 --device 交易电脑2"),
    ("--backup", 1, "--backup <文件>（导出路径；默认写到 数据根\\exports）", "--backup C:\\transport.json"),
    ("--fingerprint", 1, "--fingerprint SHA256:…（首次连接确认用）", "--server-inspect root@1.2.3.4 --fingerprint SHA256:abc…"),
    // 内部提权子进程：由本程序自己起，用户不需要手工输入。放在这里是为了让参数校验认识它。
    ("--install-seal", 1, "--install-seal <安装目录>（内部安装权限阶段）", "由安装器以管理员权限调用"),
    ("--uninstall-preflight", 1, "--uninstall-preflight <安装目录> [--keep-guard]（内部卸载安全阶段）", "只由已安装的 SpiderVPN 卸载器调用"),
    ("--uninstall-owns-shortcut", 2, "--uninstall-owns-shortcut <快捷方式> <安装目录>（内部归属检查）", "只由已安装的 SpiderVPN 卸载器调用"),
    ("--guard-apply", 2, "--guard-apply <request.json> <response.json>（内部提权子进程）", "不由用户手工执行"),
];

/// 不带值的开关。
const FLAG_ARGS: &[&str] = &[
    // P0-13：名单内交易程序正在运行时，显式安装/同步默认被拒；这个开关表示
    // 「我看过提示，仍要启用」。它与界面确认框里的「仍要启用」是同一条判据。
    "--acknowledge-running",
    "--apply",
    "--connect",
    "--diagnose",
    "--disconnect",
    "--headless",
    "--keep-guard",
    "--help",
    "--history",
    "--lines",
    "--ping",
    "--plan",
    "--restore",
    "--restore-apply",
    "--split-list",
    "--exits",
    "--force",
    "--guard-status",
    "--guard-install",
    "--guard-sync",
    "--guard-remove",
    "--guard-verify",
    "--providers",
    "--provider-discover",
    "--status",
    "--tun",
    // A7：把安装程序生成的开始菜单快捷方式复制到桌面（不碰 COM、不碰配置）。
    "--desktop-shortcut",
];

/// 出口观测的一句人话（CLI）。归属判不了时如实说「无法归属」——那不是失败，
/// 只说明线路文件里没有可比的公网字面 IP（例如服务器写的是域名）。
fn exit_probe_line(rec: &exit_probe::Record) -> String {
    let who = if rec.attributed {
        "与本线路服务器一致"
    } else {
        "无法归属到本线路服务器"
    };
    format!("出口：{}（{}，由 {} 观测）", rec.ip, who, rec.endpoint)
}

/// 交易保护投影的**逐行文本**。抽出来是为了能被单测逐字断言：
/// 这几行是用户判断「装没装上」的第一手依据，改一个字都是新事实。
fn guard_status_lines(st: &guard::GuardStatus) -> Vec<String> {
    let mut lines = vec![
        format!("  交易保护  ：{}", st.summary),
        format!(
            "  状态      ：{}（{}）",
            st.state.as_str(),
            st.reason.as_str()
        ),
        format!("  参与程序  ：{}", st.trade_program_count),
        format!("  名单进程  ：{}", st.trade_program_listed),
        format!(
            "  证据时间  ：{}",
            st.evidence_at.as_deref().unwrap_or("尚未核验")
        ),
        format!(
            "  证据时龄  ：{}",
            if st.age_text.is_empty() { "尚未核验" } else { &st.age_text }
        ),
        format!("  待核验    ：{}", st.verify_pending.as_str()),
        format!(
            "  证据存储  ：{}",
            if st.store_kind.is_empty() { "未建立" } else { &st.store_kind }
        ),
    ];
    // R25-1：管理员进程看到的 `EvidenceUnprotected` 是**视角**问题，不是安装失败。
    // 判定与三态都不动，只在末尾补一句实话；普通权限进程永远不会走到这里，
    // 所以行数在有/没有这句话时不同，是有意为之（测试逐字钉住）。
    if let Some(note) = st.perspective_note.as_deref() {
        lines.push(format!("  提示      ：{note}"));
    }
    lines
}

fn print_guard_status(st: &guard::GuardStatus) {
    for line in guard_status_lines(st) {
        println!("{line}");
    }
}

/// 交易保护命令失败的退出码：拒绝授权/旧版在跑/WFP 未就绪是环境问题；
/// 名单或路径缺失是配置问题；并发占用是冲突。
fn guard_failure_code(message: &str) -> u8 {
    if message.contains("另一个交易保护操作") {
        exit::CONFLICT
    } else if message.contains("找不到配置") || message.contains("找不到可执行文件") {
        exit::CONFIG
    } else {
        exit::ENVIRONMENT
    }
}

/// 退出码说明表：与 `mod exit` 同源，`--help` 直接遍历它。
/// 加一档就在这里加一行——文档里另写一份清单，迟早与代码对不上。
const EXIT_CODES: &[(u8, &str)] = &[
    (exit::OK, "成功"),
    (exit::INTERNAL, "未分类内部错误（没预料到的问题，不猜类别）"),
    (exit::USAGE, "用法错误：参数缺失、取值非法、未知开关"),
    (exit::CONFIG, "配置/文件类，需人工干预（改文件、重新导入线路）"),
    (exit::ENVIRONMENT, "环境不支持或未就绪（未连接、权限不足、旧版在跑）"),
    (exit::NETWORK, "网络类，可重试"),
    (exit::CONFLICT, "冲突，需用户决策（同名线路、已有实例在运行）"),
];

/// `--help` 的输出：把两张表原样摊开。**不手写第二份清单**——
/// 帮助里少了某条命令，比没有帮助更误导人。
fn print_usage() {
    println!("  SpiderVPN · 不带参数打开界面");
    println!();
    println!("  带值的命令：");
    for (_, _, usage, example) in VALUED_ARGS {
        println!("    {usage}");
        println!("        例：{example}");
    }
    println!();
    println!("  开关与只读命令：");
    println!("    {}", FLAG_ARGS.join("  "));
    println!();
    println!("  操作记录：--history（界面也有「记录」页，读的是同一个文件）");
    println!();
    println!("  退出码：");
    for (code, text) in EXIT_CODES {
        println!("    {code}  {text}");
    }
    println!("    旧版曾用 7（未连接）与 12（配置类）；目标版起不再返回这两个值，");
    println!("    按旧值判断的脚本需要改成 4（未连接）与 3（配置类）。");
}

/// 校验命令行参数：只做三件事——缺值、未知参数、多余参数。
/// 不带任何参数 = 正常打开界面（保持原样）；带了参数就必须是认识的、且值给全。
fn validate_argv(argv: &[String]) -> Result<(), String> {
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !a.starts_with("--") {
            i += 1; // 这是某个参数的值，已在上一步跳过
            continue;
        }
        if let Some((_, need, usage, example)) = VALUED_ARGS.iter().find(|(f, _, _, _)| *f == a) {
            let take: Vec<&String> = argv.iter().skip(i + 1).take(*need).collect();
            // 值不够，或者"值"其实是另一个参数（`--use --status` 这种）→ 都算缺值
            let bad = take.len() < *need || take.iter().any(|v| v.starts_with("--"));
            if bad {
                return Err(format!("需要参数：{usage}\n用法：{example}"));
            }
            i += 1 + *need;
            continue;
        }
        if FLAG_ARGS.contains(&a) {
            if let Some(next) = argv.get(i + 1) {
                if !next.starts_with("--") {
                    return Err(format!("多余参数：{next}（{a} 不需要参数）"));
                }
            }
            i += 1;
            continue;
        }
        return Err(format!("未知参数：{a}\n不带参数运行可打开界面"));
    }
    Ok(())
}

/// 启动期致命错误时的用户提示。命令行模式只打印（有控制台可看），
/// 双击启动（无参数）时弹原生消息框——GUI 子系统没有控制台，只打印等于"点了没反应"。
///
/// `alert` 注入出来是为了能在单测里替换成记录器：真的 MessageBox 会把测试卡住等人点。
fn report_fatal_config_error(
    cfg_path: &std::path::Path,
    err: &config::ConfigError,
    gui: bool,
    alert: &dyn Fn(&str, &str),
) -> i32 {
    let body = format!(
        "配置文件读取失败：{err}\n路径：{}\n处理：把该文件改名后重新导入线路，或从 backup 目录恢复。",
        cfg_path.display()
    );
    println!("  配置不可用：{}", err);
    if gui {
        alert("SpiderVPN 无法启动", &body);
    }
    exit::CONFIG as i32
}

/// 真的弹一个原生消息框（`user32!MessageBoxW` 直接链，不引依赖）。
fn message_box(title: &str, body: &str) {
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(hwnd: isize, text: *const u16, caption: *const u16, utype: u32) -> i32;
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    let t = wide(title);
    let b = wide(body);
    // MB_OK | MB_ICONERROR | MB_TOPMOST
    unsafe {
        MessageBoxW(0, b.as_ptr(), t.as_ptr(), 0x0000_0001 | 0x0000_0010 | 0x0004_0000);
    }
}

/// 打印当前分流规则。空规则要说清「全部走节点」——空列表不解释会被当成"没生效"。
fn print_split(split: &config::SplitConfig) {
    if split.is_empty() {
        println!("  分流规则：（空）全部流量走日常出口（默认直连）");
        return;
    }
    println!("  分流规则（按目标出口）：");
    for (kind, list) in [("进程", &split.processes), ("域名", &split.domains)] {
        for e in list {
            println!("    {kind}  {}  → {}", e.value(), e.target().label());
        }
    }
}

/// 读 `--to direct|trade|daily`（可省略，缺省 direct）。
fn split_target_arg() -> Result<config::SplitTarget, String> {
    match arg_values("--to", 1) {
        None => Ok(config::SplitTarget::Direct),
        Some(v) => config::SplitTarget::from_name(&v[0]).ok_or_else(|| {
            format!("--to 只支持 direct / trade / daily（收到：{}）", v[0].trim())
        }),
    }
}

/// 分流的**覆盖范围**提示：只有系统代理模式、且**配了任意规则**（进程或域名）时才说。
///
/// 进程规则在两种模式下都**生效**（实测见 tests/README：proxy 模式下 curl 命中规则后出口等于直连基线）。
/// 这里要回答的是另一个更常见的问题：为什么配了分流，某个程序还是照旧——因为它根本不经过我们。
fn print_split_scope_hint(cfg: &config::AppConfig, root: &std::path::Path) {
    // 用**选中线路的实际模式**，不是全局字段：混着导过 proxy/TUN 线路时两者会不一致，
    // 而这句提示的意义恰恰是"你现在只有系统代理、别以为全覆盖了"（两个方向都会误判）。
    let actual = cfg
        .current_engine_path(root)
        .and_then(|p| engine_config::actual_mode(&p))
        .unwrap_or(cfg.mode);
    if actual != config::Mode::Proxy || cfg.split.is_empty() {
        return;
    }
    println!("  系统代理模式下，只有经过本程序的流量才受分流规则影响；");
    println!("  不读系统代理的程序（多数桌面交易软件属于这类）本来就不经过本程序。");
    println!("  要覆盖全部程序，请用 TUN 模式。");
}

/// 新增或更新一条线路：id 已存在就覆盖（沿用 id），否则追加。返回是否走了「更新」。
fn upsert_line(cfg: &mut config::AppConfig, line: config::LineConfig) -> bool {
    if let Some(existing) = cfg.lines.iter_mut().find(|l| l.id == line.id) {
        existing.name = line.name;
        existing.proxy_endpoint = line.proxy_endpoint;
        // 连接方式也跟着走：调用方已经算好了"该是哪一个"（文件形状 / 保留原选择）。
        existing.transport = line.transport;
        // 「已验证的依据」同样跟着走：重导入是一份新参数，调用方给的就是它算好的值
        // （`None` = 旧依据作废重验）。不搬这一行，旧依据就会留在新参数上——那是假话。
        existing.verified_transport = line.verified_transport;
        true
    } else {
        cfg.lines.push(line);
        false
    }
}

/// 找不到线路时把候选列出来——只报「找不到」等于让用户猜。
fn print_line_candidates(cfg: &config::AppConfig) {
    if cfg.lines.is_empty() {
        println!("  当前没有任何线路，请先导入或用 --set-line 写入一条。");
        return;
    }
    println!("  可选线路：");
    for line in &cfg.lines {
        println!("    {}  {}", line.name, line.proxy_endpoint);
    }
}

/// 「缺什么给什么码」的唯一判断（`--connect` / `--plan` / `--apply` / `--headless` 共用）：
/// - **配置文件不存在** → 8（配置不完整，不是「缺线路」，文案也要说准）
/// - **配置在但没有可用线路**（`lines` 为空 / selected 失效且无回退） → 13
///
/// 引擎缺失由需要它的命令（连接）另行判断，也给 8；`--plan` 不启动引擎，不因它被拦。
fn config_gate(cfg: Option<&config::AppConfig>, what: &str) -> Result<(), (u8, String)> {
    match cfg {
        // 两种「没得连」都归 CONFIG：缺文件要人导入/恢复，缺当前线路要人指定，
        // 都不是网络问题、也都不是用法错误。
        None => Err((exit::CONFIG, format!("找不到配置文件（config.json），无法{what}。请先导入线路。"))),
        Some(c) if c.current_line().is_none() => {
            Err((exit::CONFIG, format!("未配置线路，无法{what}。请先导入线路或用 --set-line 写入一条。")))
        }
        Some(_) => Ok(()),
    }
}

/// 引擎是否「没配」：没有 engine 段，或 binary 是空白，都算没配。
fn engine_missing(cfg: Option<&config::AppConfig>) -> bool {
    cfg.and_then(|c| c.engine.as_ref())
        .map(|e| e.binary.trim().is_empty())
        .unwrap_or(true)
}

/// 取当前线路的端点。调用前必须先过 `config_gate`（它保证线路存在）。
fn current_endpoint(cfg: Option<&config::AppConfig>) -> String {
    cfg.and_then(|c| c.current_line())
        .map(|l| l.proxy_endpoint.clone())
        .unwrap_or_default()
}

/// 只读命令：**一律不写用户配置**（schema 1 只在内存里迁成多线路）。
/// `--headless` 也在里面：CI 冒烟会反复跑它，跑一次就改用户配置是不可接受的。
/// 交易保护命令同样不迁移配置；其中 install/sync/remove 会写 WFP 与证据，但不写 config.json。
const READONLY_COMMANDS: [&str; 14] = [
    "--status", "--lines", "--plan", "--restore", "--headless", "--diagnose", "--history",
    "--server-inspect", "--guard-status", "--guard-install", "--guard-sync", "--guard-remove",
    "--guard-verify",
    // 只写桌面上的一个 .lnk，不碰 config.json：不该顺带触发 schema 迁移落盘。
    "--desktop-shortcut",
];

/// 可与其他实例（界面开着）并存的只读命令：它们不接管代理、不写配置，读的是当前快照。
///
/// 与 `READONLY_COMMANDS` **不是一回事**：那个说的是「不写用户配置」，其中 `--restore` 会改代理，
/// 必须独占；这里说的是「不需要单实例锁」。两者重叠但语义不同，别合并。
const SHARED_READ_COMMANDS: [&str; 11] = ["--status", "--lines", "--exits", "--plan", "--headless", "--providers", "--provider-discover", "--diagnose", "--history", "--guard-status", "--desktop-shortcut"];

/// 这次命令行是不是「可与界面并存」的只读命令。
fn is_shared_read(args: &[String]) -> bool {
    SHARED_READ_COMMANDS.iter().any(|flag| args.iter().any(|a| a == flag))
}

/// 「没配置就不许改设置」的统一说法（三个开关命令共用）。
const NO_CONFIG_FOR_SETTINGS: &str = "未配置线路，无法修改设置。请先导入线路或用 --set-line。";

/// 从标准输入读一行密码。
///
/// **只去掉行尾的 CR/LF**：密码可以以空格结尾，`trim()` 会把它悄悄改掉，
/// 然后用户看到的是「密码不对」而永远查不出原因。
fn read_password_stdin() -> String {
    let mut password = String::new();
    if std::io::stdin().read_line(&mut password).is_err() {
        return String::new();
    }
    password.trim_end_matches(|c| c == '\r' || c == '\n').to_string()
}

/// `on|off` → bool。别的写法一律报错并给用法：这两个开关改的是开机行为，不能靠猜。
fn parse_on_off(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

/// 开关的中文说法：`--status`、命令行确认、界面复选框用同一个词。
fn on_off(v: bool) -> &'static str {
    if v {
        "开"
    } else {
        "关"
    }
}

/// 记一条「上次退出没干完的事」到数据根。窗口关掉之后没人看得见 stderr，只能靠下次启动回显。
fn note_startup_issue(root: &std::path::Path, msg: &str) {
    let p = root.join("last-cleanup-error.txt");
    if let Err(e) = std::fs::write(&p, msg) {
        eprintln!("（连这条记录也写不进去：{e}）");
    }
}

/// 取走上次留下的记录（只回显一次，取完就删，免得每次启动都念一遍旧账）。
fn take_startup_issue(root: &std::path::Path) -> Option<String> {
    let p = root.join("last-cleanup-error.txt");
    let text = std::fs::read_to_string(&p).ok()?;
    let _ = std::fs::remove_file(&p);
    let t = text.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// 往状态 JSON 里塞一个布尔字段。解析不出来就原样返回——状态投影坏了不该让界面更坏。
fn inject_bool(state: String, key: &str, v: bool) -> String {
    match serde_json::from_str::<serde_json::Value>(&state) {
        Ok(mut val) => {
            if let Some(o) = val.as_object_mut() {
                o.insert(key.to_string(), serde_json::Value::Bool(v));
            }
            val.to_string()
        }
        Err(_) => state,
    }
}


/// 一键部署（命令行入口）：检查 → 装服务端 → 装兼容连接 → 把本机接进去 → 登记线路。
///
/// 编排本身在 [`servercmd::setup`]，与界面走同一段；这里只负责「命令行特有的两件事」：
/// 第一次连新机器时把指纹打给人看（并且**不先问密码**），以及把进度打到 stdout。
fn run_server_setup(
    data_root: &std::path::Path,
    spec_text: &str,
    fingerprint: Option<&str>,
) -> ExitCode {
    let known = ssh::Target::parse(spec_text)
        .ok()
        .and_then(|target| serverstore::find_by_target(data_root, &target).ok().flatten())
        .is_some();

    // 第一次连这台机器、又没给指纹：只读一次主机公钥就退出，**连密码都不问**。
    // 先问密码再去连，等于让用户为一个根本不会发出去的凭据白输一遍。
    if !known && fingerprint.is_none() {
        let Ok(target) = ssh::Target::parse(spec_text) else {
            println!("  {spec_text} 需要写成 用户名@主机[:端口]，例如 root@203.0.113.10");
            return ExitCode::from(exit::USAGE);
        };
        println!("  第一次连接 {}:{}，先读取主机指纹。", target.host, target.port);
        return match ssh::probe_host_key(&target, std::time::Duration::from_secs(15)) {
            Ok(actual) => {
                println!("  这台服务器的主机指纹：");
                println!("    {actual}");
                println!("  请与服务器管理员核对，确认后重新运行：");
                println!("    --server-setup {spec_text} --fingerprint {actual}");
                println!("  （这一次没有发送密码，也没有改动服务器。）");
                ExitCode::from(exit::CONFLICT)
            }
            Err(error @ (ssh::Error::Connect(_) | ssh::Error::Timeout)) => {
                println!("  {error}");
                ExitCode::from(exit::NETWORK)
            }
            Err(error) => {
                println!("  {error}");
                ExitCode::from(exit::INTERNAL)
            }
        };
    }

    // 只有「第一次保存凭据」才需要密码；已有记录时走 DPAPI 里那份。
    let password = if known {
        String::new()
    } else {
        let password = read_password_stdin();
        if password.is_empty() {
            println!(
                "  需要从标准输入提供密码：echo '密码' | spidervpn --server-setup {spec_text} --fingerprint <指纹>"
            );
            return ExitCode::from(exit::USAGE);
        }
        password
    };

    let origin = events::Origin::cli();
    let mut progress = |line: &str| println!("  {line}");
    // 与界面共用同一个设置项（读不到配置就按默认：自动记住开）。
    let auto_trust = config::load_readonly(&data_root.join(config::DEFAULT_PATH))
        .ok()
        .flatten()
        .map(|c| c.auto_trust_first_connection)
        .unwrap_or(true);
    match servercmd::setup(
        data_root,
        spec_text,
        fingerprint,
        if password.is_empty() { None } else { Some(&password) },
        auto_trust,
        &origin,
        &mut progress,
    ) {
        Ok(report) => {
            println!("  完成：");
            println!(
                "    服务器  ：{}（接口 {}，UDP {}）",
                report.address, report.interface, report.udp_port
            );
            if let Some(item) = &report.transport {
                println!(
                    "    兼容连接：TCP {}（REALITY，握手域名 {}）",
                    item.port, item.server_name
                );
            }
            for line in &report.lines {
                println!("    线路    ：{}", line.describe());
            }
            // 自动记住的指纹 / 复用了已有部署：这两句以前被算出来就扔了，
            // 于是命令行报「完成」时，用户不知道刚才那次没核对过指纹。
            for notice in report.notices() {
                println!("    {notice}");
            }
            println!("  下一步：在界面上选一条线路连接，或运行 --connect。");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("  {}", error.message);
            ExitCode::from(error.code)
        }
    }
}

/// 取「这条服务器记录 + 解开它的密码」。
///
/// `--server-transport` / `--server-join` / `--server-setup` 三个命令共用：
/// 它们都要求「先 trust 过一次」。把这段抄三遍的话，将来改凭据格式就得改三处，
/// 而漏掉的那一处会以「密码错」的形式出现——最难查的一种。
/// 邀请服务（A1）的四个命令共用一个入口：都要「解析目标 → 取凭据 → 推导接口名 →
/// 装或调服务器脚本 → 落盘身份」，差别只在最后一步。
///
fn run_invite(data_root: &std::path::Path, spec_text: &str) -> u8 {
    let (record, password) = match server_credentials(data_root, spec_text) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let spec = deploy::Spec::for_record(&record.id);
    let host = record.host.trim().to_string();
    // 邀请码里的入口只收**规范写法**的 IPv4：域名会同时带进 DNS 这个可变因素，
    // 而「同一个地址有多种写法」会让指纹绑定失效。这条判断在连服务器之前做。
    let canonical = host
        .parse::<std::net::Ipv4Addr>()
        .map(|address| address.to_string())
        .unwrap_or_default();
    if canonical != host {
        println!("  邀请码里的入口必须是 IPv4 地址，服务器记录里写的是 {host}。");
        println!("  请先用 IPv4 重新保存这台服务器：--server-trust root@<IPv4> --fingerprint <指纹>。");
        return exit::CONFIG;
    }
    let endpoint = format!("{host}:18443");
    let target = record.target();
    let expected = record.fingerprint.as_str();
    let store = pairhost::identity_path(data_root, &record.id);
    let now = model::now_epoch_secs_u64() as i64;

    let install = |target: &ssh::Target| {
        pairhost::install(target, &password, Some(expected), &spec.interface, &endpoint)
    };

    if arg_values("--invite-init", 1).is_some() {
        return match install(&target) {
            Ok(identity) => match pairhost::save_identity(&store, &identity) {
                Ok(()) => {
                    println!("  邀请服务已就绪：{endpoint}");
                    println!("  管理身份  ：{}", identity.management_fingerprint);
                    println!("  证书指纹  ：{}", identity.tls_sha256);
                    // 「这次到底换上新脚本没有」必须说出来：旧服务器上页面会提示
                    // 「重新执行一次开启接收服务」，用户执行完得能看出那一步成没成，
                    // 否则只能反复点、反复猜。
                    println!("  服务脚本  ：{}", identity.script.label());
                    println!("  现在可以运行 --invite-create {spec_text} 生成邀请码。");
                    exit::OK
                }
                Err(message) => {
                    println!("  {message}");
                    exit::CONFIG
                }
            },
            Err(fault) => {
                println!("  {}", fault.message);
                fault.code
            }
        };
    }

    if arg_values("--invite-create", 1).is_some() {
        let lifetime = match arg_values("--lifetime", 1) {
            Some(values) => match values[0].trim().parse::<i64>() {
                Ok(seconds) if (600..=86_400).contains(&seconds) => seconds,
                _ => {
                    println!("  有效期必须是 600–86400 秒（10 分钟到 24 小时）。");
                    return exit::USAGE;
                }
            },
            None => 1_800,
        };
        let device = arg_values("--device", 1)
            .map(|values| values[0].trim().to_string())
            .unwrap_or_else(|| "新电脑".to_string());
        // 本机还没有身份记录时先装一次（幂等）：用户不该为了「生成一张邀请码」
        // 先记住要跑另一个命令。
        let identity = match pairhost::load_identity(&store) {
            Some(identity) => identity,
            None => match install(&target) {
                Ok(identity) => {
                    if let Err(message) = pairhost::save_identity(&store, &identity) {
                        println!("  {message}");
                        return exit::CONFIG;
                    }
                    identity
                }
                Err(fault) => {
                    println!("  {}", fault.message);
                    return fault.code;
                }
            },
        };
        return match pairhost::create(
            &target,
            &password,
            Some(expected),
            lifetime,
            &device,
            &identity,
            now,
        ) {
            Ok(issued) => {
                println!("  邀请码（一次性，{} 失效）：", issued.expires_at_utc);
                println!("    {}", issued.invite.code);
                println!("  邀请 id  ：{}", issued.invite.invite_id);
                println!(
                    "  新电脑加入后默认名为「{}」；在另一台电脑上：添加线路 → 我有邀请码 → 粘贴后点校验。",
                    issued.device_name
                );
                exit::OK
            }
            Err(fault) => {
                println!("  {}", fault.message);
                fault.code
            }
        };
    }

    let invite_id = match arg_values("--invite-id", 1) {
        Some(values) => values[0].trim().to_string(),
        None => {
            println!("  需要 --invite-id <邀请 id>：状态与作废都按 id 指名，不靠「最近一张」猜。");
            return exit::USAGE;
        }
    };

    if arg_values("--invite-status", 1).is_some() {
        return match pairhost::status(&target, &password, Some(expected), &invite_id) {
            Ok(value) => {
                let text = |key: &str| {
                    value
                        .get(key)
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                };
                println!("  邀请 {}", text("inviteId"));
                println!("  状态    ：{}", text("state"));
                println!("  设备名  ：{}", text("deviceName"));
                println!("  有效期至：{}", text("expiresAtUtc"));
                // 已消费的邀请才有这三项。没有它们，撤设备的人只能看到「某台设备」，
                // 无从判断是哪一台、占了哪个地址——「按邀请记录找设备」就断在这里。
                // 未消费时不打印，免得三行空白让人以为字段丢了。
                let device_id = text("deviceId");
                if !device_id.is_empty() {
                    println!("  设备 ID ：{device_id}");
                }
                let client_key = text("clientPublicKey");
                if !client_key.is_empty() {
                    println!("  设备公钥：{client_key}");
                }
                let client_address = text("clientAddress");
                if !client_address.is_empty() {
                    println!("  设备地址：{client_address}");
                }
                exit::OK
            }
            Err(fault) => {
                println!("  {}", fault.message);
                fault.code
            }
        };
    }

    match pairhost::cancel(&target, &password, Some(expected), &invite_id) {
        Ok(value) => {
            let state = value.get("state").and_then(|v| v.as_str()).unwrap_or("");
            println!("  邀请 {invite_id} 现在是 {state}。");
            exit::OK
        }
        Err(fault) => {
            println!("  {}", fault.message);
            fault.code
        }
    }
}

fn server_credentials(
    data_root: &std::path::Path,
    spec_text: &str,
) -> Result<(serverstore::ServerRecord, credential::Credential), u8> {
    let target = match ssh::Target::parse(spec_text) {
        Ok(target) => target,
        Err(message) => {
            println!("  {message}");
            return Err(exit::USAGE);
        }
    };
    let record = match serverstore::find_by_target(data_root, &target) {
        Ok(Some(record)) => record,
        Ok(None) => {
            println!("  本机没有 {spec_text} 的服务器记录。先运行 --server-trust 确认指纹并保存密码。");
            return Err(exit::CONFIG);
        }
        Err(error) => {
            println!("  {}", error.message);
            return Err(exit::CONFIG);
        }
    };
    let stored = match serverstore::credential(data_root, &record) {
        Ok(stored) => stored,
        Err(error) => {
            println!("  {}", error.message);
            println!("  请重新运行 --server-trust {spec_text} --fingerprint <指纹> 存一次密码。");
            return Err(exit::ENVIRONMENT);
        }
    };
    // 记录里可能是密码，也可能是私钥（r92）：要连服务器就得先变成可用的 `Credential`。
    let password = match stored.into_credential() {
        Ok(password) => password,
        Err(message) => {
            println!("  {message}");
            return Err(exit::ENVIRONMENT);
        }
    };
    Ok((record, password))
}

/// 把 SSH 错误翻成「用户看得懂 + 该退几号」。四个服务器命令共用同一套映射：
/// 同一个失败在四个地方给四种退出码，界面就没法统一处理。
pub(crate) fn ssh_exit_code(error: &ssh::Error) -> u8 {
    match error {
        ssh::Error::Auth => {
            println!("  用户名或密码不正确（服务器记录里的凭据可能已失效）。");
            exit::ENVIRONMENT
        }
        ssh::Error::Connect(_) | ssh::Error::Timeout => {
            println!("  {error}");
            exit::NETWORK
        }
        ssh::Error::HostKeyMismatch { .. } | ssh::Error::HostKeyUnknown { .. } => {
            println!("  服务器身份与记录不一致，已停止。");
            exit::CONFLICT
        }
        _ => {
            println!("  {error}");
            exit::INTERNAL
        }
    }
}

/// 取 `--flag` 之后的 n 个参数。缺参数返回 None（调用方据此报错，而不是静默忽略）。
fn arg_values(flag: &str, n: usize) -> Option<Vec<String>> {
    let args: Vec<String> = std::env::args().collect();
    let idx = args.iter().position(|a| a == flag)?;
    // 需要 idx+1..=idx+n 全部存在
    if idx + n >= args.len() {
        return None;
    }
    Some(args[idx + 1..=idx + n].to_vec())
}


/// 动作的中文说法。`--status` 与界面按钮用同一套措辞，用户看到的按钮名和命令行建议要一致。
fn action_zh(a: presentation::Action) -> &'static str {
    match a {
        presentation::Action::Connect => "连接",
        presentation::Action::Disconnect => "断开",
        presentation::Action::Retry => "重试",
        presentation::Action::Reconnect => "重新连接",
        presentation::Action::Setup => "去配置",
        presentation::Action::None => "请稍候",
    }
}

/// `--import` 不给 `--port` 时用的 mixed 入站端口。与旧版线路文件里那个探测端口一致，
/// 但两者互不相干：这里只决定本程序自己的本机代理端口。
const DEFAULT_PORT: u16 = 17890;

/// `--import`：生成引擎配置 + 写好线路，返回最终落盘的线路配置。
///
/// 顺序刻意如此：先落引擎配置，再写线路。反过来的话中途失败会留下「线路已指向本程序、
/// 引擎配置却不存在」，用户点连接只会得到一个看不懂的引擎启动失败。
fn import_profile(
    root: &std::path::Path,
    profile_path: &std::path::Path,
    engine_binary: &str,
    port: u16,
    line_name: Option<&str>,
    mode: config::Mode,
    origin: &events::Origin,
) -> Result<(config::AppConfig, bool), String> {
    // 端口上限 65532：探测入站要占 端口+3，超了自检就只能永远跳过——在导入时就说清。
    // 界面导入与 CLI 同走这里，两条入口一条规则。
    engine_config::validate_probe_room(port)?;
    let text = std::fs::read_to_string(profile_path)
        .map_err(|e| format!("读不到线路文件（{}）：{e}", profile_path.display()))?;
    // 分流规则与 AI 工具名单都跟着配置走：重新导入线路不该把用户配好的两份名单清掉。
    let existing_for_split = config::load(&root.join(config::DEFAULT_PATH)).ok().flatten();
    let split = existing_for_split.as_ref().map(|c| c.split.clone()).unwrap_or_default();
    // **必须传既有名单**：`generate` 会先按形状删掉旧规则再按这两份重建，
    // 只传分流等于「重新导入一次就把名单清空」。
    let agents = existing_for_split.as_ref().map(|c| c.agents.clone()).unwrap_or_default();
    let exits_cfg = existing_for_split.as_ref().map(|c| c.exits.clone()).unwrap_or_default();
    let body = engine_config::generate(&text, port, mode, &split, &agents, &exits_cfg)?;
    // 自检探测端口（端口+3）绑不上 = 连上之后自检永远「跳过」，用户看不到任何通道结论：
    // 试绑一次，现在就拒绝。放在 generate 之后，让「端口非法 / 线路文件坏」先用它们自己的文案说话。
    engine_config::validate_probe_port_free(port)
        .map_err(|e| format!("{IMPORT_CONFLICT_PREFIX}{e}"))?;

    let name = line_name.map(str::trim).filter(|n| !n.is_empty()).map(str::to_string);
    // 已落盘的 id 原样保留：先按**名字**找现有线路，找到就沿用它的 id（只更新端点/引擎配置）。
    // 否则 id 规则一改，同名线路会被当成新线路，用户那条线的 lines\<id>.json 就对不上了。
    let existing = config::load(root.join(config::DEFAULT_PATH).as_path()).ok().flatten();
    let existing_id = name.as_deref().and_then(|n| {
        existing
            .as_ref()
            .and_then(|c| c.find_line(n))
            .map(|l| l.id.clone())
    });
    let id = existing_id.clone().or_else(|| {
        name.as_deref()
            .map(config::slug)
            .or_else(|| Some(derive_line_id(profile_path)))
    })
    .unwrap_or_else(|| derive_line_id(profile_path));
    // 连接方式：线路文件**本身就是**兼容连接那一份（endpoint 挂在 tc-transport 上、参数齐全）
    // 就把意图读出来记成用户已选 —— 旧版的 Tcp profile 是部署产生的，用户导入这样一份文件，
    // 要的就是"这台机器走兼容连接"。文件是标准连接形状时**保留原有选择**：重新导入
    // 不该抹掉用户显式选过的东西；从没选过则继续是"没选过"（走标准连接）。
    let transport = if engine_config::tcp_shaped(&text) {
        Some(config::Transport::Tcp)
    } else {
        existing
            .as_ref()
            .and_then(|c| c.lines.iter().find(|l| l.id == id))
            .and_then(|l| l.transport)
    };
    let line = config::LineConfig {
        id: id.clone(),
        name: name.unwrap_or_else(|| id.clone()),
        proxy_endpoint: format!("127.0.0.1:{port}"),
        transport,
        // 换了一份线路参数，「上次通过」的依据就不再是这份配置的了，重新验。
        verified_transport: None,
    };

    // 引擎配置按线路落盘：`lines\<id>.json`。这份文件可能含 WireGuard 私钥，
    // 落盘走 secretfile：临时文件、收紧 ACL、写、改名一次做完（F1）。
    let engine_path = line.engine_config_path(root);
    if let Some(dir) = engine_path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("创建线路目录失败（{}）：{e}", dir.display()))?;
    }
    crate::secretfile::write(&engine_path, &body)
        .map_err(|e| format!("写入引擎配置失败（{}）：{e}", engine_path.display()))?;

    // 导入只动这一条：其它线路、开关、模式都保留（用户配好的不能被一次导入抹掉）。
    let cfg_path = root.join(config::DEFAULT_PATH);
    let mut cfg = match config::load(&cfg_path).map_err(|e| e.to_string())? {
        Some(c) => c,
        None => config::AppConfig {
            schema: config::SCHEMA,
            mode,
            auto_start: false,
            auto_connect: false,
            close_to_tray: false,
            quality_warning: true,
            auto_trust_first_connection: true,
            selected: String::new(),
            lines: Vec::new(),
            split: config::SplitConfig::default(),
            agents: config::AgentsConfig::default(),
            exits: config::Exits::default(),
            engine: None,
        },
    };
    let updated = upsert_line(&mut cfg, line);
    cfg.selected = id;
    cfg.mode = mode;
    cfg.engine = Some(config::EngineSettings { binary: engine_binary.to_string() });
    config::save_with_origin(&cfg_path, &cfg, origin)
        .map_err(|e| format!("写入线路配置失败：{e}"))?;
    Ok((cfg, updated))
}


/// 没给 `--line-name` 时用 profile 所在目录名当 id。
///
/// 再往上一级是固定的 `profiles`，拿它当 id 的话所有 profile 会撞成同一个 id，
/// 所以取 profile 自己那级目录名。
fn derive_line_id(profile_path: &std::path::Path) -> String {
    profile_path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "line".to_string())
}

/// 只用于给互斥名加区分度，不用于任何安全用途。
fn simple_hash(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:016x}", h)
}

#[cfg(test)]
mod tests {
    use super::*;
    // 合并逻辑在 `uiweb`（与键表同文件）；这里只按名字用，断言的是宿主侧真的调到了它。
    use crate::uiweb::{merge_maintenance_reply, merge_ui_command_reply};

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("tcrs-main-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        let _ = std::fs::create_dir_all(&p);
        p
    }

    #[test]
    fn guard_status_prints_the_perspective_note_only_when_the_backend_supplies_it() {
        // 普通权限：原样 8 行，一个「提示」都不许多。这句话只在「你自己就能改证据」的
        // 视角下成立，多打一次就是误导。
        let mut st = guard::GuardStatus::unknown(guard::GuardReason::EvidenceUnprotected, 1);
        st.store_kind = "Registry".to_string();
        let plain = guard_status_lines(&st);
        assert_eq!(plain.len(), 8, "没有视角说明时不得多行：{plain:?}");
        assert!(!plain.iter().any(|line| line.contains("提示")));

        // 管理员视角：末尾追加一句，逐字等于常量（CLI 与界面共用同一句）。
        st.perspective_note = Some(guard::state::PERSPECTIVE_NOTE_ELEVATED.to_string());
        let lines = guard_status_lines(&st);
        assert_eq!(lines.len(), 9);
        assert_eq!(
            lines[8],
            format!("  提示      ：{}", guard::state::PERSPECTIVE_NOTE_ELEVATED)
        );
    }

    #[test]
    fn configured_without_runtime_record_projects_disconnected() {
        let root = tmp_root("proj");
        let ev = ipc::evidence(&root, true, true);
        assert!(ev.deployment_present, "配好线路就必须算「已配置」");
        let p = presentation::present(&ev);
        assert_eq!(p.key, presentation::StateKey::Disconnected);
        assert_eq!(p.action, presentation::Action::Connect);
        assert_eq!(p.title, "未连接");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_config_projects_unconfigured() {
        let root = tmp_root("proj-empty");
        let ev = ipc::evidence(&root, false, true);
        assert!(!ev.deployment_present);
        let p = presentation::present(&ev);
        assert_eq!(p.key, presentation::StateKey::Unconfigured);
        assert_eq!(p.action, presentation::Action::Setup);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 造一份两种模式都能导入的最小线路文件（带 TUN 入站与一个真实出口）。
    fn write_profile(root: &std::path::Path) -> std::path::PathBuf {
        let dir = root.join("lines").join("L1").join("profiles").join("P1");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("dual-mode.json");
        let body = r#"{
            "inbounds": [{ "type": "tun", "tag": "trade-tun", "address": ["172.30.250.1/30"],
                           "mtu": 1380, "stack": "gvisor", "auto_route": true, "strict_route": true }],
            "route": { "rules": [], "final": "direct" },
            "outbounds": [{ "type": "direct", "tag": "direct" },
                          { "type": "selector", "tag": "trade-exit", "outbounds": ["direct"], "default": "direct" }]
        }"#;
        std::fs::write(&f, body).unwrap();
        f
    }

    fn ui_ctx_for(root: &std::path::Path) -> ipc::Ctx {
        ipc::Ctx {
            root: root.to_path_buf(),
            log_dir: root.join("logs"),
            source: events::Source::Ui,
            ..Default::default()
        }
    }

    #[test]
    fn webview_merge_preserves_restore_result_and_failure_shape() {
        let mut state = serde_json::json!({"ok": true, "detail": "操作失败：写入失败"});
        let reply = serde_json::json!({
            "ok": false,
            "error": "写入失败；凭据已保留",
            "errorCode": "config",
            "message": "写入失败；凭据已保留",
            "restoreResult": {"ok": false, "changed": false, "message": "写入失败；凭据已保留"},
            "maintenance": {"journalPresent": true, "proxyOwned": true, "canRestore": true}
        });
        merge_maintenance_reply(&mut state, &reply);
        assert_eq!(state["ok"], false);
        assert_eq!(state["errorCode"], "config");
        assert_eq!(state["restoreResult"]["ok"], false);
        assert_eq!(state["maintenance"]["journalPresent"], true);
        assert_eq!(state["message"], "写入失败；凭据已保留");

        // 普通 status 没有 restoreResult，不得把当前完整状态改成另一份增量。
        let mut unrelated = serde_json::json!({"ok": true, "title": "未连接"});
        merge_maintenance_reply(&mut unrelated, &serde_json::json!({"ok": true}));
        assert_eq!(unrelated, serde_json::json!({"ok": true, "title": "未连接"}));
    }

    /// `qualitySummary` 必须活着穿过宿主的回包合并。
    ///
    /// 漏掉它时：后端算得出 58 个采样、中位 122 ms，而首页「线路响应」永远
    /// 「等待采样」、三格全是「—」——真机上就是 2026-11-16 用户截图那一幕。
    /// 页面级测试用假 fetch，抓不到这条缝，只能在这里钉。
    #[test]
    fn webview_merge_keeps_the_quality_summary() {
        let mut state = serde_json::json!({"ok": true, "state": "Connected"});
        merge_ui_command_reply(
            &mut state,
            &serde_json::json!({
                "ok": true,
                "qualitySummary": {"SampleCount": 58, "MedianLatencyMs": 122},
            }),
        );
        assert_eq!(state["qualitySummary"]["SampleCount"], 58, "{state}");
    }

    #[test]
    fn webview_merge_keeps_the_servers_payload_for_invite_ownership() {
        // r36：邀请入口的归属查询走 UI 侧 fetch，而 UI 侧回包是「状态对象 + 白名单
        // 增量」。`servers` 不在白名单时，宿主拿到的是一个没有 servers 的 status，
        // `invite_servers` 判成「读不到」→ 每条线路 CanInvite=false → 按钮恒灰。
        // 页面测试用假 fetch，抓不到这条；这里钉住回包形状。
        let mut state = serde_json::json!({"ok": true, "state": "Disconnected"});
        merge_ui_command_reply(
            &mut state,
            &serde_json::json!({
                "ok": true,
                "servers": [{
                    "Id": "32d4f356-db4b-4ca5-8f06-cda3587a5f80",
                    "Name": "root@203.0.113.10",
                    "Host": "203.0.113.10",
                    "LineIds": ["81ea5efab7154128621517c5bb98fde63a5"],
                }],
            }),
        );
        assert_eq!(
            state["servers"][0]["LineIds"][0], "81ea5efab7154128621517c5bb98fde63a5",
            "归属表必须进快照，否则邀请入口永远是灰的"
        );
        assert_eq!(state["ok"], true, "成功回包不能被改写成失败");
        assert_eq!(state["state"], "Disconnected", "状态字段仍然保留");

        // 同一条通道上的另一半：邀请四条命令的回包。少了 `invite`，
        // `finish_op` 收到的是「没有 invite 的 status」，状态机永远停在 Creating。
        let mut state = serde_json::json!({"ok": true, "state": "Disconnected"});
        merge_ui_command_reply(
            &mut state,
            &serde_json::json!({
                "ok": true,
                "invite": {"Section": "Create", "Data": {"InviteId": "I1", "Code": "TCI1.x"}},
            }),
        );
        assert_eq!(state["invite"]["Section"], "Create", "签发回包必须进状态机");
        assert_eq!(state["invite"]["Data"]["InviteId"], "I1");
    }

    #[test]
    fn webview_merge_keeps_the_server_device_payloads() {
        // 新增命令时最容易漏的一处：回包键不在这份白名单里，命令真的跑了，
        // 页面却永远停在「正在读取…」。设备页与撤销各钉一条。
        let mut state = serde_json::json!({"ok": true});
        merge_ui_command_reply(
            &mut state,
            &serde_json::json!({
                "ok": true,
                "serverDevices": {"devices": [{"address": "10.66.0.2"}]},
                "serverRevoke": {"publicKey": "key", "peers": 1},
            }),
        );
        assert!(state.get("serverDevices").is_some(), "设备页回包必须留下");
        assert!(state.get("serverRevoke").is_some(), "撤销回包必须留下");
    }

    #[test]
    fn webview_merge_preserves_diagnose_payload_and_command_failure() {
        let mut state = serde_json::json!({"ok": true, "title": "未连接"});
        let reply = serde_json::json!({
            "ok": false,
            "error": "诊断未通过",
            "errorCode": "network",
            "message": "诊断未通过",
            "diagnose": {"line": "线路甲", "verdict": {"text": "所有目标均不可达"}},
            "lines": [{"id": "L1"}]
        });
        merge_ui_command_reply(&mut state, &reply);
        assert_eq!(state["ok"], false);
        assert_eq!(state["error"], "诊断未通过");
        assert_eq!(state["errorCode"], "network");
        assert_eq!(state["diagnose"]["line"], "线路甲");
        assert_eq!(state["diagnose"]["verdict"]["text"], "所有目标均不可达");
        assert_eq!(state["lines"][0]["id"], "L1");
    }

    #[test]
    fn t13_webview_merge_preserves_latency_result_and_failure() {
        let mut state = serde_json::json!({"ok": true, "title": "已连接"});
        merge_ui_command_reply(&mut state, &serde_json::json!({
            "ok": true,
            "latencyMs": 37,
            "measuredAtUtc": "2026-10-30T04:00:00Z",
            "latencyError": null
        }));
        assert_eq!(state["latencyMs"], 37);
        assert_eq!(state["measuredAtUtc"], "2026-10-30T04:00:00Z");
        assert!(state.get("latencyError").is_some(), "成功也要清除上一次测量错误");

        let mut failed = serde_json::json!({"ok": true, "title": "已连接", "latencyMs": 37});
        merge_ui_command_reply(&mut failed, &serde_json::json!({
            "ok": false,
            "error": "探测超时",
            "errorCode": "network",
            "latencyError": "探测超时"
        }));
        assert_eq!(failed["ok"], false);
        assert_eq!(failed["errorCode"], "network");
        assert_eq!(failed["latencyError"], "探测超时");
        assert_eq!(failed["latencyMs"], 37, "失败可以保留上次真实读数，但不能伪造新读数");
    }

    #[test]
    fn t14_webview_merge_preserves_compatible_partial_failure() {
        let mut state = serde_json::json!({"ok": true, "title": "未连接"});
        merge_ui_command_reply(&mut state, &serde_json::json!({
            "ok": false,
            "error": "兼容连接偏好已保存，但重新连接失败：未配置引擎",
            "compatibleResult": {
                "stage": "connect",
                "saved": true,
                "reconnected": false,
                "verified": false,
                "message": "兼容连接偏好已保存，但重新连接失败：未配置引擎"
            }
        }));
        assert_eq!(state["ok"], false, "命令失败不能被重建的 status 覆盖");
        assert_eq!(state["compatibleResult"]["stage"], "connect");
        assert_eq!(state["compatibleResult"]["saved"], true);
        assert_eq!(state["compatibleResult"]["reconnected"], false);
        assert_eq!(state["compatibleResult"]["verified"], false);
    }

    #[test]
    fn t17_webview_merge_preserves_export_and_rename_results() {
        let mut state = serde_json::json!({"ok": true, "title": "未连接"});
        merge_ui_command_reply(&mut state, &serde_json::json!({
            "ok": true,
            "lines": [{"id": "L1", "name": "新名称"}],
            "renameResult": {"ok": true, "changed": true, "name": "新名称", "message": "已改名为「新名称」"},
            "exportResult": {"ok": true, "path": r"C:\data\logs\exports\operations-1.jsonl", "count": 3, "message": "已导出 3 条"}
        }));
        assert_eq!(state["lines"][0]["name"], "新名称");
        assert_eq!(state["renameResult"]["changed"], true);
        assert_eq!(state["exportResult"]["count"], 3);
        assert_eq!(state["exportResult"]["path"], r"C:\data\logs\exports\operations-1.jsonl");

        let mut failed = serde_json::json!({"ok": true, "title": "未连接"});
        merge_ui_command_reply(&mut failed, &serde_json::json!({
            "ok": false,
            "error": "已经有名为「线路乙」的线路，请换一个名称",
            "errorCode": "conflict",
            "renameResult": {
                "ok": false, "changed": false, "name": null,
                "message": "已经有名为「线路乙」的线路，请换一个名称"
            }
        }));
        assert_eq!(failed["ok"], false);
        assert_eq!(failed["errorCode"], "conflict");
        assert_eq!(failed["renameResult"]["ok"], false);
    }

    #[test]
    fn t18_webview_merge_preserves_provider_conclusions_and_backup_result() {
        let mut state = serde_json::json!({"ok": true, "title": "已连接"});
        merge_ui_command_reply(&mut state, &serde_json::json!({
            "ok": true,
            "providers": [{
                "slot": 1, "name": "Clash", "effectiveState": "effective",
                "effectiveRole": "daily", "effectiveReason": "日常出口已指向它；交易出口没有使用它"
            }],
            "entryNote": "使用客户端混合端口 7895",
            "backupResult": {
                "ok": true, "lineId": "L2", "lineName": "备用线路",
                "reachable": true, "latencyMs": 12, "notCurrentLatency": true,
                "message": "备用线路「备用线路」TCP 端口可达（12 ms）；不等于当前响应"
            }
        }));
        assert_eq!(state["providers"][0]["effectiveState"], "effective");
        assert_eq!(state["providers"][0]["effectiveRole"], "daily");
        assert_eq!(state["entryNote"], "使用客户端混合端口 7895");
        assert_eq!(state["backupResult"]["lineId"], "L2");
        assert_eq!(state["backupResult"]["latencyMs"], 12);
        assert_eq!(state["backupResult"]["notCurrentLatency"], true);

        let mut failed = serde_json::json!({"ok": true});
        merge_ui_command_reply(&mut failed, &serde_json::json!({
            "ok": false,
            "error": "连接后才能检查备用线路",
            "errorCode": "environment",
            "backupResult": {
                "ok": false, "lineId": "L2", "lineName": "备用线路",
                "reachable": null, "latencyMs": null, "notCurrentLatency": true,
                "message": "连接后才能检查备用线路；未连接时不做任何网络探测"
            }
        }));
        assert_eq!(failed["ok"], false);
        assert_eq!(failed["errorCode"], "environment");
        assert!(failed["backupResult"]["reachable"].is_null());
    }

    #[test]
    fn import_failure_text_is_identical_for_ui_and_cli() {
        // T-08 DoD④：同一个导入失败，界面 `.msg` 与 CLI stderr 必须逐字相等。
        // 两侧都走 import_failure；这条测试盯的是「不许任何一侧偷偷加前缀或缩进」。
        let err = "线路文件不存在：C:\\nope.json";
        let (code, text) = import_failure(err);
        assert_eq!(code, exit::CONFIG);
        assert_eq!(text, err, "界面与 CLI 必须逐字相同");
        assert!(!text.contains("导入失败："), "旧前缀已废弃，加回去就不同源了");

        let conflict = format!("{IMPORT_CONFLICT_PREFIX}端口 17890 的自检探测端口 17893 已被占用");
        let (code, text) = import_failure(&conflict);
        assert_eq!(code, exit::CONFLICT, "端口冲突要归冲突，不能归配置");
        assert_eq!(text, conflict);
    }

    #[test]
    fn gui_start_with_a_broken_config_shows_a_message_box_and_exits_config() {
        // 双击启动没有控制台：只 println 等于"点了没反应"。这里断言弹框被调用且正文可操作。
        let calls = std::cell::RefCell::new(Vec::<(String, String)>::new());
        let alert = |t: &str, b: &str| calls.borrow_mut().push((t.to_string(), b.to_string()));
        let path = std::path::Path::new(r"C://data//config.json");
        let err = config::ConfigError::Parse("expected value at line 1".into());

        let code = report_fatal_config_error(path, &err, true, &alert);
        assert_eq!(code, exit::CONFIG as i32, "配置读不出来归 CONFIG(3)，不再是旧值 12");
        let got = calls.borrow();
        assert_eq!(got.len(), 1, "GUI 模式必须弹一次框");
        assert!(got[0].0.contains("无法启动"), "标题要说明起不来：{}", got[0].0);
        assert!(got[0].1.contains("配置文件读取失败"), "正文含原因：{}", got[0].1);
        assert!(got[0].1.contains("config.json"), "正文含路径：{}", got[0].1);
        assert!(got[0].1.contains("重新导入") && got[0].1.contains("backup"), "正文含处理办法：{}", got[0].1);

        // 命令行模式不弹框（控制台有人看得见）
        drop(got);
        calls.borrow_mut().clear();
        let code = report_fatal_config_error(path, &err, false, &alert);
        assert_eq!(code, exit::CONFIG as i32);
        assert!(calls.borrow().is_empty(), "命令行模式不许弹框");
    }

    #[test]
    fn ui_import_applies_the_chosen_tun_mode() {
        let root = tmp_root("ui-tun");
        let prof = write_profile(&root);
        let mut ctx = ui_ctx_for(&root);
        let raw = serde_json::json!({
            "cmd": "import",
            "profile": prof.to_string_lossy(),
            "engine": r"C:\Windows\System32\PING.EXE",
            "name": "界面 TUN",
            "mode": "tun",
            // 本用例验证模式，不验证固定默认端口；避免并行导入争用 17893。
            "port": free_port_pair(),
        })
        .to_string();

        let st: serde_json::Value =
            serde_json::from_str(&handle_ui_import(&root, &mut ctx, &raw)).unwrap();

        assert!(st["detail"].as_str().unwrap_or_default().contains("已导入线路"), "导入必须先成功：{st}");
        // 落盘：线路配置记下 tun，引擎配置同时有 TUN 与 mixed 入站
        let cfg = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(cfg.mode, config::Mode::Tun, "界面选了 TUN 就必须写 tun");
        // 引擎配置按线路落盘了：不再有全局 engine.json。
        let line_path = cfg.current_line().unwrap().engine_config_path(&root);
        let ej: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&line_path).unwrap()).unwrap();
        assert!(
            ej["inbounds"].as_array().unwrap().iter().any(|i| i["type"] == "tun"),
            "tun 模式的引擎配置必须含 TUN 入站：{ej}"
        );

        // 回推给界面的状态：模式与线路都是新的（不重载上下文就会显示旧的）
        assert_eq!(st["mode"], "TUN");
        assert_eq!(st["line"], "界面 TUN");
        assert!(st["detail"].as_str().unwrap_or_default().contains("已导入线路"));
        assert_eq!(ctx.cfg.as_ref().map(|c| c.mode), Some(config::Mode::Tun));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ui_import_conflict_writes_nothing_until_replace_is_confirmed() {
        let root = tmp_root("ui-conflict");
        let prof = write_profile(&root);
        let mut ctx = ui_ctx_for(&root);
        let first = serde_json::json!({
            "cmd": "import", "profile": prof.to_string_lossy(),
            "engine": r"C:\Windows\System32\PING.EXE", "name": "重复线路",
            "mode": "proxy", "onConflict": "ask", "port": free_port_pair()
        })
        .to_string();
        let st: serde_json::Value =
            serde_json::from_str(&handle_ui_import(&root, &mut ctx, &first)).unwrap();
        assert_eq!(st["ok"], true, "{st}");

        let cfg_path = root.join(config::DEFAULT_PATH);
        let cfg_before = std::fs::read(&cfg_path).unwrap();
        let line = config::load(&cfg_path).unwrap().unwrap().current_line().unwrap().clone();
        let engine_path = line.engine_config_path(&root);
        let engine_before = std::fs::read(&engine_path).unwrap();
        let mtime_before = std::fs::metadata(&engine_path).unwrap().modified().unwrap();

        // mtime 的分辨率不足以在一次快速连点里区分“有没有写”，留出一秒再比。
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        let again: serde_json::Value =
            serde_json::from_str(&handle_ui_import(&root, &mut ctx, &first)).unwrap();
        assert_eq!(again["ok"], false, "{again}");
        assert_eq!(again["errorCode"], "conflict", "{again}");
        assert_eq!(again["conflict"]["name"], "重复线路", "{again}");
        assert_eq!(std::fs::read(&cfg_path).unwrap(), cfg_before, "确认前配置不能变");
        assert_eq!(std::fs::read(&engine_path).unwrap(), engine_before, "确认前引擎配置不能变");
        assert_eq!(
            std::fs::metadata(&engine_path).unwrap().modified().unwrap(),
            mtime_before,
            "确认前引擎配置的 mtime 也不能变"
        );

        let replace = first.replace("\"ask\"", "\"replace\"");
        let ok: serde_json::Value =
            serde_json::from_str(&handle_ui_import(&root, &mut ctx, &replace)).unwrap();
        assert_eq!(ok["ok"], true, "确认替换后才允许写：{ok}");
        assert_eq!(ok["importDone"], true, "{ok}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ui_import_save_as_adds_a_line_and_rechecks_the_new_name() {
        let root = tmp_root("ui-save-as");
        let prof = write_profile(&root);
        let mut ctx = ui_ctx_for(&root);
        let base = serde_json::json!({
            "cmd": "import", "profile": prof.to_string_lossy(),
            "engine": r"C:\Windows\System32\PING.EXE", "mode": "proxy",
            "port": free_port_pair()
        });
        let first = base.to_string();
        let st: serde_json::Value =
            serde_json::from_str(&handle_ui_import(&root, &mut ctx, &first)).unwrap();
        assert_eq!(st["ok"], true, "{st}");

        let mut save_as = base.clone();
        save_as["name"] = serde_json::json!("另存线路");
        save_as["onConflict"] = serde_json::json!("save-as");
        let second: serde_json::Value =
            serde_json::from_str(&handle_ui_import(&root, &mut ctx, &save_as.to_string())).unwrap();
        assert_eq!(second["ok"], true, "{second}");
        let cfg = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(cfg.lines.len(), 2, "另存为必须新增一条：{cfg:?}");
        assert_eq!(cfg.current_line().map(|l| l.name.as_str()), Some("另存线路"));

        let third = save_as.clone();
        let again: serde_json::Value =
            serde_json::from_str(&handle_ui_import(&root, &mut ctx, &third.to_string())).unwrap();
        assert_eq!(again["ok"], false, "{again}");
        assert_eq!(again["errorCode"], "conflict", "新名字再撞也要继续提示：{again}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn inspect_import_names_the_bad_field_and_pick_file_is_injectable() {
        let root = tmp_root("ui-inspect-pick");
        let prof = write_profile(&root);
        let empty = inspect_import_problems("", "");
        assert_eq!(empty.len(), 2, "{empty:?}");
        assert!(empty.iter().any(|p| p["field"] == "profile"));
        assert!(empty.iter().any(|p| p["field"] == "engine"));
        let valid = inspect_import_problems(
            prof.to_str().unwrap(),
            r"C:\Windows\System32\PING.EXE",
        );
        assert!(valid.is_empty(), "合法文件不该报问题：{valid:?}");
        let bad = root.join("not-a-line.json");
        std::fs::write(&bad, r#"{"hello":"world"}"#).unwrap();
        let broken = inspect_import_problems(
            bad.to_str().unwrap(),
            r"C:\Windows\System32\PING.EXE",
        );
        assert_eq!(broken.len(), 1, "{broken:?}");
        assert_eq!(broken[0]["field"], "profile");
        assert!(broken[0]["fix"].as_str().unwrap_or("").contains("线路 JSON"), "{broken:?}");

        let ctx = ui_ctx_for(&root);
        let reply = handle_ui_pick_file_with(
            &ctx,
            r#"{"cmd":"pick-file","slot":"profile"}"#,
            |slot| {
                assert_eq!(slot, "profile");
                Ok(Some(r"C:\fixtures\dual-mode.json".to_string()))
            },
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["filePick"]["slot"], "profile", "{v}");
        assert_eq!(v["filePick"]["cancelled"], false, "{v}");
        assert!(v["filePick"]["pickId"].as_str().unwrap_or_default().starts_with("pick-"));

        let cancelled = handle_ui_pick_file_with(
            &ctx,
            r#"{"cmd":"pick-file","slot":"engine"}"#,
            |_| Ok(None),
        );
        let c: serde_json::Value = serde_json::from_str(&cancelled).unwrap();
        assert_eq!(c["filePick"]["cancelled"], true, "{c}");
        assert!(c["filePick"].get("path").is_none(), "取消不能清空旧值：{c}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// r94：选恢复包时把文件内容一起带回；另存为把文本写到用户选的路径。
    #[test]
    fn picking_a_recovery_file_reads_its_text_and_save_file_writes_it() {
        let root = tmp_root("ui-recovery-file");
        let ctx = ui_ctx_for(&root);
        let source = root.join("source.tcrecovery");
        std::fs::write(&source, "ENC-FROM-FILE").unwrap();
        let reply = handle_ui_pick_file_with(
            &ctx,
            r#"{"cmd":"pick-file","slot":"recovery"}"#,
            |slot| {
                assert_eq!(slot, "recovery", "槽位不许被归一化");
                Ok(Some(source.to_string_lossy().to_string()))
            },
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["filePick"]["slot"], "recovery", "{v}");
        assert_eq!(v["filePick"]["text"], "ENC-FROM-FILE", "{v}");

        // 超限：在读之前拒绝，不返回半截文本。
        let big = root.join("big.tcrecovery");
        std::fs::write(&big, vec![b'x'; crate::recovery::RECOVERY_MAX_BYTES + 1]).unwrap();
        let reply = handle_ui_pick_file_with(
            &ctx,
            r#"{"cmd":"pick-file","slot":"recovery"}"#,
            |_| Ok(Some(big.to_string_lossy().to_string())),
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or("").contains("超过"), "{v}");

        // 另存为：路径由对话框给，内容是页面给的文本。
        let destination = root.join("out.tcrecovery");
        let destination_text = destination.to_string_lossy().to_string();
        let reply = handle_ui_save_file_with(
            &ctx,
            &serde_json::json!({
                "cmd":"save-file","slot":"recovery","text":"ENC-PACKAGE",
                "suggestedName":"x.tcrecovery"
            })
            .to_string(),
            |slot, text, suggested| {
                assert_eq!(slot, "recovery");
                assert_eq!(text, "ENC-PACKAGE");
                assert_eq!(suggested, "x.tcrecovery");
                // 生产实现（`ui::save_file`）在对话框之后写文件；这里照样落盘。
                std::fs::write(&destination_text, text).unwrap();
                Ok(Some(destination_text.clone()))
            },
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["fileSave"]["saved"], true, "{v}");
        assert_eq!(v["fileSave"]["path"], destination_text, "{v}");
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "ENC-PACKAGE");

        // 取消：`cancelled:true`，不产生路径。
        let reply = handle_ui_save_file_with(
            &ctx,
            &serde_json::json!({"cmd":"save-file","slot":"recovery","text":"ENC"}).to_string(),
            |_, _, _| Ok(None),
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["fileSave"]["cancelled"], true, "{v}");
        assert!(v["fileSave"].get("path").is_none(), "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pick_exe_returns_only_the_process_name_for_the_requested_group() {
        let root = tmp_root("ui-pick-exe");
        let ctx = ui_ctx_for(&root);
        let reply = handle_ui_pick_exe_with(
            &ctx,
            r#"{"cmd":"pick-exe","target":"trade"}"#,
            |slot| {
                assert_eq!(slot, "process", "程序选择走独立的交易程序选择器");
                Ok(Some(r"C:\fixtures\TDXW.exe".to_string()))
            },
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["filePick"]["slot"], "process", "{v}");
        assert_eq!(v["filePick"]["target"], "trade", "{v}");
        assert_eq!(v["filePick"]["processName"], "TDXW.exe", "{v}");
        assert_eq!(v["filePick"]["path"], r"C:\fixtures\TDXW.exe", "{v}");
        assert_eq!(v["filePick"]["cancelled"], false, "{v}");

        let cancelled: serde_json::Value = serde_json::from_str(&handle_ui_pick_exe_with(
            &ctx,
            r#"{"cmd":"pick-exe","target":"daily"}"#,
            |_| Ok(None),
        ))
        .unwrap();
        assert_eq!(cancelled["filePick"]["cancelled"], true, "{cancelled}");
        assert!(cancelled["filePick"].get("processName").is_none(), "取消不能制造进程名");

        let rejected: serde_json::Value = serde_json::from_str(&handle_ui_pick_exe_with(
            &ctx,
            r#"{"cmd":"pick-exe","target":"direct"}"#,
            |_| Ok(Some(r"C:\fixtures\notes.txt".to_string())),
        ))
        .unwrap();
        assert_eq!(rejected["ok"], false, "{rejected}");
        assert!(rejected["error"].as_str().unwrap_or_default().contains(".exe"), "{rejected}");
        assert!(rejected.get("filePick").is_none(), "非 exe 不能投递成分流规则");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 「选择引擎程序」这条链：`pick-file{slot:"engine"}` → 真探测（这里注入）→ 写 config.json。
    ///
    /// 注意**用的命令**：引擎走 `pick-file`（`slot` 参数），不是 `pick-exe`——后者的 `target`
    /// 只有 direct/trade/daily，那是给分流选进程目标用的。走错命令等于给用户一个
    /// 「选完没反应」的按钮，所以这条断言同时钉住「用对了命令」。
    #[test]
    fn picking_the_engine_binary_verifies_it_and_saves_it() {
        let root = tmp_root("ui-pick-engine");
        let cfg = config::parse(
            r#"{"schema":1,"line":{"id":"L1","name":"线路甲","proxy_endpoint":"127.0.0.1:17890"}}"#,
        )
        .unwrap();
        config::save(&root.join(config::DEFAULT_PATH), &cfg).unwrap();
        let ctx = ui_ctx_for(&root);
        let engine = root.join("sing-box.exe");
        std::fs::write(&engine, b"stub").unwrap();

        // ① 选通并验过：配置里出现 engine.binary，回包里带版本号。
        let reply = handle_ui_pick_file_with_probe(
            &ctx,
            r#"{"cmd":"pick-file","slot":"engine"}"#,
            |slot| {
                assert_eq!(slot, "engine", "必须是 engine 这个 slot");
                Ok(Some(engine.to_string_lossy().to_string()))
            },
            &|path: &std::path::Path| {
                assert_eq!(path, engine.as_path());
                Ok("sing-box version 1.14.2".to_string())
            },
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["filePick"]["slot"], "engine", "{v}");
        assert_eq!(v["filePick"]["cancelled"], false, "{v}");
        assert!(
            v["engineSet"]["Message"].as_str().unwrap_or_default().contains("1.14.2"),
            "回包里必须有「真的验过」的证据：{v}"
        );
        let saved = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(
            saved.engine.as_ref().map(|e| e.binary.as_str()),
            Some(engine.to_string_lossy().as_ref()),
            "选完没有写进配置"
        );

        // ② 选了个不是引擎的程序：拒绝、且配置里仍是上一次那个好用的。
        let bad = root.join("notepad.exe");
        std::fs::write(&bad, b"stub").unwrap();
        let refused: serde_json::Value = serde_json::from_str(&handle_ui_pick_file_with_probe(
            &ctx,
            r#"{"cmd":"pick-file","slot":"engine"}"#,
            |_| Ok(Some(bad.to_string_lossy().to_string())),
            &|_: &std::path::Path| Err("这个程序不是 sing-box".to_string()),
        ))
        .unwrap();
        assert_eq!(refused["ok"], false, "{refused}");
        assert!(
            refused["engineSet"]["Message"].as_str().unwrap_or_default().contains("sing-box"),
            "失败也要有话说：{refused}"
        );
        let saved = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(
            saved.engine.as_ref().map(|e| e.binary.as_str()),
            Some(engine.to_string_lossy().as_ref()),
            "选错了不该把原来那个好引擎换掉"
        );

        // ③ 取消：不发任何结论，也不清掉已配置的引擎。
        let cancelled: serde_json::Value = serde_json::from_str(&handle_ui_pick_file_with_probe(
            &ctx,
            r#"{"cmd":"pick-file","slot":"engine"}"#,
            |_| Ok(None),
            &|_: &std::path::Path| panic!("取消不该触发探测"),
        ))
        .unwrap();
        assert_eq!(cancelled["filePick"]["cancelled"], true, "{cancelled}");
        assert!(cancelled.get("engineSet").is_none(), "取消不该报「已选用」：{cancelled}");

        // ④ 选线路文件（slot 缺省）走的是老路：不许顺手把它当引擎验。
        let profile = root.join("dual-mode.json");
        std::fs::write(&profile, b"{}").unwrap();
        let profile_reply: serde_json::Value = serde_json::from_str(&handle_ui_pick_file_with_probe(
            &ctx,
            r#"{"cmd":"pick-file"}"#,
            |slot| {
                assert_eq!(slot, "profile", "缺省 slot 是 profile");
                Ok(Some(profile.to_string_lossy().to_string()))
            },
            &|_: &std::path::Path| panic!("线路文件不该被当成引擎去探测"),
        ))
        .unwrap();
        assert_eq!(profile_reply["filePick"]["slot"], "profile", "{profile_reply}");
        assert!(profile_reply.get("engineSet").is_none(), "{profile_reply}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ui_settings_saves_both_switches_and_syncs_only_autostart() {
        let root = tmp_root("ui-settings");
        // 造一份能过 parse 的配置：设置是改现有配置，不能凭空造
        std::fs::create_dir_all(&root).unwrap();
        let cfg = config::parse(
            r#"{"schema":1,"line":{"id":"L1","name":"设置","proxy_endpoint":"127.0.0.1:17890"}}"#,
        )
        .unwrap();
        config::save(&root.join(config::DEFAULT_PATH), &cfg).unwrap();
        let mut ctx = ui_ctx_for(&root);
        ctx.cfg = Some(cfg);
        let run_key = format!(r"Software\SpiderVPN\tests\ui-settings-{}", std::process::id());
        let exe = std::path::Path::new(r"C:\x\bin\spidervpn.exe"); // 不存在这个布局：自启项会退回 exe 本身

        // 打开自启 + 自动连接
        let raw = serde_json::json!({"cmd":"settings","autoStart":true,"autoConnect":true}).to_string();
        let st: serde_json::Value =
            serde_json::from_str(&handle_ui_settings_in(&root, &mut ctx, &raw, &run_key, exe)).unwrap();
        assert_eq!(st["autoStart"], true);
        assert_eq!(st["autoConnect"], true);
        assert_eq!(st["detail"], "设置已保存");
        let saved = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        assert!(saved.auto_start && saved.auto_connect, "两个开关都要落盘");
        assert_eq!(
            crate::autostart::current_in(&run_key).as_deref(),
            Some(r"C:\x\bin\spidervpn.exe"),
            "没有启动入口时应退回 exe 本身"
        );

        // 只关自动连接：自启项不许被顺手重写
        let raw = serde_json::json!({"cmd":"settings","autoStart":true,"autoConnect":false}).to_string();
        let st: serde_json::Value =
            serde_json::from_str(&handle_ui_settings_in(&root, &mut ctx, &raw, &run_key, exe)).unwrap();
        assert_eq!(st["autoConnect"], false);
        // 老配置没有这一项：读进来必须是「开着」，否则升级后提醒悄悄消失。
        assert_eq!(st["qualityWarning"], true);

        // 关线路变差提醒：只落这一个开关，两个自启/自动连接开关都不许被带偏。
        let raw = serde_json::json!({"cmd":"settings","qualityWarning":false}).to_string();
        let st: serde_json::Value =
            serde_json::from_str(&handle_ui_settings_in(&root, &mut ctx, &raw, &run_key, exe)).unwrap();
        assert_eq!(st["qualityWarning"], false);
        assert_eq!(st["autoStart"], true);
        let saved = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        assert!(!saved.quality_warning, "开关要落盘：{saved:?}");
        assert!(
            crate::autostart::current_in(&run_key).is_some(),
            "自启项没变时不该被动过（这里是「仍在」，不是「被删」）"
        );

        // 自动记住首次服务器身份：默认开（老配置没这一项也一样），可以关掉并落盘。
        assert_eq!(st["autoTrust"], true, "老配置读进来必须是开着的（与旧版同一默认）");
        let raw = serde_json::json!({"cmd":"settings","autoTrust":false}).to_string();
        let st: serde_json::Value =
            serde_json::from_str(&handle_ui_settings_in(&root, &mut ctx, &raw, &run_key, exe)).unwrap();
        assert_eq!(st["autoTrust"], false);
        assert_eq!(st["qualityWarning"], false, "别的开关不许被带偏");
        let saved = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        assert!(!saved.auto_trust_first_connection, "开关要落盘：{saved:?}");

        // 关自启：Run 键的值要消失
        let raw = serde_json::json!({"cmd":"settings","autoStart":false,"autoConnect":false}).to_string();
        let _ = handle_ui_settings_in(&root, &mut ctx, &raw, &run_key, exe);
        assert_eq!(crate::autostart::current_in(&run_key), None, "关掉自启后 Run 值必须删除");

        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(&run_key);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ui_import_falls_back_to_proxy_when_mode_is_missing_or_unknown() {
        for (tag, mode_field) in [("no-mode", None), ("bad-mode", Some("quic"))] {
            let root = tmp_root(&format!("ui-{tag}"));
            let prof = write_profile(&root);
            let mut ctx = ui_ctx_for(&root);
            let mut body = serde_json::json!({
                "cmd": "import",
                "profile": prof.to_string_lossy(),
                "engine": r"C:\Windows\System32\PING.EXE",
                "name": "界面 默认",
                // 模式缺省与端口缺省是两件事；本用例不占用固定默认端口。
                "port": free_port_pair(),
            });
            if let Some(m) = mode_field {
                body["mode"] = serde_json::Value::String(m.to_string());
            }

            let st: serde_json::Value =
                serde_json::from_str(&handle_ui_import(&root, &mut ctx, &body.to_string())).unwrap();

            let cfg = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
            assert_eq!(cfg.mode, config::Mode::Proxy, "{tag}：缺省或乱填都按代理，且不报错");
            assert_eq!(st["mode"], "代理", "{tag}：界面要显示代理");
            assert!(st["detail"].as_str().unwrap_or_default().contains("已导入线路"), "{tag}：导入本身要成功");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    /// 一对空闲端口（线路端口与探测端口 = +3 都得空着）：否则导入会被「端口被占」挡掉。
    fn free_port_pair() -> u16 {
        for _ in 0..200 {
            let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            if p >= 65_532 {
                continue;
            }
            let Ok(main) = std::net::TcpListener::bind(("127.0.0.1", p)) else { continue };
            drop(main);
            let Ok(probe) = std::net::TcpListener::bind(("127.0.0.1", p + 3)) else { continue };
            drop(probe);
            return p;
        }
        panic!("找不到可用端口对");
    }

    #[test]
    fn ui_import_uses_the_typed_port_and_falls_back_to_17890() {
        // 端口是「被占时让人换一个」的那个旋钮：填了必须生效，不填/填错必须还是 17890。
        let picked = free_port_pair();
        for (tag, given, expect) in [
            ("given", Some(picked as u64), picked),
            ("empty", None, DEFAULT_PORT),
            ("too-big", Some(70_000), DEFAULT_PORT),
        ] {
            let root = tmp_root(&format!("ui-port-{tag}"));
            let prof = write_profile(&root);
            let mut ctx = ui_ctx_for(&root);
            let mut body = serde_json::json!({
                "cmd": "import",
                "profile": prof.to_string_lossy(),
                "engine": r"C:\Windows\System32\PING.EXE",
                "name": format!("端口 {tag}"),
            });
            if let Some(p) = given {
                body["port"] = serde_json::json!(p);
            }

            let st: serde_json::Value =
                serde_json::from_str(&handle_ui_import(&root, &mut ctx, &body.to_string())).unwrap();

            let cfg = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
            let line = cfg.current_line().unwrap();
            assert_eq!(line.proxy_endpoint, format!("127.0.0.1:{expect}"), "{tag}：{st}");
            // 线路端点与引擎监听口必须是同一个：只改一边等于连到一个没人听的口。
            let ej: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(line.engine_config_path(&root)).unwrap(),
            )
            .unwrap();
            assert!(
                ej["inbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|i| i["type"] == "mixed" && i["listen_port"] == expect),
                "{tag}：引擎配置的 mixed 入站要用同一个端口：{ej}"
            );
            assert!(
                st["detail"].as_str().unwrap_or_default().contains("已导入线路"),
                "{tag}：导入本身要成功：{st}"
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }
}
