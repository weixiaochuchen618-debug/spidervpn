//! 窗口与 WebView2 承载。
//!
//! 只负责「起一个属于本程序的窗口 + 一个属于本程序的浏览器」。
//! 浏览器用户目录在 `data\WebView2`（自己的目录），不与旧版共享缓存、Cookie、LocalStorage——
//! 共享 UDF 会让两个程序互相顶掉对方的登录态，那是最隐蔽的一类串扰。
//!
//! 页面本身不做任何判断：按钮把命令原文交给宿主，宿主办完把新状态推回来。
//! 这样「点按钮」和「命令行调一次」走的是同一段逻辑，不会长出两套行为。

use std::cell::RefCell;
use std::rc::Rc;

use serde_json::Value;

#[cfg(target_os = "windows")]
mod native_pick {
    use std::ffi::c_void;

    #[repr(C)]
    struct OpenFileNameW {
        l_struct_size: u32,
        hwnd_owner: *mut c_void,
        h_instance: *mut c_void,
        filter: *const u16,
        custom_filter: *mut u16,
        max_custom_filter: u32,
        filter_index: u32,
        file: *mut u16,
        max_file: u32,
        file_title: *mut u16,
        max_file_title: u32,
        initial_dir: *const u16,
        title: *const u16,
        flags: u32,
        file_offset: u16,
        file_extension: u16,
        default_ext: *const u16,
        custom_data: isize,
        hook: *mut c_void,
        template_name: *const u16,
        reserved: *mut c_void,
        reserved_u32: u32,
        flags_ex: u32,
    }

    #[link(name = "comdlg32")]
    extern "system" {
        fn GetOpenFileNameW(ofn: *mut OpenFileNameW) -> i32;
        fn GetSaveFileNameW(ofn: *mut OpenFileNameW) -> i32;
        fn CommDlgExtendedError() -> u32;
    }

    // 文件对话框在独立线程上跑：WebView 的 IPC 回调在 UI 线程上，直接调用会
    // 把整个窗口的消泵一起压住，Windows 会把对话框标成「未响应」。
    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(reserved: *const c_void, flags: u32) -> i32;
        fn CoUninitialize();
    }

    const COINIT_APARTMENTTHREADED: u32 = 0x2;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 在独立 STA 线程上打开选择器：对话框有自己的消息泵，不会因为 UI 线程在等
    /// `join` 就被标成「未响应」。`Ok(None)` 仍然是用户取消。
    pub fn open_on_dialog_thread(title: &str, filter: &str) -> Result<Option<String>, String> {
        let title = title.to_string();
        let filter = filter.to_string();
        let handle = std::thread::Builder::new()
            .name("tc-file-dialog".to_string())
            .spawn(move || {
                unsafe {
                    CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED);
                }
                let result = open(&title, &filter);
                unsafe {
                    CoUninitialize();
                }
                result
            })
            .map_err(|e| format!("无法打开文件选择器：{e}"))?;
        handle.join().map_err(|_| "文件选择器线程异常退出".to_string())?
    }

    /// 打开系统文件选择器。`Ok(None)` 表示用户取消；`Err` 才是真的打不开。
    pub fn open(title: &str, filter: &str) -> Result<Option<String>, String> {
        let title_w = wide(title);
        let filter_w = wide(filter);
        let mut file = vec![0u16; 32768];
        let mut ofn: OpenFileNameW = unsafe { std::mem::zeroed() };
        ofn.l_struct_size = std::mem::size_of::<OpenFileNameW>() as u32;
        ofn.filter = filter_w.as_ptr();
        ofn.filter_index = 1;
        ofn.file = file.as_mut_ptr();
        ofn.max_file = file.len() as u32;
        ofn.title = title_w.as_ptr();
        // 文件必须存在、路径必须存在；不改变进程工作目录；使用新版对话框。
        ofn.flags = 0x0000_1000 | 0x0000_0800 | 0x0000_0008 | 0x0008_0000;
        let picked = unsafe { GetOpenFileNameW(&mut ofn) };
        if picked != 0 {
            let len = file.iter().position(|c| *c == 0).unwrap_or(file.len());
            return Ok(Some(String::from_utf16_lossy(&file[..len])));
        }
        let code = unsafe { CommDlgExtendedError() };
        if code == 0 {
            Ok(None)
        } else {
            Err(format!("文件选择器打不开（错误码 {code}）"))
        }
    }

    /// 打开系统「另存为」对话框。`Ok(None)` = 用户取消。
    ///
    /// 只改 `default_ext` 与初始文件名，其余与打开对话框共用同一个结构体布局。
    pub fn save(
        title: &str,
        filter: &str,
        suggested_name: &str,
        default_ext: &str,
    ) -> Result<Option<String>, String> {
        let title_w = wide(title);
        let filter_w = wide(filter);
        let ext_w = wide(default_ext);
        let mut file = vec![0u16; 32768];
        for (slot, ch) in file.iter_mut().zip(suggested_name.encode_utf16()) {
            *slot = ch;
        }
        let mut ofn: OpenFileNameW = unsafe { std::mem::zeroed() };
        ofn.l_struct_size = std::mem::size_of::<OpenFileNameW>() as u32;
        ofn.filter = filter_w.as_ptr();
        ofn.filter_index = 1;
        ofn.file = file.as_mut_ptr();
        ofn.max_file = file.len() as u32;
        ofn.title = title_w.as_ptr();
        ofn.default_ext = ext_w.as_ptr();
        // OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER
        ofn.flags = 0x0000_0002 | 0x0000_0800 | 0x0000_0008 | 0x0008_0000;
        let picked = unsafe { GetSaveFileNameW(&mut ofn) };
        if picked != 0 {
            let len = file.iter().position(|c| *c == 0).unwrap_or(file.len());
            return Ok(Some(String::from_utf16_lossy(&file[..len])));
        }
        let code = unsafe { CommDlgExtendedError() };
        if code == 0 {
            Ok(None)
        } else {
            Err(format!("保存对话框打不开（错误码 {code}）"))
        }
    }
}

/// 选择导入文件。只接受线路 JSON、可执行程序或 SSH 私钥；页面拿不到路径时由此补上。
#[cfg(target_os = "windows")]
/// 打开系统文件选择器。`slot` 同时决定**标题与文件名过滤器**：
/// - `"process"` → `*.exe`（「选择交易程序」，`pick-exe` 用；独立线程打开）
/// - `"engine"` → `*.exe`（「选择代理引擎程序」）
/// - `"key"` → `*.pem;*.key;*.ppk`（「选择 SSH 私钥文件」）
/// - `"recovery"` → `*.tcrecovery`（「选择加密管理恢复资料」）
/// - 其余（含缺省 `"profile"`）→ `*.json`（「选择线路文件」）
///
/// `.ppk` 不能从过滤器里排除：PuTTY 用户的私钥就是 `.ppk`，排除了等于让他们
/// 白选一次才发现「不支持」。真正的版本限制（只认 v2/v3）由解析那一步说清楚。
pub fn pick_file(slot: &str) -> Result<Option<String>, String> {
    if slot == "process" {
        native_pick::open_on_dialog_thread(
            "选择交易程序",
            "可执行程序 (*.exe)\u{0}*.exe\u{0}所有文件 (*.*)\u{0}*.*\u{0}\u{0}",
        )
    } else if slot == "engine" {
        native_pick::open(
            "选择代理引擎程序",
            "可执行程序 (*.exe)\u{0}*.exe\u{0}所有文件 (*.*)\u{0}*.*\u{0}\u{0}",
        )
    } else if slot == "key" {
        native_pick::open(
            "选择 SSH 私钥文件",
            // `*.*` **不能省**：`id_ed25519` 这种没有扩展名的钥是最常见的一种，
            // 只给 `*.pem;*.key;*.ppk` 会让它在默认过滤器下「明明有却看不见」。
            "SSH 私钥 (*.pem;*.key;*.ppk;*.*)\u{0}*.pem;*.key;*.ppk;*.*\u{0}所有文件 (*.*)\u{0}*.*\u{0}\u{0}",
        )
    } else if slot == "recovery" {
        native_pick::open(
            "选择加密管理恢复资料",
            "加密资料 (*.tcrecovery)\u{0}*.tcrecovery\u{0}所有文件 (*.*)\u{0}*.*\u{0}\u{0}",
        )
    } else {
        native_pick::open(
            "选择线路文件",
            "线路文件 (*.json)\u{0}*.json\u{0}所有文件 (*.*)\u{0}*.*\u{0}\u{0}",
        )
    }
}

/// 打开系统「另存为」对话框并写入文本。`Ok(None)` = 用户取消。
///
/// 目前只有「保存加密管理恢复资料」用它；过滤器与扩展名都按旧版的 `.tcrecovery`。
pub fn save_file(
    slot: &str,
    text: &str,
    suggested_name: &str,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "windows")]
    {
        if slot != "recovery" {
            return Err("这个保存槽位不支持。".to_string());
        }
        let path = native_pick::save(
            "保存加密管理恢复资料",
            "加密资料 (*.tcrecovery)\u{0}*.tcrecovery\u{0}\u{0}",
            suggested_name,
            "tcrecovery",
        )?;
        let Some(path) = path else {
            return Ok(None);
        };
        std::fs::write(&path, text)
            .map_err(|error| format!("写不了这个文件：{path}（{error}）"))?;
        Ok(Some(path))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (slot, text, suggested_name);
        Err("这个平台没有另存为对话框。".to_string())
    }
}

use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::WindowBuilder;
use wry::{WebView, WebViewBuilder};

type Handler = dyn Fn(&str) -> String + Send + Sync + 'static;
type Budget = dyn Fn(&str) -> f64 + Send + Sync + 'static;
type EventSink = dyn Fn(UiHostEvent) + Send + Sync + 'static;
type HostTrace = Option<std::sync::Arc<std::path::PathBuf>>;

fn host_trace_path(root: &str, isolated: bool, enabled: bool) -> HostTrace {
    (isolated && enabled).then(|| {
        std::sync::Arc::new(
            std::path::Path::new(root)
                .join("logs")
                .join("t09-host-events.jsonl"),
        )
    })
}

fn test_host_trace(root: &str) -> HostTrace {
    host_trace_path(
        root,
        std::env::var_os("SPIDERVPN_ROOT").is_some(),
        std::env::var("SPIDERVPN_TEST_HOST_TRACE").as_deref() == Ok("1"),
    )
}

/// 隔离验收专用：只记录调度元数据，不记录配置、命令回包或敏感业务载荷。
/// 默认路径为 None；测试钩子失败也不改变产品命令的受理与回包行为。
fn trace_host(trace: &HostTrace, action: &str, event: &UiHostEvent, evaluated: Option<bool>) {
    let Some(path) = trace else { return };
    let state = serde_json::from_str::<serde_json::Value>(&event.state).unwrap_or_default();
    let op = state.get("op").cloned().unwrap_or_default();
    let observed_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let record = serde_json::json!({
        "observedAtUnixMs": observed_at_unix_ms,
        "action": action,
        "threadId": format!("{:?}", std::thread::current().id()),
        "id": event.id,
        "cmd": event.cmd,
        "terminal": event.terminal,
        "op": op,
        "hasDiagnose": state.get("diagnose").is_some(),
        "hasCompatibleResult": state.get("compatibleResult").is_some(),
        "evaluateScriptOk": evaluated,
    });
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path.as_ref()) {
        use std::io::Write;
        // 整行一次写出去。原先是 `to_writer` 写完 JSON 再单独写一个换行——两次写之间
        // 若别的线程也进来写，两行就会交叉，整份轨迹里出现不可解析的行（r40 真机
        // 验收时 23 行好、4 行坏）。这份文件是排查「命令跑完了、页面却没动」的唯一
        // 证据，坏一行就可能正好吃掉关键事件。
        let mut line = record.to_string();
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

/// 工作线程只投递数据；WebView 的调用全部回到 tao UI 线程。
#[derive(Clone, Debug)]
struct UiHostEvent {
    id: u64,
    cmd: String,
    state: String,
    terminal: bool,
}

#[derive(Clone, Debug)]
struct ActiveOperation {
    id: u64,
    op: serde_json::Value,
}

/// 一次 `accept` 的结论。**三种都要分开**：重复点击不是「忙」，
/// 它应该重发当前进度（用户看到的是同一件事）；另一个命令在跑才是忙。
enum Accept {
    Start(ActiveOperation),
    Repeat(ActiveOperation),
    /// 闸门被别的命令占着：带上占用者，好把人话说全。
    Busy(String),
}

#[derive(Default)]
struct OperationBook {
    next_id: u64,
    active: std::collections::HashMap<String, ActiveOperation>,
    /// **全局单闸门**：同一时刻只允许一个长命令在跑，记下它是谁。
    ///
    /// 管道/CLI 侧本来就是单闸门（`ipc::respond` 用一把 `Mutex` 串行），
    /// 界面侧却一直按**命令名**去重——于是「连接」与「导入」可以同时跑：
    /// 一个在拨号，另一个在重写 `config.json`，后写者赢，前一条线路凭空消失。
    /// 这里把界面的口径对齐到管道：一条长命令在跑时，别的长命令一律挡下。
    ///
    /// 挡下而不是排队：排队会让「断开」在「自动选路」后面等几十秒，而用户
    /// 以为它已经开始；拒绝能立刻说清「正在做什么、该等谁」。
    holder: Option<String>,
}

impl OperationBook {
    /// 同命令 single-flight；不同命令一律挡在业务 handler 之前。
    fn accept(&mut self, cmd: &str, budget_sec: f64) -> Accept {
        if let Some(current) = self.active.get(cmd) {
            return Accept::Repeat(current.clone());
        }
        if let Some(holder) = self.holder.as_deref() {
            if holder != cmd {
                return Accept::Busy(holder.to_string());
            }
        }
        self.next_id += 1;
        let started = crate::selfcheck::at_rfc3339(crate::model::now_epoch_secs_u64());
        let op = serde_json::json!({
            "cmd": cmd,
            "phase": "queued",
            "startedAtUtc": started,
            "budgetSec": budget_sec,
        });
        let current = ActiveOperation { id: self.next_id, op };
        self.active.insert(cmd.to_string(), current.clone());
        self.holder = Some(cmd.to_string());
        Accept::Start(current)
    }

    fn complete(&mut self, event: &UiHostEvent) {
        if !event.terminal {
            return;
        }
        // 只认「属于这条命令、且是这一代」的终态：旧终态与别人被拒的事件
        // 都不许动闸门。
        if self.active.get(&event.cmd).map(|op| op.id) != Some(event.id) {
            return;
        }
        self.active.remove(&event.cmd);
        if self.holder.as_deref() == Some(event.cmd.as_str()) {
            self.holder = None;
        }
    }
}

fn operation_event(current: &ActiveOperation, phase: &str) -> UiHostEvent {
    let mut op = current.op.clone();
    op["phase"] = serde_json::json!(phase);
    UiHostEvent {
        id: current.id,
        cmd: current.op["cmd"].as_str().unwrap_or_default().to_string(),
        state: serde_json::json!({"operationOnly": true, "op": op}).to_string(),
        terminal: false,
    }
}

fn final_event(current: &ActiveOperation, reply: String) -> UiHostEvent {
    let mut state = serde_json::from_str::<serde_json::Value>(&reply).unwrap_or_else(|_| {
        serde_json::json!({
            "ok": false,
            "error": "宿主回包不是合法 JSON",
            "detail": "操作失败：宿主回包不是合法 JSON",
        })
    });
    let failed = state.get("ok").and_then(|v| v.as_bool()) == Some(false);
    let mut op = current.op.clone();
    op["phase"] = serde_json::json!(if failed { "failed" } else { "finished" });
    state["op"] = op;
    UiHostEvent {
        id: current.id,
        cmd: current.op["cmd"].as_str().unwrap_or_default().to_string(),
        state: state.to_string(),
        terminal: true,
    }
}

/// 被全局闸门挡下时回给页面的那一条。
///
/// 它**不是**一次操作：`op.phase = "refused"`，`finish_op` 看到这个相位只弹提示，
/// 不碰正在跑的那条的 `busy`/`operation`。`id = 0` 也保证 `complete` 不会误清闸门。
fn refuse_event(cmd: &str, message: &str) -> UiHostEvent {
    let op = serde_json::json!({
        "cmd": cmd,
        "phase": "refused",
        "startedAtUtc": crate::selfcheck::at_rfc3339(crate::model::now_epoch_secs_u64()),
        "budgetSec": 0.0,
    });
    UiHostEvent {
        id: 0,
        cmd: cmd.to_string(),
        state: serde_json::json!({
            "ok": false,
            "errorCode": "busy",
            "error": message,
            "detail": message,
            "operationOnly": true,
            "op": op,
        })
        .to_string(),
        terminal: true,
    }
}

/// 受理后立即返回 UI 线程；协调线程发心跳，业务线程只执行原 handler。
/// 超预算不会取消事务，也不会伪造 failed。
///
/// `journal` / `origin` 只对连接、断开、诊断三种命令生效：记录必须**先于**业务线程
/// 落盘（写不进去就不开始），结论在终态事件之前写回。重复提交不产生第二条记录。
///
/// 返回「这一次真的开始了」。自动路径（A5 等待态推进、连接中自动切换）要它：
/// 被闸门挡下时不能把「已经尝试过」记成「已经做过」，否则自动切换会白丢 10 分钟冷却。
fn submit_operation(
    book: &mut OperationBook,
    raw: String,
    budget_sec: f64,
    handler: std::sync::Arc<Handler>,
    sink: std::sync::Arc<EventSink>,
    journal: &crate::oprecord::Journal,
    origin: &str,
) -> bool {
    let Some(cmd) = crate::ipc::command_name(&raw) else { return false };
    let current = match book.accept(&cmd, budget_sec) {
        Accept::Start(current) => current,
        Accept::Repeat(current) => {
            // 同一条命令重复点击：重发当前进度，不再进业务 handler。
            sink(operation_event(&current, current.op["phase"].as_str().unwrap_or("running")));
            return false;
        }
        Accept::Busy(holder) => {
            // **用户点的那一次才回话。** 自动路径每一拍都会重试（A5 每秒一次、
            // 自动切换有退避），每次都弹一句「正在连接」等于噪音，而且那条
            // 提示会盖住用户真正在等的那条操作的状态。
            if origin == "ui" || origin == "tray" {
                let message = format!(
                    "正在{}，等它结束再试。",
                    crate::uiweb::command_label(&holder)
                );
                sink(refuse_event(&cmd, &message));
            }
            return false;
        }
    };
    let record = match crate::oprecord::kind_of_command(&cmd) {
        None => None,
        Some(kind) => match journal.begin(kind, origin) {
            Ok(record) => Some(record),
            Err(error) => {
                let message = format!("无法写入操作记录：{error}；本次操作没有开始");
                let event = final_event(
                    &current,
                    serde_json::json!({
                        "ok": false,
                        "errorCode": "record",
                        "error": message,
                        "detail": message,
                    })
                    .to_string(),
                );
                book.complete(&event);
                sink(event);
                return false;
            }
        },
    };
    let journal = journal.clone();
    sink(operation_event(&current, "queued"));
    std::thread::spawn(move || {
        let finish_record = |reply: &str| {
            let Some(record) = record.as_ref() else { return };
            let parsed = serde_json::from_str::<Value>(reply).ok();
            let ok = parsed
                .as_ref()
                .and_then(|value| value.get("ok"))
                .and_then(Value::as_bool)
                == Some(true);
            let text_of = |key: &str| {
                parsed
                    .as_ref()
                    .and_then(|value| value.get(key))
                    .and_then(Value::as_str)
                    .unwrap_or("")
            };
            let (phase, code, message) = if ok {
                (
                    crate::oprecord::SUCCEEDED,
                    "",
                    format!("{}完成", crate::oprecord::label(&record.kind)),
                )
            } else {
                let error = text_of("error");
                let detail = text_of("detail");
                let message = if !error.is_empty() {
                    error
                } else if !detail.is_empty() {
                    detail
                } else {
                    "操作失败"
                };
                (crate::oprecord::FAILED, text_of("errorCode"), message.to_string())
            };
            if let Err(error) = journal.finish(&record.id, phase, &message, code) {
                // 记录写不回去不改变业务结论：用户仍要看到真实结果，这里只留一行控制台。
                println!("  操作记录未落盘：{error}");
            }
        };
        sink(operation_event(&current, "running"));
        let (tx, rx) = std::sync::mpsc::channel();
        let worker_handler = std::sync::Arc::clone(&handler);
        std::thread::spawn(move || {
            let _ = tx.send(worker_handler(&raw));
        });
        loop {
            match rx.recv_timeout(std::time::Duration::from_secs(1)) {
                Ok(reply) => {
                    finish_record(&reply);
                    sink(final_event(&current, reply));
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    sink(operation_event(&current, "running"));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let reply = serde_json::json!({
                        "ok": false,
                        "error": "宿主命令异常结束",
                        "detail": "操作失败：宿主命令异常结束",
                    })
                    .to_string();
                    finish_record(&reply);
                    sink(final_event(&current, reply));
                    break;
                }
            }
        }
    });
    true
}

/// 去掉「每次都会变」的字段，用来判断一份快照值不值得再推给页面。
///
/// 只去 `State.SnapshotAtUtc`：它是心跳时间，不是业务状态。其余字段（Busy、Running、
/// 线路状态、Toast…）任何一项变了都必须推——跳过推送会让页面显示旧事实。
fn stable_snapshot(snapshot: &Value) -> String {
    let mut copy = snapshot.clone();
    if let Some(state) = copy.get_mut("State").and_then(Value::as_object_mut) {
        state.remove("SnapshotAtUtc");
    }
    copy.to_string()
}

/// 空闲补推的间隔：忙（长命令在跑）或有部署在跑时按 1 秒。
///
/// 部署不经过 `busy`（它是后台线程，不是「用户正在等一次同步结果」），所以
/// 必须单独问一句——否则进度条每 2 秒才动一次，看起来像卡住了。
fn snapshot_interval_ms(busy: bool, deploying: bool) -> u64 {
    if busy || deploying {
        1_000
    } else {
        2_000
    }
}

/// 「部署还在跑，所以不退出」的那张对话框。
///
/// 两处用它：关窗（托盘不可用时拒绝关闭）与托盘「退出」。文案必须给出**出路**，
/// 否则用户面对一个关不掉的窗口只能去任务管理器杀进程——那正是不许发生的事。
/// `tray` 决定要不要提「缩到托盘」这条出路：没有托盘还提它，等于指一条不存在的地方。
fn deploy_busy_dialog(sentence: &str, tray: bool) -> Value {
    let note = if tray {
        "要退出，先在「线路」页的任务列表里取消这些部署，或等它们做完。现在缩小到托盘可以让它们继续跑。"
    } else {
        "要退出，先在「线路」页的任务列表里取消这些部署，或等它们做完。托盘不可用，所以这次没有退出。"
    };
    serde_json::json!({
        "Id": "deploy-busy",
        "Title": "部署还在进行",
        // 正文就是那一句「还有 N 个部署没有完成」：条数与措辞都来自同一个地方，
        // 界面上不会出现「对话框说 2、托盘说 1」。
        "Body": format!("{sentence}。现在退出会把它打断，已经发出去的操作还要重新核对。"),
        "Note": note,
        "Confirm": "知道了",
        // 只有一个「知道了」：这里没有「继续退出」这个选项，所以不给第二个按钮。
        "Cancel": "",
        "Danger": false,
        "Details": "",
        "Progress": false,
        "Scope": "deploy-busy",
        "Target": "",
    })
}

/// 起窗口并进入消息循环。函数不返回（除非窗口创建失败）。
///
/// `state` 是初始状态 JSON；`handler` 收页面传来的原始字符串（一条 JSON 请求），返回新的状态 JSON。
/// 之所以传/返回字符串而不是结构体：宿主与页面的唯一契约就是那段 JSON，
/// 多一层类型转换只是多一处会漂移的地方。
///
/// `on_close` 在**真正退出**时执行一次（关窗退出、或托盘菜单「退出」），返回进程退出码。
/// 窗口这一层不关心「断开」是什么，只负责把退出时机交给调用方——它需要先断开再退出。
/// `close_to_tray` 决定关窗是「断开并退出」还是「藏到托盘、连接保持」；
/// `tray_ok` 是给调用方回读的「托盘到底起没起来」，状态里要如实告诉用户；
/// `deploying`（T09）让「有部署没跑完」这一维参与关窗判定与快照节拍。
pub fn run(
    root: &str,
    udf: &str,
    close_to_tray: bool,
    tray_ok: std::sync::Arc<std::sync::atomic::AtomicBool>,
    // 「现在有没有部署没跑完」：`Some(人话)` = 有。每次调用都读引擎的真实计数、
    // 不在这里缓存——缓存会让「刚跑完」的那一秒关不掉窗口。
    deploying: Box<dyn Fn() -> Option<String>>,
    handler: Box<Handler>,
    operation_budget: Box<Budget>,
    on_close: Box<dyn Fn() -> i32>,
) -> Result<(), String> {
    let event_loop = EventLoopBuilder::<UiHostEvent>::with_user_event().build();

    let window = WindowBuilder::new()
        .with_title("SpiderVPN")
        .with_inner_size(LogicalSize::new(1100.0, 780.0))
        .build(&event_loop)
        .map_err(|e| format!("窗口创建失败：{e}"))?;

    // 旧版web 前端不需要注入初始 HTML（资产经自定义协议伺服，状态经
    // __tcPush 推送）；render_page 仅剩测试在用。

    // 托盘：起不来就当没有，关窗自动退回「断开并退出」——不能出现「窗口藏了、托盘又没有」的死局。
    // 依赖 tray-icon 在自己的线程里跑消息循环，我们只在事件循环里轮询它投递的事件，不抢它的循环。
    let tray = crate::tray::tray_or_none(crate::tray::Tray::new);
    tray_ok.store(tray.is_some(), std::sync::atomic::Ordering::Relaxed);
    // 空闲时的关窗行为。**有部署在跑时会变**（`tray::close_decision` 多一维），
    // 所以这里只说明「没有部署时」会怎样——别让日志替另一条判定打包票。
    let close_idle = crate::tray::on_close(close_to_tray, tray.is_some());
    // 控制台留一行：托盘有没有起来、关窗会怎样，都得能在日志里查到（真机上没法靠眼睛点）。
    println!(
        "  托盘      ：{}（关窗：{}；有部署在跑时另有判定）",
        if tray.is_some() { "已就绪" } else { "不可用" },
        match close_idle {
            crate::tray::OnClose::HideToTray => "缩到托盘，连接保持",
            _ => "断开并退出",
        }
    );

    // IPC 回调要拿到 webview 才能把新状态推回页面，而 webview 要 build 之后才存在：
    // 先用共享槽位占位，build 完再放进去。回调只在 UI 线程上同步触发，那时槽位必然已填充。
    let slot: Rc<RefCell<Option<WebView>>> = Rc::new(RefCell::new(None));
    let slot_in_handler = Rc::clone(&slot);
    // web 前端的页面宿主状态（页码/Ack/Dialog/Toast/长命令 busy）。
    // 备用线路读数的缓存要与采样线程共享，所以先建好再挂上去。
    let standby_cache: std::sync::Arc<std::sync::Mutex<Vec<Value>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let webui: Rc<RefCell<crate::uiweb::WebUi>> = Rc::new(RefCell::new({
        let mut web = crate::uiweb::WebUi::new();
        web.standby = std::sync::Arc::clone(&standby_cache);
        web
    }));
    let webui_state = Rc::clone(&webui);
    let webui_event = Rc::clone(&webui);
    // 宿主文件拖放：OS 拖进来的 .exe 直接填进「交易程序」输入框；桌面快捷方式（.lnk）
    // 换成它指向的 exe 再填（判据在 `shortcut::executable_target`）。
    // 不要走 WebView 的 HTML5 drop：浏览器拿不到文件完整路径，旧版靠 WPF 的
    // `DragDrop` 事件，这里用 wry 的 OS 级 drag-drop 处理器对齐。
    let drag_ui = Rc::clone(&webui_state);
    let drag_slot = Rc::clone(&slot_in_handler);
    // 业务 handler 与预算计算器都可送入工作线程；WebView 本身绝不离开 UI 线程。
    let handler: std::sync::Arc<Handler> = std::sync::Arc::from(handler);
    let operation_budget: std::sync::Arc<Budget> = std::sync::Arc::from(operation_budget);
    let handler_page = std::sync::Arc::clone(&handler);
    let drag_handler = std::sync::Arc::clone(&handler_page);
    let budget_page = std::sync::Arc::clone(&operation_budget);
    let slot_for_tray = Rc::clone(&slot);
    let operations: Rc<RefCell<OperationBook>> = Rc::new(RefCell::new(OperationBook::default()));
    let operations_page = Rc::clone(&operations);
    let host_trace = test_host_trace(root);
    let trace_sink = host_trace.clone();
    let proxy = event_loop.create_proxy();
    let sink: std::sync::Arc<EventSink> = std::sync::Arc::new(move |event| {
        trace_host(&trace_sink, "event-sent", &event, None);
        let _ = proxy.send_event(event);
    });
    let sink_page = std::sync::Arc::clone(&sink);
    // A5/A6：界面长操作的记录。三处入口（页面、空闲推进、托盘）写同一个数据根，
    // 页面闭包与事件循环各持一份克隆。
    let journal = crate::oprecord::Journal::new(root);
    let journal_page = journal.clone();

    // 浏览器用户目录必须显式指定：wry 默认会在 exe 同级建 `*.exe.WebView2`，
    // 那既不在我们的数据根里，也会随安装位置漂移。UDF 共享会让两个程序互相顶掉登录态。
    //
    // 页面必须从稳定的 origin 提供：`with_html` 走 WebView2 的 NavigateToString，
    // origin 是 `null`（opaque），`localStorage` 会直接抛 SecurityError。自定义协议在
    // Windows 上映射为 `http://tc.ui`，origin 稳定，存储随上面的 UDF 持久化。
    //
    // 前端是 旧版的 web\ 资产（index.html + app.js + 3 个 CSS，见 web\ 目录）。
    // CSP 是 script-src 'self'，所以每个文件都必须按路径伺服，不能内联。
    let mut context = wry::WebContext::new(Some(std::path::PathBuf::from(udf)));
    let webview = WebViewBuilder::new_with_web_context(&mut context)
        .with_custom_protocol("tc".into(), move |_id, req| {
            match crate::uiweb::asset(req.uri().path()) {
                Some((mime, bytes)) => wry::http::Response::builder()
                    .header("Content-Type", mime)
                    .body(std::borrow::Cow::Borrowed(bytes))
                    .expect("asset response"),
                None => wry::http::Response::builder()
                    .status(404)
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .body(std::borrow::Cow::Borrowed(&b"not found"[..]))
                    .expect("404 response"),
            }
        })
        .with_url(crate::uiweb::PAGE_ORIGIN_URL)
        .with_initialization_script(crate::uiweb::INIT_SCRIPT)
        .with_ipc_handler(move |req: wry::http::Request<String>| {
            let raw = req.body().to_string();
            // web 前端的消息形如 {"Type":"connect",…}；其余（{cmd:…}）是旧自建页面的
            // 通道，调试期可能混发——按旧路径保底，不走意图翻译。
            let is_web = serde_json::from_str::<serde_json::Value>(&raw)
                .ok()
                .and_then(|v| {
                    v.get("Type")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .is_some();
            let fetch = |cmd: &str| {
                serde_json::from_str::<Value>(&(handler_page)(cmd)).unwrap_or(Value::Null)
            };
            if !is_web {
                let state = handler_page(&raw);
                if let Some(w) = slot_in_handler.borrow().as_ref() {
                    let _ = w.evaluate_script(&format!("window.__tcApply({state})"));
                }
                return;
            }
            // 意图 → 既有命令。长命令进预算通道，完成时经 UiHostEvent 回推快照。
            let steps = {
                let mut web = webui_state.borrow_mut();
                web.route(&raw, &fetch)
            };
            let mut long_ran = false;
            for step in steps {
                match step {
                    crate::uiweb::Step::Sync(cmd) => {
                        let reply_text = handler_page(&cmd);
                        if let Ok(reply) = serde_json::from_str::<Value>(&reply_text) {
                            let mut web = webui_state.borrow_mut();
                            // 表单里的命令（改名/连接方式）自己处理回包：成功要关表单、
                            // 失败要把宿主原话留在页面上，不能被通用 Toast 覆盖。
                            let had_form = web.form.is_some();
                            web.absorb_reply(&cmd, &reply);
                            if !had_form {
                                web.toast_from_reply(&reply, "");
                            }
                        }
                    }
                    // 一次性递送（邀请码）：不进快照，也不等回包。
                    crate::uiweb::Step::Script(code) => {
                        if let Some(w) = slot_in_handler.borrow().as_ref() {
                            let _ = w.evaluate_script(&code);
                        }
                    }
                    crate::uiweb::Step::Long(cmd) => {
                        long_ran = true;
                        let budget = budget_page(&cmd);
                        submit_operation(
                            &mut operations_page.borrow_mut(),
                            cmd,
                            budget,
                            std::sync::Arc::clone(&handler_page),
                            std::sync::Arc::clone(&sink_page),
                            &journal_page,
                            "ui",
                        );
                    }
                }
            }
            if long_ran {
                // 长命令结束后由 UiHostEvent 统一推送；这里不再重复推。
                return;
            }
            let snap = webui_state.borrow_mut().snapshot(&fetch);
            if let Some(w) = slot_in_handler.borrow().as_ref() {
                let _ = w.evaluate_script(&format!("window.__tcPush({snap})"));
            }
        })
        .with_drag_drop_handler(move |event| {
            // 只处理「放下」；拖入/移动交给系统默认指针。
            let wry::DragDropEvent::Drop { paths, .. } = event else {
                return false;
            };
            // 表单改完只推一份快照，**不写配置**：与「浏览…」一致，点「添加程序」才落盘。
            let push = || {
                let fetch = |cmd: &str| {
                    serde_json::from_str::<Value>(&(drag_handler)(cmd)).unwrap_or(Value::Null)
                };
                let snap = drag_ui.borrow_mut().snapshot(&fetch);
                if let Some(w) = drag_slot.borrow().as_ref() {
                    let _ = w.evaluate_script(&format!("window.__tcPush({snap})"));
                }
            };
            // 候选路径怎么算只有一处（`shortcut::executable_target`）：`.exe` 直通，
            // 桌面快捷方式换成它指向的 exe——配置里必须是能拿去匹配进程的真实路径，
            // 存一条 `.lnk` 的路径只会「加进去了但永远匹配不到」。多个文件取第一个能用的。
            let program = paths
                .iter()
                .find_map(|path| crate::shortcut::executable_target(path));
            let Some(program) = program else {
                // 换不出程序。拖的是快捷方式就**必须**说一句：桌面上的图标几乎都是 `.lnk`，
                // 静默丢掉等于用户看到的「拖了没反应」。别的文件类型（.txt 之类）不接管、
                // 也不吭声——那不是这一页的东西，交给页面自己处理。
                //
                // 这里的 `return false` 只表达「**我们**不处理、不写表单」，**不**表示
                // 「OLE 层会把这次拖放交还给页面」——后者当前根本不可观测：wry 0.57.1 的
                // `IDropTarget::Drop` 把 handler 的返回值整个丢掉，`_pdwEffect` 也没人写
                // （webview2/drag_drop.rs 的 Drop 分支），而 `DragEnter` 只要有文件就无条件
                // 回 `DROPEFFECT_COPY`（同文件 DragEnter 分支）。所以 `DoDragDrop` 的 EFFECT
                // 永远是 Copy——拿它判断「有没有被接住」只会误判。
                let Some(shortcut) = paths.iter().find(|path| crate::shortcut::is_shortcut(path))
                else {
                    return false;
                };
                let said = {
                    let mut web = drag_ui.borrow_mut();
                    web.form
                        .as_mut()
                        .map(|form| form.notice_program_unusable(&shortcut.to_string_lossy()))
                        .unwrap_or(false)
                };
                if !said {
                    // 不在「交易软件名单」页：不吞这次拖放。
                    return false;
                }
                push();
                return true;
            };
            let path = program.to_string_lossy().to_string();
            let accepted = {
                let mut web = drag_ui.borrow_mut();
                web.form
                    .as_mut()
                    .map(|form| form.fill_program_path(&path))
                    .unwrap_or(false)
            };
            if !accepted {
                // 不在「交易软件名单」页：不吞这次拖放（`false` 只表示我们没接、没写表单，
                // 不代表会退回给页面——见上面那段）。
                return false;
            }
            push();
            true
        })
        .build(&window)
        .map_err(|e| format!("WebView2 初始化失败：{e}"))?;
    // 到这里才把 webview 放进去。webview 与这个槽位互相持有（Rc 环），
    // 但 `run` 随窗口关闭结束、进程随即退出，不需要额外拆环。
    *slot.borrow_mut() = Some(webview);

    let has_tray = tray.is_some();
    // 托盘提示当前说的是不是「有部署在跑」。只在翻转时改一次：`set_tooltip` 是
    // 跨线程调 Win32，没必要每秒来一遍。
    let mut tooltip_busy = false;
    let mut last_idle_push = std::time::Instant::now();
    // 最近一次真正推到页面的快照（去掉每次都会变的时间戳）与推送时刻。
    // 用途：页面每收到一份快照就整页重画，空闲时每秒推一份会让 WebView2 常驻烧 CPU。
    let mut last_pushed_stable: Option<String> = None;
    let mut last_push_at = std::time::Instant::now();
    // 连接期间的响应采样节拍：旧版的宿主也是每 30 秒取一次线路质量。
    // 这里只负责「到点起一个后台测量」，测量本身仍走既有 measure-latency。
    let mut last_quality_sample = std::time::Instant::now();
    // 备用线路读数：与线路质量同一个 30 秒节拍，但只在连接中、且不忙时跑。
    let mut last_standby_probe = std::time::Instant::now();
    // A8 连接中监测：60 秒看一次网络/质量，真正切换另有 10 分钟冷却
    // （探测与重连本身有成本，不能让「还没恢复」变成每分钟断一次）。
    let mut last_auto_watch = std::time::Instant::now();
    let mut last_auto_switch = std::time::Instant::now();
    // 自动切换被闸门挡下时记这一笔。不这么做的话：挡下 → 10 分钟冷却照扣
    // （白丢一次切换），不扣又会每秒重试一次（每秒一次拒绝事件）。
    // 折中是「挡下后 30 秒再看」，两次都不糟。
    let mut last_auto_defer = std::time::Instant::now() - std::time::Duration::from_secs(600);
    // 托盘是 build 之后才建好的，而首屏状态在更早就算好了：进循环第一圈补推一次，
    // 让页面拿到真实的 trayAvailable（否则「托盘不可用」永远显示不出来）。
    // （首帧快照的推送由事件循环里「页面 ready 前周期重推」负责，见下。）
    event_loop.run(move |event, _, control_flow| {
        // 有托盘时必须定期醒来轮询（tray-icon 在自己的线程收消息，不会叫醒这个事件循环）；
        // 页面就绪后也要每秒醒一次补推快照——app.js 用 SnapshotAtUtc 判「数据过期」，
        // 只在事件时推会让空闲页面在 10 秒后自己变旧（横幅 + 标题降级成「状态未知」）。
        let ready_now = webui_event.borrow().ready;
        // 这一帧的「有没有部署没跑完」。**同一帧内只问一次**：关窗判定、托盘退出判定、
        // 快照节拍、托盘提示都用它，四处看到的必须是同一个答案。
        // 跨帧不缓存：部署刚跑完的那一秒，窗口就该能关掉。
        let deploy_busy = deploying();
        if let Some(t) = tray.as_ref() {
            if deploy_busy.is_some() != tooltip_busy {
                tooltip_busy = deploy_busy.is_some();
                match deploy_busy.as_deref() {
                    Some(sentence) => t.set_tooltip(sentence),
                    None => t.set_tooltip(crate::tray::TOOLTIP_IDLE),
                }
            }
        }
        *control_flow = if has_tray || !ready_now {
            ControlFlow::WaitUntil(std::time::Instant::now() + std::time::Duration::from_millis(200))
        } else {
            ControlFlow::WaitUntil(std::time::Instant::now() + std::time::Duration::from_millis(1000))
        };

        // 页面 ready（app.js 注册好监听器）之前，每 200ms 重推一次首帧快照：
        // 只推一次会跟页面加载竞速，事件丢失后页面永远停在「正在读取连接状态」。
        // 上限 100 次（20 秒）兜底，避免页面脚本坏了以后白转。
        if !webui_event.borrow().ready && webui_event.borrow().ready_pushes < 100 {
            webui_event.borrow_mut().ready_pushes += 1;
            let fetch = |cmd: &str| {
                serde_json::from_str::<Value>(&(handler)(cmd)).unwrap_or(Value::Null)
            };
            let snap = webui_event.borrow_mut().snapshot(&fetch);
            if let Some(w) = slot_for_tray.borrow().as_ref() {
                let _ = w.evaluate_script(&format!("window.__tcPush({snap})"));
            }
        }

        // 空闲补推：页面就绪后按节拍投影一次快照。
        //
        // 但**只有内容真的变了、或距上次推送超过 6 秒**才发给页面：app.js 每收到
        // 一份快照就整页重画，空闲时每秒推一份会让 WebView2 常驻多烧 3~4% 单核
        // （实测：6.7% → 见 docs/baseline-0.1.4.md 的性能实测一节）。
        // 6 秒仍小于 app.js 的 10 秒「数据过期」阈值，横幅不会被误触发。
        //
        // 忙的时候保持每秒一推：页面上的已用秒数靠 SnapshotAtUtc 走字，不能停。
        if ready_now {
            let busy_now = webui_event.borrow().busy;
            let interval = snapshot_interval_ms(busy_now, deploy_busy.is_some());
            if last_idle_push.elapsed() >= std::time::Duration::from_millis(interval) {
                last_idle_push = std::time::Instant::now();
                let fetch = |cmd: &str| {
                    serde_json::from_str::<Value>(&(handler)(cmd)).unwrap_or(Value::Null)
                };
                // A5：等待态推进。没有等待态时这里只是一次 `Option` 判空；
                // 有等待态且名单程序已退出时，会真的发起连接（`use` + `connect`），
                // 与用户点「连接」走同一条预算通道。
                let pending_steps = webui_event.borrow_mut().poll_pending_connect(&fetch);
                if !pending_steps.is_empty() {
                    let mut started = false;
                    for step in pending_steps {
                        match step {
                            crate::uiweb::Step::Sync(cmd) => {
                                let reply_text = handler(&cmd);
                                if let Ok(reply) = serde_json::from_str::<Value>(&reply_text) {
                                    webui_event.borrow_mut().absorb_reply(&cmd, &reply);
                                }
                            }
                            crate::uiweb::Step::Long(cmd) => {
                                started = true;
                                let budget = operation_budget(&cmd);
                                submit_operation(
                                    &mut operations.borrow_mut(),
                                    cmd,
                                    budget,
                                    std::sync::Arc::clone(&handler),
                                    std::sync::Arc::clone(&sink),
                                    &journal,
                                    "poll",
                                );
                            }
                            crate::uiweb::Step::Script(_) => {}
                        }
                    }
                    if started {
                        // 长命令结束后由 UiHostEvent 统一推快照，这里不再重复推。
                        return;
                    }
                }
                let snap = webui_event.borrow_mut().snapshot(&fetch);
                let stable = stable_snapshot(&snap);
                let stale =
                    last_push_at.elapsed() >= std::time::Duration::from_millis(6_000);
                if busy_now || stale || last_pushed_stable.as_deref() != Some(stable.as_str()) {
                    if let Some(w) = slot_for_tray.borrow().as_ref() {
                        let _ = w.evaluate_script(&format!("window.__tcPush({snap})"));
                    }
                    last_pushed_stable = Some(stable);
                    last_push_at = std::time::Instant::now();
                }
            // 连接中每 30 秒补一次响应采样。忙（有长命令在跑）时跳过：
            // 测量自己要读引擎端口，跟连接/断开抢时间只会得到假读数。
            let running = snap
                .get("State")
                .and_then(|s| s.get("Running"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if running
                && !webui_event.borrow().busy
                && last_quality_sample.elapsed() >= std::time::Duration::from_secs(30)
            {
                last_quality_sample = std::time::Instant::now();
                let sampler = std::sync::Arc::clone(&handler);
                std::thread::spawn(move || {
                    let _ = sampler(r#"{"cmd":"measure-latency"}"#);
                });
            }
            // 备用线路读数（T-18 的 measure-backup，只建 TCP 不穿隧道）。
            // 同一节拍但不与上面共用计时：测速失败不该把备用读数一起饿死。
            if running
                && !webui_event.borrow().busy
                && last_standby_probe.elapsed() >= std::time::Duration::from_secs(30)
            {
                last_standby_probe = std::time::Instant::now();
                let sampler = std::sync::Arc::clone(&handler);
                let cache = std::sync::Arc::clone(&standby_cache);
                std::thread::spawn(move || {
                    let lines: Value =
                        serde_json::from_str(&sampler(r#"{"cmd":"lines"}"#)).unwrap_or(Value::Null);
                    let selected = lines.get("selected").and_then(Value::as_str).unwrap_or("").to_string();
                    let mut measured = Vec::new();
                    let targets = lines
                        .get("lines")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    for line in targets.iter().take(8) {
                        let id = line.get("id").and_then(Value::as_str).unwrap_or("");
                        if id.is_empty() || id == selected {
                            continue;
                        }
                        let cmd = serde_json::json!({"cmd": "measure-backup", "lineId": id}).to_string();
                        let reply: Value =
                            serde_json::from_str(&sampler(&cmd)).unwrap_or(Value::Null);
                        if let Some(result) = reply.get("backupResult") {
                            // 只有真的探过（reachable 是布尔）才算一条读数：
                            // 「本版不测」这类拒绝不能变成「响应 —」挂在卡片上。
                            if !result.get("reachable").map(Value::is_boolean).unwrap_or(false) {
                                continue;
                            }
                            let at = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() as i64)
                                .unwrap_or(0);
                            measured.push(serde_json::json!({
                                "NodeId": id,
                                "LineName": result.get("lineName").cloned().unwrap_or(serde_json::json!("")),
                                "LatencyMs": result.get("latencyMs").cloned().unwrap_or(Value::Null),
                                "AtUnix": at,
                            }));
                        }
                    }
                    if let Ok(mut guard) = cache.lock() {
                        *guard = measured;
                    }
                });
            }
            // A8 连接中持续监测：网络变了或连续变差就自动换一种走法。
            // 只碰「自动」档：固定了连接方式的线路，用户的选择不能被后台改掉。
            if running
                && !webui_event.borrow().busy
                && last_auto_watch.elapsed() >= std::time::Duration::from_secs(60)
            {
                last_auto_watch = std::time::Instant::now();
                let lines: Value =
                    serde_json::from_str(&(handler)(r#"{"cmd":"lines"}"#)).unwrap_or(Value::Null);
                let selected = lines
                    .get("selected")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let line = lines
                    .get("lines")
                    .and_then(Value::as_array)
                    .and_then(|items| {
                        items.iter().find(|line| {
                            line.get("id").and_then(Value::as_str) == Some(selected.as_str())
                        })
                    })
                    .cloned()
                    .unwrap_or(Value::Null);
                let automatic = line
                    .get("transportSelected")
                    .and_then(Value::as_bool)
                    .map(|fixed| !fixed)
                    .unwrap_or(false);
                if automatic {
                    let routes: Value =
                        serde_json::from_str(&(handler)(r#"{"cmd":"auto-route-list"}"#))
                            .unwrap_or(Value::Null);
                    let changed = routes
                        .pointer(&format!("/autoRoutes/Lines/{selected}/NetworkChanged"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let mut reason = if changed { "network" } else { "" };
                    if reason.is_empty() {
                        // 证据没变时再看质量：连续三次差/没读数才算「变差」，
                        // 单次抖动不触发切换。
                        let transport = line
                            .get("transport")
                            .and_then(Value::as_str)
                            .unwrap_or("udp");
                        let profile = if transport == "udp" { "标准" } else { "兼容" };
                        let probe = serde_json::json!({
                            "cmd": "quality-summary",
                            "id": selected,
                            "profile": profile,
                        })
                        .to_string();
                        let summary: Value =
                            serde_json::from_str(&(handler)(&probe)).unwrap_or(Value::Null);
                        if summary
                            .pointer("/qualitySummary/Degraded")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                        {
                            reason = "quality";
                        }
                    }
                    if !reason.is_empty()
                        && last_auto_switch.elapsed() >= std::time::Duration::from_secs(600)
                        && last_auto_defer.elapsed() >= std::time::Duration::from_secs(30)
                    {
                        let cmd = serde_json::json!({
                            "cmd": "auto-reroute",
                            "line": selected,
                            "reason": reason,
                        })
                        .to_string();
                        let started = submit_operation(
                            &mut operations.borrow_mut(),
                            cmd,
                            operation_budget("auto-reroute"),
                            std::sync::Arc::clone(&handler),
                            std::sync::Arc::clone(&sink),
                            &journal,
                            "auto",
                        );
                        // 真的开始跑才扣 10 分钟冷却；被闸门挡下只退 30 秒再看。
                        if started {
                            last_auto_switch = std::time::Instant::now();
                        } else {
                            last_auto_defer = std::time::Instant::now();
                        }
                        // 长命令结束后由 UiHostEvent 统一推快照。
                        return;
                    }
                }
            }
            }
        }

        if let Event::UserEvent(host) = &event {
            trace_host(&host_trace, "ui-event-received", host, None);
            operations.borrow_mut().complete(host);
            // 长命令（连接/断开/测速/诊断/还原/导入）结束：清 busy，失败时把宿主
            // 的那句话放进 Toast，然后推一份新快照——页面据此解除等待态。
            let host_state: Value =
                serde_json::from_str(&host.state).unwrap_or(Value::Null);
            // 「自己搭服务器」：读指纹的长命令结束后，表单会交回下一步（直接开始，
            // 或先弹「确认首次服务器身份」）。在这里就地执行，用户看到的就是
            // 「点一次开始部署 → 指纹核对完 → 直接进入部署」。
            let followups = webui_event.borrow_mut().finish_op(&host_state);
            for step in followups {
                match step {
                    crate::uiweb::Step::Sync(cmd) => {
                        let reply_text = (handler)(&cmd);
                        if let Ok(reply) = serde_json::from_str::<Value>(&reply_text) {
                            webui_event.borrow_mut().absorb_reply(&cmd, &reply);
                        }
                    }
                    crate::uiweb::Step::Long(cmd) => {
                        let budget = operation_budget(&cmd);
                        submit_operation(
                            &mut operations.borrow_mut(),
                            cmd,
                            budget,
                            std::sync::Arc::clone(&handler),
                            std::sync::Arc::clone(&sink),
                            &journal,
                            "ui",
                        );
                    }
                    crate::uiweb::Step::Script(_) => {}
                }
            }
            let fetch = |cmd: &str| {
                serde_json::from_str::<Value>(&(handler)(cmd)).unwrap_or(Value::Null)
            };
            let snap = webui_event.borrow_mut().snapshot(&fetch);
            if let Some(w) = slot_for_tray.borrow().as_ref() {
                let evaluated = w.evaluate_script(&format!("window.__tcPush({snap})"));
                trace_host(
                    &host_trace,
                    "ui-evaluate-script",
                    host,
                    Some(evaluated.is_ok()),
                );
            }
        }

        if let Some(t) = tray.as_ref() {
            for cmd in t.poll() {
                match cmd {
                    crate::tray::Cmd::Show => {
                        window.set_visible(true);
                        window.set_focus();
                    }
                    // 托盘菜单的「连接」「断开」与界面按钮走同一个 handler：一条路径，不会长出两套行为。
                    crate::tray::Cmd::Connect | crate::tray::Cmd::Disconnect => {
                        let raw = if cmd == crate::tray::Cmd::Connect {
                            r#"{"cmd":"connect"}"#
                        } else {
                            r#"{"cmd":"disconnect"}"#
                        };
                        // 界面要立刻进入等待态：busy 与 Operation 与按钮路径同源。
                        {
                            let mut web = webui_event.borrow_mut();
                            web.busy = true;
                            web.operation = Some(serde_json::json!({
                                "Kind": if cmd == crate::tray::Cmd::Connect { "Connect" } else { "Disconnect" },
                                // A5：托盘发起的连接/断开同样可以「停止等待」；终态到达时
                                // `finish_op` 按 `Cmd` 判断它是不是被停止等待的那一条。
                                "Cmd": if cmd == crate::tray::Cmd::Connect { "connect" } else { "disconnect" },
                                "CanCancel": true,
                                "Detached": false,
                                "LineId": "", "Name": "", "Message": "", "StartedAtUtc": "",
                            }));
                        }
                        let budget = operation_budget(raw);
                        submit_operation(
                            &mut operations.borrow_mut(),
                            raw.to_string(),
                            budget,
                            std::sync::Arc::clone(&handler),
                            std::sync::Arc::clone(&sink),
                            &journal,
                            "tray",
                        );
                    }
                    // 托盘「退出」与关窗退出**同一条清理路径**：先断开再退出，不给旁路。
                    // 但 T09 起多一道闸：有部署没跑完时**不退出**，把窗口叫出来说明原因。
                    // 从托盘点「退出」的人多半以为没人在用，这时悄悄杀掉部署最伤的信任。
                    crate::tray::Cmd::Quit => match deploy_busy.as_deref() {
                        Some(sentence) => {
                            println!("  托盘退出：{sentence}，已取消退出");
                            window.set_visible(true);
                            window.set_focus();
                            let fetch = |cmd: &str| {
                                serde_json::from_str::<Value>(&(handler)(cmd))
                                    .unwrap_or(Value::Null)
                            };
                            let snap = {
                                let mut web = webui_event.borrow_mut();
                                web.dialog = Some(deploy_busy_dialog(sentence, has_tray));
                                web.snapshot(&fetch)
                            };
                            if let Some(w) = slot_for_tray.borrow().as_ref() {
                                let _ = w.evaluate_script(&format!("window.__tcPush({snap})"));
                            }
                        }
                        None => {
                            *control_flow = ControlFlow::ExitWithCode(on_close());
                        }
                    },
                }
            }
        }

        // 窗口重新获得焦点：刷新服务商列表。命令行改过注册表后切回窗口即见最新，
        // 不必重开界面。事件驱动——页面有断言禁止 setInterval 轮询。
        if let Event::WindowEvent { event: WindowEvent::Focused(true), .. } = event {
            // 窗口重新聚焦时刷新服务商结论（旧版同款时机）；快照全量推送覆盖它。
            let fetch = |cmd: &str| {
                serde_json::from_str::<Value>(&(handler)(cmd)).unwrap_or(Value::Null)
            };
            let snap = webui_event.borrow_mut().snapshot(&fetch);
            if let Some(w) = slot_for_tray.borrow().as_ref() {
                let _ = w.evaluate_script(&format!("window.__tcPush({snap})"));
            }
        }

        if let Event::WindowEvent { event: WindowEvent::CloseRequested, .. } = event {
            // 判定只有一份（`tray::close_decision`）。多出来的那一维是「有部署没跑完」：
            // 有它时托盘优先（部署继续），没托盘则**拒绝关窗**——窗口可以再叫出来，
            // 被打断的部署不能「再叫回来」。
            match crate::tray::close_decision(close_to_tray, has_tray, deploy_busy.is_some()) {
                // 藏起来，连接保持；退出只能走托盘「退出」——它会先断开。
                crate::tray::OnClose::HideToTray => {
                    window.set_visible(false);
                    if let Some(sentence) = deploy_busy.as_deref() {
                        println!("  关窗：{sentence}，已缩到托盘继续");
                        // 下次开窗时先看到这句话，不然用户不知道刚才为什么没退成。
                        webui_event.borrow_mut().toast = format!("{sentence}，已缩到托盘继续。");
                    }
                }
                // 关窗必须先断开再退出：否则窗口没了、引擎还在跑、系统代理还指着我们。
                // 用户以为关干净了，实际网络挂在代理上；引擎被系统回收后更糟——代理指向一个
                // 不存在的服务，表现为直接断网。清理失败也要退出，只是把退出码带出去。
                crate::tray::OnClose::DisconnectAndExit => {
                    *control_flow = ControlFlow::ExitWithCode(on_close());
                }
                // 没托盘 + 有部署：藏了就叫不出来，退了就打断部署。把窗口留住，把原因摆脸上。
                crate::tray::OnClose::RefuseAndShowDialog => {
                    if let Some(sentence) = deploy_busy.as_deref() {
                        println!("  关窗：{sentence}，托盘不可用，已拒绝关闭");
                        window.set_visible(true);
                        window.set_focus();
                        let fetch = |cmd: &str| {
                            serde_json::from_str::<Value>(&(handler)(cmd))
                                .unwrap_or(Value::Null)
                        };
                        let snap = {
                            let mut web = webui_event.borrow_mut();
                            web.dialog = Some(deploy_busy_dialog(sentence, has_tray));
                            web.snapshot(&fetch)
                        };
                        if let Some(w) = slot_for_tray.borrow().as_ref() {
                            let _ = w.evaluate_script(&format!("window.__tcPush({snap})"));
                        }
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 只差心跳时间不算变化；业务状态变了必须推。
    /// 这条错了的表现是「界面停在旧状态」，所以它比性能收益更值得钉住。
    #[test]
    fn only_the_heartbeat_timestamp_is_ignored_when_deciding_to_push() {
        let a = serde_json::json!({
            "State": {"SnapshotAtUtc": "2026-01-01T00:00:00Z", "Busy": false, "Running": false}
        });
        let b = serde_json::json!({
            "State": {"SnapshotAtUtc": "2026-01-01T00:00:05Z", "Busy": false, "Running": false}
        });
        assert_eq!(stable_snapshot(&a), stable_snapshot(&b), "只差心跳时间不算变化");

        let c = serde_json::json!({
            "State": {"SnapshotAtUtc": "2026-01-01T00:00:05Z", "Busy": true, "Running": false}
        });
        assert_ne!(stable_snapshot(&a), stable_snapshot(&c), "Busy 变了必须推");

        let d = serde_json::json!({
            "State": {"SnapshotAtUtc": "2026-01-01T00:00:05Z", "Busy": false, "Running": true}
        });
        assert_ne!(stable_snapshot(&a), stable_snapshot(&d), "Running 变了必须推");
    }

    /// 有部署在跑时快照必须每秒算一次：任务行的 `N/4` 与原因靠它更新。
    ///
    /// 部署不走 `busy`（它是后台线程，不是「用户正在等一次同步结果」），
    /// 少了这一维就会退回 2 秒一帧，看起来像卡住。
    #[test]
    fn a_running_deployment_keeps_the_snapshot_tick_at_one_second() {
        assert_eq!(snapshot_interval_ms(false, false), 2_000, "空闲：2 秒一帧（省 CPU）");
        assert_eq!(snapshot_interval_ms(true, false), 1_000, "长命令在跑");
        assert_eq!(snapshot_interval_ms(false, true), 1_000, "部署在跑");
        assert_eq!(snapshot_interval_ms(true, true), 1_000);
    }

    /// 拒绝退出的对话框：条数来自同一个来源，出路按「有没有托盘」换，且不给「继续退出」。
    #[test]
    fn the_busy_dialog_says_how_many_and_which_way_is_out() {
        let with_tray = deploy_busy_dialog("还有 2 个部署没有完成", true);
        assert_eq!(with_tray["Title"], "部署还在进行");
        assert_eq!(with_tray["Scope"], "deploy-busy");
        let body = with_tray["Body"].as_str().unwrap_or("");
        assert!(body.contains("还有 2 个部署没有完成"), "{body}");
        assert!(body.contains("打断"), "要说清为什么不让退：{body}");
        assert_eq!(with_tray["Confirm"], "知道了");
        assert_eq!(
            with_tray["Cancel"], "",
            "这里没有「继续退出」这个选项，就别给第二个按钮"
        );
        assert_eq!(with_tray["Danger"], false, "不是危险操作，别染成红色");
        assert!(
            with_tray["Note"].as_str().unwrap_or("").contains("缩小到托盘"),
            "有托盘就要指出这条出路"
        );

        // 没有托盘时**不许**指一条不存在的路。
        let no_tray = deploy_busy_dialog("还有 1 个部署没有完成", false);
        let note = no_tray["Note"].as_str().unwrap_or("");
        assert!(!note.contains("缩小到托盘"), "{note}");
        assert!(note.contains("托盘不可用"), "{note}");
        assert!(note.contains("取消"), "要给出真正的出路：{note}");
    }

    #[test]
    fn host_trace_requires_both_isolation_and_explicit_opt_in() {
        assert!(host_trace_path("root", false, false).is_none());
        assert!(host_trace_path("root", true, false).is_none());
        assert!(host_trace_path("root", false, true).is_none());
        let path = host_trace_path("root", true, true).expect("隔离验收显式启用后应有留痕路径");
        assert_eq!(path.as_path(), std::path::Path::new("root").join("logs").join("t09-host-events.jsonl"));
    }

    /// 取一条真的被受理的操作；没被受理就是用例自己写错了。
    fn started(book: &mut OperationBook, cmd: &str) -> ActiveOperation {
        match book.accept(cmd, 30.0) {
            Accept::Start(current) => current,
            Accept::Repeat(_) => panic!("{cmd} 不该是重复提交"),
            Accept::Busy(holder) => panic!("{cmd} 被 {holder} 挡住了"),
        }
    }

    #[test]
    fn operation_book_ignores_stale_terminal_events() {
        let mut book = OperationBook::default();
        let first = started(&mut book, "connect");
        assert!(
            matches!(book.accept("connect", 30.0), Accept::Repeat(_)),
            "同命令必须 single-flight"
        );
        let old_terminal = final_event(&first, r#"{"ok":false,"error":"old"}"#.to_string());
        book.complete(&old_terminal);
        let second = started(&mut book, "connect");
        assert!(second.id != first.id);
        book.complete(&old_terminal);
        assert_eq!(book.active.get("connect").map(|op| op.id), Some(second.id),
            "旧终态不得误清后来发起的新操作");
        let ok_terminal = final_event(&second, r#"{"ok":true,"diagnose":{"line":"L1"}}"#.to_string());
        let state: serde_json::Value = serde_json::from_str(&ok_terminal.state).unwrap();
        assert_eq!(state["op"]["phase"], "finished");
        assert_eq!(state["diagnose"]["line"], "L1", "终态必须保留业务回包");
        book.complete(&ok_terminal);
        assert!(!book.active.contains_key("connect"));
        assert!(book.holder.is_none(), "终态之后闸门必须放开");
    }

    /// 全局单闸门：一条长命令在跑时，**别的**长命令必须被挡下并说出占用者。
    ///
    /// 这条防的是「连接与导入同时跑」：一个在拨号，另一个在重写 `config.json`，
    /// 后写者赢，前一条线路凭空消失（r76 之前的实际行为）。
    #[test]
    fn the_long_command_gate_names_the_holder_instead_of_running_two_at_once() {
        let mut book = OperationBook::default();
        let first = started(&mut book, "connect");
        assert_eq!(book.holder.as_deref(), Some("connect"));

        // 另一条长命令：挡下，并带上占用者。
        match book.accept("import", 60.0) {
            Accept::Busy(holder) => assert_eq!(holder, "connect"),
            other => panic!("导入必须被挡下，实际 {:?}", matches!(other, Accept::Start(_))),
        }
        // 同一条命令重复点击仍是 single-flight，不是「忙」。
        assert!(matches!(book.accept("connect", 30.0), Accept::Repeat(_)));
        // 被挡下的那条不许污染状态：active 里只有 connect，闸门还是它。
        assert_eq!(book.active.len(), 1);
        assert_eq!(book.holder.as_deref(), Some("connect"));

        // 别人（被拒）的终态事件不得放开闸门。
        let refused = refuse_event("import", "正在连接，等它结束再试。");
        book.complete(&refused);
        assert_eq!(book.holder.as_deref(), Some("connect"), "被拒事件不许放开闸门");

        // 真正跑完的那条才放开。
        book.complete(&final_event(&first, r#"{"ok":true}"#.to_string()));
        assert!(book.holder.is_none());
        assert!(matches!(book.accept("import", 60.0), Accept::Start(_)));
    }

    #[test]
    fn duplicate_submit_executes_one_business_action_and_one_audit_record() {
        let root = std::env::temp_dir().join(format!("tcrs-ui-single-flight-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let ctx = crate::ipc::Ctx {
            root: root.clone(),
            log_dir: root.join("logs"),
            source: crate::events::Source::Ui,
            ..crate::ipc::Ctx::default()
        };
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_handler = std::sync::Arc::clone(&calls);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = std::sync::Mutex::new(release_rx);
        let handler: std::sync::Arc<Handler> = std::sync::Arc::new(move |raw: &str| {
            calls_handler.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            entered_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            crate::ipc::handle_line_with(raw, &ctx)
        });
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let sink: std::sync::Arc<EventSink> = std::sync::Arc::new(move |event| {
            event_tx.send(event).unwrap();
        });
        let mut book = OperationBook::default();
        let journal = crate::oprecord::Journal::new(&root);
        let raw = r#"{"cmd":"connect"}"#.to_string();
        submit_operation(&mut book, raw.clone(), 30.0, std::sync::Arc::clone(&handler), std::sync::Arc::clone(&sink), &journal, "ui");
        entered_rx.recv_timeout(std::time::Duration::from_secs(2)).expect("第一次命令必须进入 handler");
        submit_operation(&mut book, raw, 30.0, handler, sink, &journal, "ui");
        release_tx.send(()).unwrap();

        let mut phases = Vec::new();
        let terminal = loop {
            let event = event_rx.recv_timeout(std::time::Duration::from_secs(5)).expect("必须收到终态");
            let state: serde_json::Value = serde_json::from_str(&event.state).unwrap();
            phases.push(state["op"]["phase"].as_str().unwrap_or_default().to_string());
            assert!(state["op"]["startedAtUtc"].as_str().is_some(), "秒数只能来自宿主时间戳");
            if event.terminal { break event; }
        };
        assert_eq!(phases.first().map(String::as_str), Some("queued"), "{phases:?}");
        assert!(phases.iter().any(|phase| phase == "running"), "{phases:?}");
        let final_state: serde_json::Value = serde_json::from_str(&terminal.state).unwrap();
        assert_eq!(final_state["op"]["phase"], "failed", "无配置的真实连接失败不得伪装成功");
        book.complete(&terminal);
        assert!(!book.active.contains_key("connect"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1, "重复提交不得重复执行写操作");
        let records = crate::events::read(&root, 10);
        assert_eq!(records.len(), 1, "重复连接只能新增一条 operations.jsonl 记录：{records:?}");
        assert_eq!(records[0].action, crate::events::CONNECT);
        // 通用操作记录也只许有一条，而且结论必须已经落盘（不是还挂在 Pending）。
        let op_records = crate::oprecord::load(&root).unwrap();
        assert_eq!(op_records.len(), 1, "一次连接只能有一条操作记录：{op_records:?}");
        assert_eq!(op_records[0].kind, crate::oprecord::CONNECT);
        assert_eq!(op_records[0].phase, crate::oprecord::FAILED, "{op_records:?}");
        assert!(!op_records[0].message.is_empty(), "失败原因要写进记录：{op_records:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 接缝：第二条长命令必须被挡在 handler 之前，而且**不写一条操作记录**。
    ///
    /// 只测 `OperationBook` 的话，抓不到「记录里多了一条从没跑过的导入」——
    /// 那会让人以为真的导过一次。
    #[test]
    fn a_second_long_command_is_refused_before_the_handler_and_writes_no_record() {
        let root = std::env::temp_dir().join(format!("tcrs-ui-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let ctx = crate::ipc::Ctx {
            root: root.clone(),
            log_dir: root.join("logs"),
            source: crate::events::Source::Ui,
            ..crate::ipc::Ctx::default()
        };
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_handler = std::sync::Arc::clone(&calls);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = std::sync::Mutex::new(release_rx);
        let handler: std::sync::Arc<Handler> = std::sync::Arc::new(move |raw: &str| {
            calls_handler.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            entered_tx.send(()).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            crate::ipc::handle_line_with(raw, &ctx)
        });
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let sink: std::sync::Arc<EventSink> = std::sync::Arc::new(move |event| {
            event_tx.send(event).unwrap();
        });
        let mut book = OperationBook::default();
        let journal = crate::oprecord::Journal::new(&root);

        let started = submit_operation(
            &mut book,
            r#"{"cmd":"connect"}"#.to_string(),
            30.0,
            std::sync::Arc::clone(&handler),
            std::sync::Arc::clone(&sink),
            &journal,
            "ui",
        );
        assert!(started, "第一条长命令必须真的开始");
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("第一条必须进 handler");
        assert_eq!(book.holder.as_deref(), Some("connect"));

        // 第二条：**不同名**的长命令。以前它会和连接一起跑。
        let refused_run = submit_operation(
            &mut book,
            r#"{"cmd":"import","path":"%TEMP%/bundle"}"#.to_string(),
            60.0,
            std::sync::Arc::clone(&handler),
            std::sync::Arc::clone(&sink),
            &journal,
            "ui",
        );
        assert!(!refused_run, "被挡住的那条不许报告「开始了」");

        // 拒绝必须立刻回话，而且说清在等谁。
        let mut refusal: Option<serde_json::Value> = None;
        for _ in 0..10 {
            let Ok(event) = event_rx.recv_timeout(std::time::Duration::from_secs(2)) else {
                break;
            };
            let state: serde_json::Value = serde_json::from_str(&event.state).unwrap();
            if state["op"]["phase"] == "refused" {
                refusal = Some(state);
                break;
            }
        }
        let refusal = refusal.expect("被挡下时必须有回话，不能静默");
        assert_eq!(refusal["errorCode"], "busy", "{refusal}");
        assert_eq!(refusal["op"]["cmd"], "import");
        let message = refusal["error"].as_str().unwrap_or("");
        assert!(message.contains("正在连接"), "要说清在等谁：{message}");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "被挡下的命令不许进业务 handler"
        );
        assert_eq!(book.holder.as_deref(), Some("connect"), "闸门仍属于连接");

        release_tx.send(()).unwrap();
        loop {
            let event = event_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("连接必须收到终态");
            book.complete(&event);
            if event.terminal && event.cmd == "connect" {
                break;
            }
        }
        assert!(book.holder.is_none(), "结束后闸门要放开");
        let op_records = crate::oprecord::load(&root).unwrap();
        assert_eq!(
            op_records.len(),
            1,
            "被挡下的那条不许写操作记录：{op_records:?}"
        );
        assert_eq!(op_records[0].kind, crate::oprecord::CONNECT, "{op_records:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_operation_record_is_pending_while_the_handler_runs_and_settled_before_the_terminal_event() {
        let root = std::env::temp_dir().join(format!("tcrs-ui-record-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let root_in_handler = root.clone();
        let handler: std::sync::Arc<Handler> = std::sync::Arc::new(move |_: &str| -> String {
            let records = crate::oprecord::load(&root_in_handler).unwrap();
            assert_eq!(records.len(), 1, "业务开始前记录必须已经在盘上：{records:?}");
            assert_eq!(records[0].phase, crate::oprecord::PENDING, "{records:?}");
            r#"{"ok":true,"diagnose":{"line":"L1"}}"#.to_string()
        });
        let root_in_sink = root.clone();
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let sink: std::sync::Arc<EventSink> = std::sync::Arc::new(move |event| {
            // 终态发出前，结论必须已经写回：页面收到「完成」时就该能核对到同一份事实。
            if event.terminal {
                let records = crate::oprecord::load(&root_in_sink).unwrap();
                assert_eq!(records[0].phase, crate::oprecord::SUCCEEDED, "{records:?}");
            }
            event_tx.send(event).unwrap();
        });
        let mut book = OperationBook::default();
        submit_operation(
            &mut book,
            r#"{"cmd":"diagnose"}"#.to_string(),
            5.0,
            handler,
            sink,
            &crate::oprecord::Journal::new(&root),
            "ui",
        );
        let terminal = loop {
            let event = event_rx.recv_timeout(std::time::Duration::from_secs(5)).expect("必须收到终态");
            if event.terminal { break event; }
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&terminal.state).unwrap()["ok"],
            true
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_record_that_cannot_be_written_refuses_to_start_the_operation() {
        let root = std::env::temp_dir().join(format!("tcrs-ui-record-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // `logs` 是个文件而不是目录：记录写不进去。
        std::fs::write(root.join("logs"), b"x").unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_handler = std::sync::Arc::clone(&calls);
        let handler: std::sync::Arc<Handler> = std::sync::Arc::new(move |_: &str| -> String {
            calls_handler.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            r#"{"ok":true}"#.to_string()
        });
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let sink: std::sync::Arc<EventSink> = std::sync::Arc::new(move |event| {
            event_tx.send(event).unwrap();
        });
        let mut book = OperationBook::default();
        submit_operation(
            &mut book,
            r#"{"cmd":"connect"}"#.to_string(),
            30.0,
            handler,
            sink,
            &crate::oprecord::Journal::new(&root),
            "ui",
        );
        let terminal = event_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("记录写不进去必须立刻给终态，不能让用户一直等");
        assert!(terminal.terminal);
        let state: serde_json::Value = serde_json::from_str(&terminal.state).unwrap();
        assert_eq!(state["ok"], false, "{state}");
        assert_eq!(state["errorCode"], "record", "{state}");
        assert_eq!(state["op"]["phase"], "failed", "{state}");
        assert!(
            state["error"].as_str().unwrap_or_default().contains("本次操作没有开始"),
            "{state}"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0, "没有记录就不许有副作用");
        assert!(!book.active.contains_key("connect"), "失败的受理必须释放 single-flight");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn panicking_handler_still_produces_failed_terminal() {
        let root = std::env::temp_dir().join(format!("tcrs-ui-panic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let handler: std::sync::Arc<Handler> = std::sync::Arc::new(|_: &str| -> String {
            panic!("fixture panic")
        });
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let sink: std::sync::Arc<EventSink> = std::sync::Arc::new(move |event| {
            event_tx.send(event).unwrap();
        });
        let mut book = OperationBook::default();
        submit_operation(
            &mut book,
            r#"{"cmd":"diagnose"}"#.to_string(),
            5.0,
            handler,
            sink,
            &crate::oprecord::Journal::new(&root),
            "ui",
        );
        let terminal = loop {
            let event = event_rx.recv_timeout(std::time::Duration::from_secs(5)).expect("panic 后也必须有终态");
            if event.terminal { break event; }
        };
        let state: serde_json::Value = serde_json::from_str(&terminal.state).unwrap();
        assert_eq!(state["ok"], false);
        assert_eq!(state["op"]["phase"], "failed");
        assert!(state["error"].as_str().unwrap_or_default().contains("异常结束"));
        let records = crate::oprecord::load(&root).unwrap();
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].phase, crate::oprecord::FAILED, "异常结束也要落结论：{records:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

}
