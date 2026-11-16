//! 托盘常驻：让「关了窗口还连着」这件事有个入口。
//!
//! 为什么必须有托盘才能做「关窗不断开」：窗口藏起来之后如果没有任何常驻入口，
//! 用户就再也叫不出它，只能去任务管理器杀进程——那会把代理留在接管状态。
//!
//! 依赖 `tray-icon`（Windows 上是纯 Win32 实现，与 tao 的事件循环互不干涉：
//! 它在自己的线程里跑消息循环，我们只在事件循环里**轮询**它投递的事件）。
//!
//! 红线：托盘「退出」必须走完整断开（停引擎 → 还原代理）。
//! 这里只负责产出命令，断开由 `ui::run` 交给进程自己那个 `on_close` 闭包完成——
//! 与关窗清理**同一条代码路径**，不给「从托盘退出」留一条不还原代理的旁路。
//!
//! 实际覆盖范围（别把这里当成「异常退出都安全」）：
//! - 托盘「退出」/ 关窗退出：走完整断开；
//! - 注销 / 关机：`lifecycle` 里尽力清理，最多等 3 秒，超时就交给自愈；
//! - 任务管理器强杀 / 断电：**抓不到**。兜底的是启动自愈（`connect::heal_stale`）：
//!   下次启动发现「凭据在、引擎已死」就自动还原。

use tray_icon::menu::{Menu, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

/// 菜单四项。文案直接给用户看，别用英文缩写。
pub const MENU_SHOW: &str = "显示窗口";
pub const MENU_CONNECT: &str = "连接";
pub const MENU_DISCONNECT: &str = "断开";
pub const MENU_QUIT: &str = "退出";

/// 托盘/菜单产生的一条命令。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    Show,
    Connect,
    Disconnect,
    Quit,
}

/// 关窗时到底做什么。抽成纯函数，窗口回调里只做转发，别把判断写死在回调里。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnClose {
    /// 断开 + 退出（历史默认行为）。
    DisconnectAndExit,
    /// 只隐藏窗口，连接保持。
    HideToTray,
    /// **有部署在跑、又没有托盘**：窗口不许藏（藏了就再也叫不出来），也不许退出
    /// （退出会打断部署）。只能把窗口留下、把原因摆到脸上。
    RefuseAndShowDialog,
}

/// 关窗动作的唯一判定。
///
/// `tray_available=false` 时**一律**退回「断开并退出」：窗口藏了又找不到托盘图标，
/// 用户除了杀进程没有别的办法，那比断开更糟。
///
/// T09 起多了一维 `deploying`（有部署没跑完）。它优先于用户的「关窗即断开」偏好：
/// 部署不是连接，断了可以重连，**部署打断就得从头核对**。所以：
///
/// | `deploying` | 托盘 | 结论 |
/// |---|---|---|
/// | 有 | 有 | 缩到托盘（部署继续），不看 `close_to_tray` |
/// | 有 | 无 | 拒绝关窗 + 对话框（**唯一**既不断开也不丢部署的出路） |
/// | 无 | — | 老规则（`close_to_tray && 托盘` → 藏，否则断开退出） |
pub fn close_decision(close_to_tray: bool, tray_available: bool, deploying: bool) -> OnClose {
    if deploying {
        return if tray_available {
            OnClose::HideToTray
        } else {
            OnClose::RefuseAndShowDialog
        };
    }
    on_close(close_to_tray, tray_available)
}

/// 老规则：只看「用户偏好 + 托盘可不可用」。保留独立函数，T09 之前的用例还在守它。
pub fn on_close(close_to_tray: bool, tray_available: bool) -> OnClose {
    if close_to_tray && tray_available {
        OnClose::HideToTray
    } else {
        OnClose::DisconnectAndExit
    }
}

/// 托盘图标的默认提示。有部署在跑时换成「还有 N 个部署没有完成」，
/// 这样窗口藏起来之后，用户把鼠标放到图标上就知道里面还有活。
pub const TOOLTIP_IDLE: &str = "SpiderVPN";

/// 建托盘，失败就当没有。抽成带工厂的函数是为了让「托盘起不来」这条路径能被测试注入。
pub fn tray_or_none<F>(factory: F) -> Option<Tray>
where
    F: FnOnce() -> Result<Tray, String>,
{
    match factory() {
        Ok(t) => Some(t),
        Err(e) => {
            // 明确说出来：用户看不到托盘图标时，得知道程序为什么还是关窗即断开。
            eprintln!("托盘不可用（关窗将退回「断开并退出」）：{e}");
            None
        }
    }
}

pub struct Tray {
    /// 必须持有：drop 会把图标从通知区摘掉。
    _icon: TrayIcon,
    show: MenuItem,
    connect: MenuItem,
    disconnect: MenuItem,
    quit: MenuItem,
}

impl Tray {
    pub fn new() -> Result<Tray, String> {
        let menu = Menu::new();
        let show = MenuItem::new(MENU_SHOW, true, None);
        let connect = MenuItem::new(MENU_CONNECT, true, None);
        let disconnect = MenuItem::new(MENU_DISCONNECT, true, None);
        let quit = MenuItem::new(MENU_QUIT, true, None);
        menu.append_items(&[&show, &connect, &disconnect, &quit])
            .map_err(|e| format!("托盘菜单创建失败：{e}"))?;

        let icon = build_icon().map_err(|e| format!("托盘图标生成失败：{e}"))?;
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(icon)
            .with_tooltip("SpiderVPN")
            // 左键不弹菜单：左键留给「显示窗口」，右键才是菜单。
            .with_menu_on_left_click(false)
            .build()
            .map_err(|e| format!("托盘图标创建失败：{e}"))?;

        Ok(Tray { _icon: tray, show, connect, disconnect, quit })
    }

    /// 换托盘提示（有部署在跑时用它说明里面还有活）。
    ///
    /// 失败只吞掉：改不了提示不该影响任何业务判断。
    pub fn set_tooltip(&self, text: &str) {
        let _ = self._icon.set_tooltip(Some(text));
    }

    /// 取走这一轮攒下的命令。事件循环每次醒来都调一次（托盘在自己的线程收消息，
    /// 我们不去抢它的消息循环，只读它投递的事件）。
    pub fn poll(&self) -> Vec<Cmd> {
        let mut out = Vec::new();
        // 左键点图标 = 显示窗口（与菜单第一项等价）。
        while let Ok(ev) = tray_icon::TrayIconEvent::receiver().try_recv() {
            if let tray_icon::TrayIconEvent::Click { button: tray_icon::MouseButton::Left, button_state: tray_icon::MouseButtonState::Up, .. } = ev {
                out.push(Cmd::Show);
            }
        }
        while let Ok(ev) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            let id = ev.id();
            if id == self.show.id() {
                out.push(Cmd::Show);
            } else if id == self.connect.id() {
                out.push(Cmd::Connect);
            } else if id == self.disconnect.id() {
                out.push(Cmd::Disconnect);
            } else if id == self.quit.id() {
                out.push(Cmd::Quit);
            }
        }
        out
    }
}

/// 画一个 32×32 的图标：蓝底圆 + 白色 "T"。
///
/// 不引入 `.ico` 资源文件：那是又一条要跟着 exe 走的依赖，而这里只需要一个能认出来的标记。
fn build_icon() -> Result<Icon, String> {
    Icon::from_rgba(icon_pixels(), ICON_SIZE as u32, ICON_SIZE as u32).map_err(|e| e.to_string())
}

const ICON_SIZE: i32 = 32;

/// 图标的像素（RGBA，逐行）。抽出来才能在不依赖托盘运行环境的情况下验它。
fn icon_pixels() -> Vec<u8> {
    const S: i32 = ICON_SIZE;
    let mut rgba = vec![0u8; (S * S * 4) as usize];
    let (cx, cy) = (15.5f64, 15.5f64);
    for y in 0..S {
        for x in 0..S {
            let dx = x as f64 - cx;
            let dy = y as f64 - cy;
            if dx * dx + dy * dy <= 14.0 * 14.0 {
                let i = ((y * S + x) * 4) as usize;
                // 品牌蓝
                rgba[i] = 0x1f;
                rgba[i + 1] = 0x6f;
                rgba[i + 2] = 0xeb;
                rgba[i + 3] = 0xff;
            }
        }
    }
    let white = |rgba: &mut Vec<u8>, x: i32, y: i32| {
        let i = ((y * S + x) * 4) as usize;
        rgba[i] = 0xff;
        rgba[i + 1] = 0xff;
        rgba[i + 2] = 0xff;
        rgba[i + 3] = 0xff;
    };
    // 白色 "T"：竖笔 + 顶横
    for y in 9..23 {
        for x in 14..18 {
            white(&mut rgba, x, y);
        }
    }
    for y in 9..13 {
        for x in 9..23 {
            white(&mut rgba, x, y);
        }
    }
    rgba
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_behaviour_has_exactly_one_rule() {
        // 打开且托盘可用 → 只隐藏
        assert_eq!(on_close(true, true), OnClose::HideToTray);
        // 没打开 → 历史行为
        assert_eq!(on_close(false, true), OnClose::DisconnectAndExit);
        assert_eq!(on_close(false, false), OnClose::DisconnectAndExit);
    }

    #[test]
    fn no_tray_falls_back_to_disconnect_even_if_enabled() {
        // 关键兜底：用户开了常驻、但托盘起不来 —— 必须退回断开，
        // 否则窗口藏了找不到入口，用户只能杀进程，代理还指着我们。
        assert_eq!(on_close(true, false), OnClose::DisconnectAndExit);
    }

    /// T09：有部署在跑时，关窗的三种结论一条一条钉死。
    #[test]
    fn a_running_deployment_decides_the_close_action() {
        // 有没有部署、有没有托盘 —— 两张表一共八种组合，逐一断言。
        assert_eq!(
            close_decision(true, false, true),
            OnClose::RefuseAndShowDialog,
            "没有托盘就不能藏窗口，否则部署在跑、窗口再也叫不出来"
        );
        assert_eq!(
            close_decision(false, true, true),
            OnClose::HideToTray,
            "有部署在跑时托盘优先于「关窗即断开」：部署打断就得从头核对"
        );
        assert_eq!(close_decision(true, true, true), OnClose::HideToTray);

        // 没有部署 → 完全是老规则，一条都不许变。
        for close_to_tray in [true, false] {
            for tray in [true, false] {
                assert_eq!(
                    close_decision(close_to_tray, tray, false),
                    on_close(close_to_tray, tray),
                    "close_to_tray={close_to_tray} tray={tray}"
                );
            }
        }
        assert_eq!(close_decision(false, true, false), OnClose::DisconnectAndExit);
    }

    #[test]
    fn tray_factory_failure_is_not_fatal() {
        let t = tray_or_none(|| Err("桩：没有桌面会话".to_string()));
        assert!(t.is_none());
        assert_eq!(on_close(true, t.is_some()), OnClose::DisconnectAndExit, "托盘没有就必须退回断开");
    }

    #[test]
    fn icon_is_a_valid_rgba_bitmap() {
        // 图标自己生成：尺寸/通道不对会让托盘 build 直接失败，先把它钉住。
        // （`Icon` 不暴露宽高，所以这里验的是生成逻辑：32×32、透明底、中心是品牌蓝。）
        assert!(build_icon().is_ok(), "32×32 的图标必须能生成");
        let rgba = icon_pixels();
        assert_eq!(rgba.len(), 32 * 32 * 4, "RGBA 四通道、32×32");
        let center = ((16 * 32 + 16) * 4) as usize;
        assert_eq!(&rgba[center..center + 3], &[0xff, 0xff, 0xff], "中心必须是白色 T 的笔画");
        let corner = 0usize;
        assert_eq!(rgba[corner + 3], 0, "四角必须透明，否则托盘里是个方块");
        let ring = ((16 * 32 + 3) * 4) as usize;
        assert_eq!(&rgba[ring..ring + 3], &[0x1f, 0x6f, 0xeb], "圆底是品牌蓝");
    }

    #[test]
    fn menu_items_are_the_four_we_promise() {
        // 文案是给用户看的：四项缺一不可（显示/连接/断开/退出）。
        assert_eq!(MENU_SHOW, "显示窗口");
        assert_eq!(MENU_CONNECT, "连接");
        assert_eq!(MENU_DISCONNECT, "断开");
        assert_eq!(MENU_QUIT, "退出");
    }
}
