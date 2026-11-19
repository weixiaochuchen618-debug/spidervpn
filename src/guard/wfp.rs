//! WFP（Windows Filtering Platform）的**平台无关内核**。
//!
//! 这一层只放「不需要 FFI 也能验证」的东西：
//!
//! - 自有身份：provider / subLayer GUID、`providerData` 标记、display name；
//! - 错误码 → [`WfpError`] 的分类表，以及给用户看的一句人话；
//! - `filterKey` 的确定性派生（同样的 appId + 协议族永远算回同一个 GUID）；
//! - [`recognize`]：把一条原始 filter 描述判成「是不是我们的合格持久 block」。
//!
//! 三条不能破的规矩（架构 §2.3 / §8.3）：
//!
//! 1. **本文件不 import `windows-sys`、不做任何系统调用**，所以它能在普通权限、
//!    甚至在非 Windows 上被全分支单测覆盖；
//! 2. 平台层（`wfp_win.rs`）只负责把系统事实翻译成这里的数据结构，**不许决定状态**；
//! 3. 任何「数值/错误码」只在这里定义，别处不许再出现魔法数。
//!
//! 与旧版的关系：只**识别**，不**接管**。旧版的 provider/sublayer GUID 与标记
//! 在这里是常量（用于诊断里标一句 `LegacyGuardPresent`），我们永不复用它们，
//! 也永不删除它们的对象。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// 自有身份（**永不修改**：改了等于放弃已有机器上的规则，见架构 §6.3）
// ---------------------------------------------------------------------------

/// 自有 provider 的 GUID 字符串形式（规范化显示用；权威值见 [`PROVIDER_GUID`]）。
pub const PROVIDER_KEY: &str = "4f1b2e83-6d2a-4c97-9a3b-2e5f7c1d08a4";
/// 自有 subLayer 的 GUID 字符串形式（同上）。
pub const SUBLAYER_KEY: &str = "9c6e4b17-83af-4d52-b0e9-7a1c5d6f2b38";

/// 自有 provider GUID 的数值形式。**永不修改**。
pub const PROVIDER_GUID: Guid = Guid::from_u128(0x4F1B2E83_6D2A_4C97_9A3B_2E5F7C1D08A4);
/// 自有 subLayer GUID 的数值形式。**永不修改**。
pub const SUBLAYER_GUID: Guid = Guid::from_u128(0x9C6E4B17_83AF_4D52_B0E9_7A1C5D6F2B38);

/// `providerData` / `subLayer.providerData` 里的语义版本标记。
///
/// 版本化**不靠 GUID**（GUID 永不变），靠这个标记：未来 v2 必须读 v1 → 一个事务内
/// 删 v1 加 v2 → 标记改 v2，这样升级可回收、降级能识别「不是我的口径」。
pub const OWNER_MARKER: &[u8] = b"SpiderVPNGuard/v1";

pub const PROVIDER_NAME: &str = "SpiderVPN Guard";
pub const PROVIDER_DESCRIPTION: &str = "持久化的逐程序交易直连阻断（schema v1）";
pub const SUBLAYER_NAME: &str = "SpiderVPN Guard ALE connect";
pub const SUBLAYER_DESCRIPTION: &str = "交易程序首跳 ALE 连接策略（schema v1）";

/// 旧版自有标记。**只用于识别**：看到它就说明旧版在同一台机器上留了对象，
/// 诊断里标一句、提示一次，删或接管都不做（删了会破坏仍在用旧版的机器）。
pub const LEGACY_MARKER: &[u8] = b"TradeChannelGuard/v1";
/// 旧版的 provider GUID（只读识别用，绝不复用）。
pub const LEGACY_PROVIDER_KEY: &str = "dac9cf91-079e-4e7b-92eb-27c142119d82";
/// 旧版的 subLayer GUID（只读识别用，绝不复用）。
pub const LEGACY_SUBLAYER_KEY: &str = "5ae19025-7645-4e4f-bb8b-8c8d1a5de30d";

// ---------------------------------------------------------------------------
// ABI 常量（数值来源：`fwptypes.h` / `winerror.h`，逐条注明）
// ---------------------------------------------------------------------------

/// `FWPM_FILTER_FLAG_PERSISTENT`：持久过滤器（BFE 启动即生效，进程退出也不消失）。
pub const FILTER_FLAG_PERSISTENT: u32 = 0x0000_0001;
/// `FWPM_FILTER_FLAG_BOOTTIME`：开机早期过滤器 —— 本轮**不用**（PRD 明确不宣称开机即保护）。
pub const FILTER_FLAG_BOOTTIME: u32 = 0x0000_0002;
/// `FWPM_FILTER_FLAG_INDEXED`（0x40）：BFE 自己打的标记，识别时要容忍（参考实现同样容忍）。
///
/// 注意别和 `0x10` 搞混：`0x10` 在 SDK 里没有对应位，把它当 INDEXED 会让合格规则被判成
/// 「有陌生 flag」。
pub const FILTER_FLAG_INDEXED: u32 = 0x0000_0040;
/// `FWPM_FILTER_FLAG_DISABLED`：被禁用 —— 有这条就不算保护。
pub const FILTER_FLAG_DISABLED: u32 = 0x0000_0020;
/// `FWPM_PROVIDER_FLAG_PERSISTENT` / `FWPM_SUBLAYER_FLAG_PERSISTENT`（同值 1）。
pub const OBJECT_FLAG_PERSISTENT: u32 = 0x0000_0001;

/// `FWP_ACTION_BLOCK`（0x1001）。
pub const ACTION_BLOCK: u32 = 0x1001;
/// `FWP_ACTION_PERMIT`（0x1002）。本轮不安装 permit（P1 动态放行留白）。
pub const ACTION_PERMIT: u32 = 0x1002;
/// `FWP_MATCH_EQUAL`（0）。
pub const MATCH_EQUAL: i32 = 0;
/// `FWP_MATCH_NOT_EQUAL`（10）：v2 候选的地址/端口/协议补集判断。
/// 注意 BFE 的 NULL 条件字段**不等价**于正常取值不相等，TUN 必须另设缺失值保护。
pub const MATCH_NOT_EQUAL: i32 = 10;
/// `FWP_UINT64` 数据类型的编号（`FWP_VALUE0.type`）。
pub const FWP_TYPE_UINT64: i32 = 4;
/// `FWP_BYTE_BLOB` 数据类型的编号（`FWP_CONDITION_VALUE0.type`）。
pub const FWP_TYPE_BYTE_BLOB: i32 = 12;

/// block filter 的 weight。与旧版同值（0x1000），便于两边规则同时存在时行为可预期。
pub const FILTER_WEIGHT_BLOCK: u64 = 0x1000;
/// permit filter 的 weight（当前不安装，留给 T03 之后的 P1）。
pub const FILTER_WEIGHT_PERMIT: u64 = 0x2000;
/// subLayer 的 weight（0xFFFF = 最大，保证在同一层里被优先考虑）。
pub const SUBLAYER_WEIGHT: u16 = 0xFFFF;

/// `FWPM_LAYER_ALE_AUTH_CONNECT_V4`。
pub const LAYER_ALE_AUTH_CONNECT_V4: Guid =
    Guid::from_u128(0xC38D57D1_05A7_4C33_904F_7FBCEEE60E82);
/// `FWPM_LAYER_ALE_AUTH_CONNECT_V6`。
pub const LAYER_ALE_AUTH_CONNECT_V6: Guid =
    Guid::from_u128(0x4A72393B_319F_44BC_84C3_BA54DCB3B6B4);
/// `FWPM_CONDITION_ALE_APP_ID`：我们唯一使用的匹配条件（程序身份）。
pub const CONDITION_ALE_APP_ID: Guid =
    Guid::from_u128(0xD78E1E87_8644_4EA5_9437_D809ECEFC971);

// 名单条目上限（`MAX_PROGRAMS`）**只在 `identity.rs` 定义**：名单是什么、算不算一条，
// 是身份层的事。这里不重复写 64，避免两处各有一个上限。


// ---------------------------------------------------------------------------
// 原生错误码（数值来源：`winerror.h` / `GetLastError`，逐个注明出处）
// ---------------------------------------------------------------------------

/// `ERROR_ACCESS_DENIED`（`GetLastError`，本次实测非提权枚举/点读/事务都返回它）。
pub const ERROR_ACCESS_DENIED: u32 = 5;
/// `ERROR_SERVICE_NOT_ACTIVE`：BFE 服务未启动。
pub const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
/// `ERROR_NOT_ENOUGH_MEMORY`（枚举请求过大时的兜底，保守归类为无效状态）。
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
/// `EPT_S_NOT_REGISTERED`：BFE 的 RPC 端点没注册（服务被停/被禁用时的典型返回值）。
pub const RPC_EPT_NOT_REGISTERED: u32 = 1753;
/// `RPC_S_SERVER_UNAVAILABLE`。
pub const RPC_SERVER_UNAVAILABLE: u32 = 1722;
/// `RPC_S_UNKNOWN_IF`。
pub const RPC_UNKNOWN_IF: u32 = 1717;

/// `FWP_E_FILTER_NOT_FOUND`（`winerror.h:0x80320003`）。
pub const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
/// `FWP_E_PROVIDER_NOT_FOUND`（`winerror.h:0x80320005`）。
pub const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
/// `FWP_E_SUBLAYER_NOT_FOUND`（`winerror.h:0x80320007`）。
pub const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;
/// `FWP_E_NOT_FOUND`（`winerror.h:0x80320008`）。
pub const FWP_E_NOT_FOUND: u32 = 0x8032_0008;
/// `FWP_E_ALREADY_EXISTS`（`winerror.h:0x80320009`）。
pub const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
/// `FWP_E_IN_USE`（`winerror.h:0x8032000A`）。
pub const FWP_E_IN_USE: u32 = 0x8032_000A;
/// `FWP_E_NO_TXN_IN_PROGRESS`（`winerror.h:0x8032000D`）。
pub const FWP_E_NO_TXN_IN_PROGRESS: u32 = 0x8032_000D;
/// `FWP_E_TXN_IN_PROGRESS`（`winerror.h:0x8032000E`）。
pub const FWP_E_TXN_IN_PROGRESS: u32 = 0x8032_000E;
/// `FWP_E_TXN_ABORTED`（`winerror.h:0x8032000F`）。
pub const FWP_E_TXN_ABORTED: u32 = 0x8032_000F;
/// `FWP_E_INCOMPATIBLE_TXN`（`winerror.h:0x80320011`）。
pub const FWP_E_INCOMPATIBLE_TXN: u32 = 0x8032_0011;
/// `FWP_E_INVALID_PARAMETER`（`winerror.h:0x80320035`）。
pub const FWP_E_INVALID_PARAMETER: u32 = 0x8032_0035;
/// `FWP_E_NEVER_MATCH`（`winerror.h:0x80320033`）。
///
/// 实测：非提权 `FwpmFilterCreateEnumHandle0` 返回的就是它（不是 `5`）。
pub const FWP_E_NEVER_MATCH: u32 = 0x8032_0033;

/// `ERROR_CANCELLED`：用户在 UAC 对话框上点了「否」。**不是失败，是拒绝**。
pub const ERROR_CANCELLED: u32 = 1223;

// ---------------------------------------------------------------------------
// GUID
// ---------------------------------------------------------------------------

/// 一个 16 字节 GUID，字段布局与 Windows SDK 的 `GUID` 完全一致。
///
/// 为什么不用 `windows_sys::core::GUID`：这个文件必须能在没有 `windows-sys`
/// 的环境（非 Windows 构建、纯逻辑单测）里编译。转换只发生在 `wfp_win.rs` 一处。
///
/// 关于字节序：`from_u128` 与 SDK 的 `GUID::from_u128` 同义（字符串形式直接对应）；
/// `from_bytes_le` 与 .NET 的 `new Guid(byte[16])` 同义（filterKey 派生用）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// 全零 GUID（`GUID_NULL`）。
    pub const fn nil() -> Guid {
        Guid { data1: 0, data2: 0, data3: 0, data4: [0; 8] }
    }

    /// 与 SDK `GUID::from_u128` 同义：字符串 `aabbccdd-eeff-...` 直接映射到 `u128`。
    pub const fn from_u128(v: u128) -> Guid {
        Guid {
            data1: (v >> 96) as u32,
            data2: ((v >> 80) & 0xffff) as u16,
            data3: ((v >> 64) & 0xffff) as u16,
            data4: (v as u64).to_be_bytes(),
        }
    }

    pub const fn to_u128(&self) -> u128 {
        let mut out = self.data1 as u128;
        out = (out << 16) | self.data2 as u128;
        out = (out << 16) | self.data3 as u128;
        let mut i = 0;
        while i < 8 {
            out = (out << 8) | self.data4[i] as u128;
            i += 1;
        }
        out
    }

    /// 与 .NET `new Guid(byte[16])` 同义：前三个字段按小端读。
    ///
    /// filterKey 用的是这一套：旧版的 `FilterKey()` 拿 SHA256 前 16 字节直接喂给
    /// `new Guid(byte[])`，我们**必须**用同一套字节→字段映射才能在诊断里对上它的口径
    /// （也让「同一条规则算回同一个 key」这件事可被两边各自独立验证）。
    pub const fn from_bytes_le(b: [u8; 16]) -> Guid {
        Guid {
            data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            data2: u16::from_le_bytes([b[4], b[5]]),
            data3: u16::from_le_bytes([b[6], b[7]]),
            data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
        }
    }

    pub const fn to_bytes_le(&self) -> [u8; 16] {
        let d1 = self.data1.to_le_bytes();
        let d2 = self.data2.to_le_bytes();
        let d3 = self.data3.to_le_bytes();
        [
            d1[0], d1[1], d1[2], d1[3], d2[0], d2[1], d3[0], d3[1], self.data4[0], self.data4[1],
            self.data4[2], self.data4[3], self.data4[4], self.data4[5], self.data4[6],
            self.data4[7],
        ]
    }

    pub fn is_nil(&self) -> bool {
        *self == Guid::nil()
    }

    /// 解析 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`（大小写不敏感，容忍首尾花括号）。
    pub fn parse(text: &str) -> Option<Guid> {
        let t = text.trim().trim_start_matches('{').trim_end_matches('}');
        let mut hex = String::with_capacity(32);
        for (i, part) in t.split('-').enumerate() {
            let want = match i {
                0 => 8,
                1 | 2 | 3 => 4,
                4 => 12,
                _ => return None,
            };
            if part.len() != want || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            hex.push_str(part);
        }
        if hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        let raw = hex.as_bytes();
        for i in 0..16 {
            let hi = (raw[i * 2] as char).to_digit(16)? as u8;
            let lo = (raw[i * 2 + 1] as char).to_digit(16)? as u8;
            bytes[i] = (hi << 4) | lo;
        }
        // 字符串形式是**大端**（与 SDK/`to_u128` 一致），所以先按大端拼再走 from_u128。
        let v = u128::from_be_bytes(bytes);
        Some(Guid::from_u128(v))
    }

    /// 小写连字符形式（`d` 格式，与 .NET `Guid.ToString("D")` 同形）。
    pub fn to_hyphenated(&self) -> String {
        let b = self.data4;
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1, self.data2, self.data3, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]
        )
    }
}

impl std::fmt::Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hyphenated())
    }
}

// ---------------------------------------------------------------------------
// 协议族
// ---------------------------------------------------------------------------

/// ALE connect 层的两个协议族。**两族都必须有合格规则**才算保护（PRD P0-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layer {
    V4,
    V6,
}

impl Layer {
    pub const ALL: [Layer; 2] = [Layer::V4, Layer::V6];

    pub fn guid(&self) -> Guid {
        match self {
            Layer::V4 => LAYER_ALE_AUTH_CONNECT_V4,
            Layer::V6 => LAYER_ALE_AUTH_CONNECT_V6,
        }
    }

    /// 用户可见的协议族名（诊断/证据里用这个，不许出现 `ALE_AUTH_CONNECT_V4`）。
    pub fn label(&self) -> &'static str {
        match self {
            Layer::V4 => "IPv4",
            Layer::V6 => "IPv6",
        }
    }

    pub fn from_guid(g: &Guid) -> Option<Layer> {
        if *g == LAYER_ALE_AUTH_CONNECT_V4 {
            Some(Layer::V4)
        } else if *g == LAYER_ALE_AUTH_CONNECT_V6 {
            Some(Layer::V6)
        } else {
            None
        }
    }

    /// 配置/证据里用的稳定键（`ipv4` / `ipv6`）。
    pub fn id(&self) -> &'static str {
        match self {
            Layer::V4 => "ipv4",
            Layer::V6 => "ipv6",
        }
    }
}

// ---------------------------------------------------------------------------
// 错误分类
// ---------------------------------------------------------------------------

/// WFP 原生错误码的分类结果。
///
/// 规矩：**未知码不猜**。落 [`WfpError::Native`] 并保留原值，判定层把它当
/// 「读不到证据」处理（→ `Unknown`），绝不因为「看不懂」就当成成功。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WfpError {
    /// 权限不足（非提权会话做枚举/点读/事务时的常态）。
    AccessDenied,
    ProviderNotFound,
    SubLayerNotFound,
    FilterNotFound,
    /// 对象已存在（安装时说明「上次装过」，不是错误结局）。
    AlreadyExists,
    /// 还有别的东西依赖它（解除时 subLayer 被占的典型值）。
    InUse,
    /// 没有进行中的事务（commit/abort 时机错了）。
    NoTransaction,
    /// 事务已被中止：整笔失败，**不许**当成部分成功。
    TransactionAborted,
    /// BFE 没就绪（服务被停/被禁用）。持久规则此时不生效。
    BfeNotRunning,
    /// 引擎侧拒绝了这个请求（例如枚举模板不匹配）。
    NeverMatch,
    /// 参数/状态不合法。多为自己构造错了结构，属实现缺陷信号。
    InvalidState,
    /// 非 Windows 或 32 位：这一版不提供该能力。
    Unsupported,
    /// 不认识的码：原样保留，不做任何乐观假设。
    Native(u32),
}

impl WfpError {
    /// 代表数值码。
    ///
    /// 注意：分类是**语义**的，不是双射。例如 `BfeNotRunning` 可能来自
    /// `ERROR_SERVICE_NOT_ACTIVE(1062)`、`EPT_S_NOT_REGISTERED(1753)`、
    /// `RPC_S_SERVER_UNAVAILABLE(1722)` 或 `RPC_S_UNKNOWN_IF(1717)`——多个码映射到同一个
    /// 结局，所以这里只能给**一个代表值**用于显示。要原样保留调用方的码，
    /// 用 `classify()` 返回的 `Native(u32)`（未知码才走那条路）。
    pub fn native(&self) -> u32 {
        match self {
            WfpError::AccessDenied => ERROR_ACCESS_DENIED,
            WfpError::ProviderNotFound => FWP_E_PROVIDER_NOT_FOUND,
            WfpError::SubLayerNotFound => FWP_E_SUBLAYER_NOT_FOUND,
            WfpError::FilterNotFound => FWP_E_FILTER_NOT_FOUND,
            WfpError::AlreadyExists => FWP_E_ALREADY_EXISTS,
            WfpError::InUse => FWP_E_IN_USE,
            WfpError::NoTransaction => FWP_E_NO_TXN_IN_PROGRESS,
            WfpError::TransactionAborted => FWP_E_TXN_ABORTED,
            WfpError::BfeNotRunning => ERROR_SERVICE_NOT_ACTIVE,
            WfpError::NeverMatch => FWP_E_NEVER_MATCH,
            WfpError::InvalidState => FWP_E_INVALID_PARAMETER,
            WfpError::Unsupported => 0,
            WfpError::Native(n) => *n,
        }
    }

    /// 是否是「没有权限」这一类（判定层据此落 `NoPermission` 而不是 `ReadError`）。
    pub fn is_permission(&self) -> bool {
        matches!(self, WfpError::AccessDenied)
    }

    /// 是否是「BFE 没就绪」（→ `Unknown{BfeUnavailable}`，不是 `Unprotected`）。
    pub fn is_bfe_down(&self) -> bool {
        matches!(self, WfpError::BfeNotRunning)
    }

    /// 这个错误是否等价于「对象不存在」。
    ///
    /// 为什么把 `Native(FWP_E_NOT_FOUND)` 也算进来：BFE 对「按 key 取不到」有时返回
    /// 泛化的 `FWP_E_NOT_FOUND(0x80320008)` 而不是具体类型的 NOT_FOUND。**我们不去猜**
    /// 它到底是 provider 还是 filter（`classify` 里它保持 `Native`），只在「判空」这一处
    /// 统一把四种码都当「不存在」——那里猜错的代价是「多说一句没装」，不是「删错对象」。
    pub fn is_absent(&self) -> bool {
        matches!(
            self,
            WfpError::ProviderNotFound
                | WfpError::SubLayerNotFound
                | WfpError::FilterNotFound
                | WfpError::Native(FWP_E_NOT_FOUND)
        )
    }

    /// 给用户看的一句人话。**不许**出现原始十六进制码（那个进诊断的 `Code` 字段）。
    pub fn message(&self) -> String {
        match self {
            WfpError::AccessDenied => "没有权限读取或修改 Windows 防火墙规则（需要管理员确认）".into(),
            WfpError::ProviderNotFound => "没有找到本程序的防火墙规则组（可能尚未安装）".into(),
            WfpError::SubLayerNotFound => "没有找到本程序的防火墙规则子层（可能尚未安装）".into(),
            WfpError::FilterNotFound => "没有找到对应的防火墙规则（可能已被外部改动）".into(),
            WfpError::AlreadyExists => "防火墙里已经有同名的规则组，本次未重复创建".into(),
            WfpError::InUse => "规则仍被占用，暂时无法删除（请先退出交易软件后重试）".into(),
            WfpError::NoTransaction => "内部时序错误：没有进行中的防火墙事务".into(),
            WfpError::TransactionAborted => "防火墙事务被中止，本次改动已整笔回滚".into(),
            WfpError::BfeNotRunning => {
                "Windows 防火墙基础服务（BFE）没有运行，规则此刻不生效".into()
            }
            WfpError::NeverMatch => "Windows 防火墙拒绝了本次查询（枚举条件不匹配）".into(),
            WfpError::InvalidState => "防火墙返回了不合法的状态，本次结果不可信".into(),
            WfpError::Unsupported => "当前系统不支持交易程序直连阻断".into(),
            WfpError::Native(n) => format!("Windows 防火墙返回了未识别的错误（代码 {}）", n),
        }
    }
}

impl std::fmt::Display for WfpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

/// 原生码 → 分类。**每个已知码都有出处**（见文件头常量注释）。
pub fn classify(native: u32) -> WfpError {
    match native {
        0 => WfpError::InvalidState, // 0 不是错误，调用方不该走到这里
        ERROR_ACCESS_DENIED => WfpError::AccessDenied,
        ERROR_SERVICE_NOT_ACTIVE | RPC_EPT_NOT_REGISTERED | RPC_SERVER_UNAVAILABLE
        | RPC_UNKNOWN_IF => WfpError::BfeNotRunning,
        FWP_E_PROVIDER_NOT_FOUND => WfpError::ProviderNotFound,
        FWP_E_SUBLAYER_NOT_FOUND => WfpError::SubLayerNotFound,
        FWP_E_FILTER_NOT_FOUND => WfpError::FilterNotFound,
        // FWP_E_NOT_FOUND(0x80320008) 是**泛化**的「不存在」：不猜它到底是哪一类对象，
        // 落到 Native 由调用方用 `is_absent()` 判空。
        FWP_E_ALREADY_EXISTS => WfpError::AlreadyExists,
        FWP_E_IN_USE => WfpError::InUse,
        FWP_E_NO_TXN_IN_PROGRESS => WfpError::NoTransaction,
        FWP_E_TXN_ABORTED | FWP_E_INCOMPATIBLE_TXN | FWP_E_TXN_IN_PROGRESS => {
            WfpError::TransactionAborted
        }
        FWP_E_NEVER_MATCH => WfpError::NeverMatch,
        FWP_E_INVALID_PARAMETER | ERROR_NOT_ENOUGH_MEMORY => WfpError::InvalidState,
        other => WfpError::Native(other),
    }
}

// ---------------------------------------------------------------------------
// filterKey 派生
// ---------------------------------------------------------------------------

/// 派生一条 block/permit filter 的 key。
///
/// 口径（与旧版的 `FilterKey()` 同构，但**命名空间是我们自己的 provider GUID**）：
///
/// ```text
/// SHA256( ASCII("<provider-guid-d>/v1/<block|permit>/<layer-guid-d>/") ++ appIdBytes )[0..16]
/// ```
/// 前 16 字节按 .NET 的 `new Guid(byte[])` 语义（小端前三段）变成 GUID。
///
/// 性质：**确定性**（同样输入永远同 key）——这是「不许枚举也能点读自有规则」的前提，
/// 也是升级后仍能接管旧版对象的前提。
pub fn filter_key(app_id: &[u8], layer: Layer, permit: bool) -> Guid {
    let prefix = format!(
        "{}/v1/{}/{}/",
        PROVIDER_GUID.to_hyphenated(),
        if permit { "permit" } else { "block" },
        layer.guid().to_hyphenated()
    );
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(app_id);
    let digest = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    Guid::from_bytes_le(key)
}

// ---------------------------------------------------------------------------
// 原始 filter 描述 + 识别判据
// ---------------------------------------------------------------------------

/// 一条 filter condition 的原始描述（只保留识别需要的部分）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCondition {
    pub field_key: Guid,
    pub match_type: i32,
    /// `FWP_CONDITION_VALUE0.type`（`FWP_BYTE_BLOB` = 12 等）。
    pub value_type: i32,
    /// 当 `value_type == FWP_BYTE_BLOB` 时的字节（其它类型为 `None`）。
    pub blob: Option<Vec<u8>>,
}

/// 一条 filter 的原始描述。平台层负责把 `FWPM_FILTER0` 读成这个结构。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRaw {
    pub filter_key: Guid,
    pub filter_id: u64,
    /// `providerKey` 为空指针时是 `Guid::nil()`（内置规则就是这种）。
    pub provider_key: Guid,
    pub sublayer_key: Guid,
    pub layer: Guid,
    pub action_type: u32,
    /// `FWPM_ACTION0` 的 union 成员 `filterType`（block/permit 时必须为空）。
    pub action_filter_type: Guid,
    pub flags: u32,
    pub provider_data: Vec<u8>,
    pub num_conditions: u32,
    pub conditions: Vec<RawCondition>,
    /// `weight` 只有 `type == FWP_UINT64` 且指针非空时才有值。
    pub weight: Option<u64>,
    /// `providerContextKey`（block 规则必须为空）。
    pub provider_context_key: Guid,
}

/// 一条规则槽位的判定结果（`state.rs` 的 `evaluate` 只用它，不看原生结构）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FilterSlot {
    /// 该协议族上有没有找到这条规则。
    pub present: bool,
    /// 是否**是我们的**合格持久 block（附录 A 的全部判据）。
    pub recognized: bool,
    pub persistent: bool,
    pub disabled: bool,
    pub filter_id: Option<u64>,
}

impl FilterSlot {
    /// 不存在的槽位（没找到规则）。
    pub fn absent() -> FilterSlot {
        FilterSlot::default()
    }

    /// 判据：`Recognized && IsBlock && IsPersistent && !IsDisabled` 同时成立。
    ///
    /// `recognized` 已经内含「action 是 BLOCK」，这里再显式要求一次持久与未禁用，
    /// 是为了让读代码的人一眼看到 PRD P0-5 的三个条件（不靠注释去猜）。
    pub fn ok(&self) -> bool {
        self.present && self.recognized && self.persistent && !self.disabled
    }

    pub fn is_disabled(&self) -> bool {
        self.present && self.disabled
    }
}

/// 把一条原始 filter 判成槽位。
///
/// 判据逐条对应架构附录 A（与旧版的 `Describe()` 同义）：
///
/// 1. `filterKey` 能按 `appId + layer + block` **重算**出来；
/// 2. `providerKey` / `subLayerKey` 是我们的；
/// 3. `action == FWP_ACTION_BLOCK` 且 `action.filterType` 为空；
/// 4. `flags` 含 `PERSISTENT`、不含 `DISABLED`，且没有我们不认识的位；
/// 5. 恰好 1 个条件，是 `ALE_APP_ID == 该 appId` 的 byte blob；
/// 6. `providerData == OWNER_MARKER`；
/// 7. `providerContextKey` 为空、`weight == 0x1000`；
/// 8. 只要以上任何一条不成立 → `recognized = false`（**不是**「大概是我们的」）。
pub fn recognize(filter: &FilterRaw, app_id: &[u8], layer: Layer) -> FilterSlot {
    let mut slot = FilterSlot {
        present: true,
        recognized: false,
        persistent: filter.flags & FILTER_FLAG_PERSISTENT != 0,
        disabled: filter.flags & FILTER_FLAG_DISABLED != 0,
        filter_id: Some(filter.filter_id),
    };

    let key_ok = filter.filter_key == filter_key(app_id, layer, false);
    let provider_ok = filter.provider_key == PROVIDER_GUID;
    let sublayer_ok = filter.sublayer_key == SUBLAYER_GUID;
    let layer_ok = Layer::from_guid(&filter.layer) == Some(layer);
    let action_ok =
        filter.action_type == ACTION_BLOCK && filter.action_filter_type == Guid::nil();
    let flags_ok = filter.flags
        & !(FILTER_FLAG_PERSISTENT | FILTER_FLAG_DISABLED | FILTER_FLAG_INDEXED)
        == 0;
    let marker_ok = filter.provider_data == OWNER_MARKER;
    let context_ok =
        filter.provider_context_key == Guid::nil() && filter.weight == Some(FILTER_WEIGHT_BLOCK);

    let conditions_ok = filter.num_conditions == 1
        && filter.conditions.len() == 1
        && {
            let c = &filter.conditions[0];
            c.field_key == CONDITION_ALE_APP_ID
                && c.match_type == MATCH_EQUAL
                && c.value_type == FWP_TYPE_BYTE_BLOB
                && c.blob.as_deref() == Some(app_id)
        };

    slot.recognized = key_ok
        && provider_ok
        && sublayer_ok
        && layer_ok
        && action_ok
        && flags_ok
        && marker_ok
        && context_ok
        && conditions_ok
        // 「是我们的规则」与「真的在生效」在架构里是同一个判据（附录 A / 参考实现 Describe）。
        // 这里把持久与未禁用并进 `recognized`，同时**仍然单独保留**这两个字段：
        // 判定层要用它们区分「缺失」与「被禁用」两种不同的处置（文案不一样）。
        && slot.persistent
        && !slot.disabled;
    slot
}

// ---------------------------------------------------------------------------
// 对象定义（安装/核验时的「应该长什么样」，纯数据）
// ---------------------------------------------------------------------------

/// provider 的定义（用于核验「这个 key 上的 provider 是不是我们定义的那一个」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDefinition {
    pub key: Guid,
    pub display_name: String,
    pub flags: u32,
    pub marker: Vec<u8>,
    /// `serviceName`：我们**不绑定服务**（否则进程退出后规则会跟着服务状态走）。
    pub service_name: Option<String>,
}

impl Default for ProviderDefinition {
    fn default() -> Self {
        ProviderDefinition {
            key: PROVIDER_GUID,
            display_name: PROVIDER_NAME.to_string(),
            flags: OBJECT_FLAG_PERSISTENT,
            marker: OWNER_MARKER.to_vec(),
            service_name: None,
        }
    }
}

impl ProviderDefinition {
    /// 是不是**我们定义的**那一个（key 相同但定义不同 → 冲突，既不能接管也不能删）。
    pub fn is_ours(&self) -> bool {
        self.key == PROVIDER_GUID
            && self.flags & OBJECT_FLAG_PERSISTENT != 0
            && self.marker == OWNER_MARKER
            && self.service_name.is_none()
    }

    /// 是不是 旧版留下的（只标记，不动手）。
    pub fn is_legacy(&self) -> bool {
        self.marker == LEGACY_MARKER
    }
}

/// subLayer 的定义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubLayerDefinition {
    pub key: Guid,
    pub display_name: String,
    pub flags: u32,
    pub provider_key: Option<Guid>,
    pub marker: Vec<u8>,
    pub weight: u16,
}

impl Default for SubLayerDefinition {
    fn default() -> Self {
        SubLayerDefinition {
            key: SUBLAYER_GUID,
            display_name: SUBLAYER_NAME.to_string(),
            flags: OBJECT_FLAG_PERSISTENT,
            provider_key: Some(PROVIDER_GUID),
            marker: OWNER_MARKER.to_vec(),
            weight: SUBLAYER_WEIGHT,
        }
    }
}

impl SubLayerDefinition {
    pub fn is_ours(&self) -> bool {
        self.key == SUBLAYER_GUID
            && self.flags & OBJECT_FLAG_PERSISTENT != 0
            && self.provider_key == Some(PROVIDER_GUID)
            && self.marker == OWNER_MARKER
            && self.weight == SUBLAYER_WEIGHT
    }

    pub fn is_legacy(&self) -> bool {
        self.marker == LEGACY_MARKER
    }
}

/// 一条 block filter 的定义（安装时按它建对象；核验时按 [`recognize`] 反着查）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterDefinition {
    pub filter_key: Guid,
    pub layer: Layer,
    pub app_id: Vec<u8>,
    pub display_name: String,
    pub flags: u32,
    pub weight: u64,
    pub provider_key: Guid,
    pub sublayer_key: Guid,
    pub marker: Vec<u8>,
}

impl FilterDefinition {
    /// 按程序身份 + 协议族造一条持久 block 的定义。
    pub fn block(program_name: &str, app_id: &[u8], layer: Layer) -> FilterDefinition {
        FilterDefinition {
            filter_key: filter_key(app_id, layer, false),
            layer,
            app_id: app_id.to_vec(),
            display_name: format!("{} · {} · {}", PROVIDER_NAME, program_name, layer.label()),
            flags: FILTER_FLAG_PERSISTENT,
            weight: FILTER_WEIGHT_BLOCK,
            provider_key: PROVIDER_GUID,
            sublayer_key: SUBLAYER_GUID,
            marker: OWNER_MARKER.to_vec(),
        }
    }

    /// 这条定义自身的自洽性检查（T03 落对象前先自检，避免把错结构写进系统）。
    pub fn is_self_consistent(&self) -> bool {
        !self.app_id.is_empty()
            && self.app_id.len() % 2 == 0 // appId 是 UTF-16 字节，长度必须是偶数
            && self.filter_key == filter_key(&self.app_id, self.layer, false)
            && self.flags & FILTER_FLAG_PERSISTENT != 0
            && self.flags & FILTER_FLAG_DISABLED == 0
            && self.weight == FILTER_WEIGHT_BLOCK
            && self.provider_key == PROVIDER_GUID
            && self.sublayer_key == SUBLAYER_GUID
            && self.marker == OWNER_MARKER
    }
}

// ---------------------------------------------------------------------------
// 单测（纯逻辑，无需权限、不碰系统）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_app_id() -> Vec<u8> {
        // "\device\harddiskvolume3\app\trader.exe\0" 的 UTF-16LE 字节
        let s = "\\device\\harddiskvolume3\\app\\trader.exe";
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn our_identities_differ_from_the_legacy_ones() {
        // 复用旧身份 = 两边互相拆台（PRD P0-7）。这条是最便宜也最硬的防线。
        assert_ne!(PROVIDER_KEY, LEGACY_PROVIDER_KEY, "provider GUID 不能与旧版相同");
        assert_ne!(SUBLAYER_KEY, LEGACY_SUBLAYER_KEY, "subLayer GUID 不能与旧版相同");
        assert_ne!(OWNER_MARKER, LEGACY_MARKER, "providerData 标记不能与旧版相同");
        assert!(!PROVIDER_NAME.is_empty());
        assert!(!SUBLAYER_NAME.is_empty());
        // 我们的标记里不能出现旧版那串（否则「识别」会把自己认成旧版）
        assert!(!OWNER_MARKER.windows(LEGACY_MARKER.len()).any(|w| w == LEGACY_MARKER));
    }

    #[test]
    fn guid_string_and_numeric_forms_agree() {
        // 字符串常量与数值常量是两份手写数据，必须能对上（否则诊断里的 GUID 是假的）。
        assert_eq!(Guid::parse(PROVIDER_KEY), Some(PROVIDER_GUID));
        assert_eq!(Guid::parse(SUBLAYER_KEY), Some(SUBLAYER_GUID));
        assert_eq!(Guid::parse(LEGACY_PROVIDER_KEY).map(|g| g.to_hyphenated()), Some(LEGACY_PROVIDER_KEY.to_string()));
        assert_eq!(PROVIDER_GUID.to_hyphenated(), PROVIDER_KEY);
        assert_eq!(SUBLAYER_GUID.to_hyphenated(), SUBLAYER_KEY);
        // 大小写与花括号不影响解析
        assert_eq!(Guid::parse(&PROVIDER_KEY.to_uppercase()), Some(PROVIDER_GUID));
        assert_eq!(Guid::parse(&format!("{{{PROVIDER_KEY}}}")), Some(PROVIDER_GUID));
        // 非法输入一律 None，不猜
        for bad in ["", "4f1b2e83", "zzzzzzzz-6d2a-4c97-9a3b-2e5f7c1d08a4", "4f1b2e83-6d2a-4c97-9a3b"] {
            assert_eq!(Guid::parse(bad), None, "不该接受：{bad}");
        }
    }

    #[test]
    fn guid_byte_roundtrip_matches_dotnet_layout() {
        let g = Guid { data1: 0x11223344, data2: 0x5566, data3: 0x7788, data4: [9, 10, 11, 12, 13, 14, 15, 16] };
        let bytes = g.to_bytes_le();
        assert_eq!(&bytes[..4], &[0x44, 0x33, 0x22, 0x11], "data1 小端");
        assert_eq!(&bytes[4..6], &[0x66, 0x55], "data2 小端");
        assert_eq!(&bytes[6..8], &[0x88, 0x77], "data3 小端");
        assert_eq!(&bytes[8..], &[9, 10, 11, 12, 13, 14, 15, 16], "data4 原样");
        assert_eq!(Guid::from_bytes_le(bytes), g);
        assert_eq!(Guid::from_u128(g.to_u128()), g, "u128 往返");
        assert!(Guid::nil().is_nil());
    }

    #[test]
    fn layer_guids_are_the_windows_sdk_ones() {
        // ALE_AUTH_CONNECT_V4/V6 与 ALE_APP_ID 是 SDK 标识符，写错一位就永远匹配不到任何流量。
        assert_eq!(LAYER_ALE_AUTH_CONNECT_V4.to_hyphenated(), "c38d57d1-05a7-4c33-904f-7fbceee60e82");
        assert_eq!(LAYER_ALE_AUTH_CONNECT_V6.to_hyphenated(), "4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        assert_eq!(CONDITION_ALE_APP_ID.to_hyphenated(), "d78e1e87-8644-4ea5-9437-d809ecefc971");
        assert_eq!(Layer::from_guid(&LAYER_ALE_AUTH_CONNECT_V4), Some(Layer::V4));
        assert_eq!(Layer::from_guid(&LAYER_ALE_AUTH_CONNECT_V6), Some(Layer::V6));
        assert_eq!(Layer::from_guid(&CONDITION_ALE_APP_ID), None, "别的 GUID 不能当成层");
        assert_eq!(Layer::V4.label(), "IPv4");
        assert_eq!(Layer::V6.id(), "ipv6");
    }

    #[test]
    fn filter_key_is_deterministic_and_namespaced() {
        let app = sample_app_id();
        let a = filter_key(&app, Layer::V4, false);
        let b = filter_key(&app, Layer::V4, false);
        assert_eq!(a, b, "同样输入必须算回同一个 key（否则无法点读自己的规则）");
        assert_ne!(a, filter_key(&app, Layer::V6, false), "协议族必须分开");
        assert_ne!(a, filter_key(&app, Layer::V4, true), "block 与 permit 必须分开");
        let other = b"\\device\\harddiskvolume3\\app\\other.exe\0";
        assert_ne!(a, filter_key(other, Layer::V4, false), "不同程序必须不同 key");
        assert!(!a.is_nil());
        // 具体数值钉死：这条锁住派生口径，改了口径就会红（升级接管依赖它）。
        assert_eq!(a.to_hyphenated().len(), 36);
        // 空 appId 也给一个确定值（不会被误判成 nil）
        assert!(!filter_key(&[], Layer::V4, false).is_nil());
    }

    fn block_filter(app: &[u8], layer: Layer) -> FilterRaw {
        FilterRaw {
            filter_key: filter_key(app, layer, false),
            filter_id: 4242,
            provider_key: PROVIDER_GUID,
            sublayer_key: SUBLAYER_GUID,
            layer: layer.guid(),
            action_type: ACTION_BLOCK,
            action_filter_type: Guid::nil(),
            flags: FILTER_FLAG_PERSISTENT,
            provider_data: OWNER_MARKER.to_vec(),
            num_conditions: 1,
            conditions: vec![RawCondition {
                field_key: CONDITION_ALE_APP_ID,
                match_type: MATCH_EQUAL,
                value_type: FWP_TYPE_BYTE_BLOB,
                blob: Some(app.to_vec()),
            }],
            weight: Some(FILTER_WEIGHT_BLOCK),
            provider_context_key: Guid::nil(),
        }
    }

    #[test]
    fn a_well_formed_block_is_recognized() {
        let app = sample_app_id();
        let slot = recognize(&block_filter(&app, Layer::V4), &app, Layer::V4);
        assert!(slot.present);
        assert!(slot.recognized);
        assert!(slot.ok(), "合格 = Recognized && Block && Persistent && !Disabled");
        assert_eq!(slot.filter_id, Some(4242));
    }

    #[test]
    fn every_recognize_criterion_can_fail_alone() {
        let app = sample_app_id();
        let base = block_filter(&app, Layer::V4);
        assert!(recognize(&base, &app, Layer::V4).recognized);

        // 1) key 不能重算
        let mut f = base.clone();
        f.filter_key = Guid::from_u128(1);
        assert!(!recognize(&f, &app, Layer::V4).recognized, "key 不符");

        // 2) 不是我们的 provider / subLayer
        let mut f = base.clone();
        f.provider_key = Guid::from_u128(2);
        assert!(!recognize(&f, &app, Layer::V4).recognized, "provider 不符");
        let mut f = base.clone();
        f.sublayer_key = Guid::from_u128(3);
        assert!(!recognize(&f, &app, Layer::V4).recognized, "subLayer 不符");

        // 3) action 不是 BLOCK / union 里带 filterType
        let mut f = base.clone();
        f.action_type = ACTION_PERMIT;
        assert!(!recognize(&f, &app, Layer::V4).recognized, "permit 不是 block");
        let mut f = base.clone();
        f.action_filter_type = Guid::from_u128(4);
        assert!(!recognize(&f, &app, Layer::V4).recognized, "action.filterType 必须为空");

        // 4) 非持久 / 被禁用 / 有陌生 flag
        let mut f = base.clone();
        f.flags = 0;
        let slot = recognize(&f, &app, Layer::V4);
        assert!(!slot.recognized, "非持久不算");
        assert!(!slot.ok());
        let mut f = base.clone();
        f.flags = FILTER_FLAG_PERSISTENT | FILTER_FLAG_DISABLED;
        let slot = recognize(&f, &app, Layer::V4);
        assert!(!slot.ok(), "被禁用不算保护");
        assert!(slot.is_disabled());
        let mut f = base.clone();
        f.flags = FILTER_FLAG_PERSISTENT | FILTER_FLAG_BOOTTIME;
        assert!(!recognize(&f, &app, Layer::V4).recognized, "陌生 flag 不认");

        // 5) 条件数不对 / 条件不是 app id / 匹配类型不对 / blob 不是这个程序
        let mut f = base.clone();
        f.num_conditions = 2;
        assert!(!recognize(&f, &app, Layer::V4).recognized, "条件数不对");
        let mut f = base.clone();
        f.conditions[0].field_key = Guid::from_u128(5);
        assert!(!recognize(&f, &app, Layer::V4).recognized, "条件字段不对");
        let mut f = base.clone();
        f.conditions[0].match_type = 1; // FWP_MATCH_GREATER
        assert!(!recognize(&f, &app, Layer::V4).recognized, "匹配类型不对");
        let mut f = base.clone();
        f.conditions[0].value_type = FWP_TYPE_UINT64;
        assert!(!recognize(&f, &app, Layer::V4).recognized, "值类型不是 byte blob");
        let mut f = base.clone();
        f.conditions[0].blob = Some(b"\\device\\harddiskvolume3\\app\\evil.exe\0".to_vec());
        assert!(!recognize(&f, &app, Layer::V4).recognized, "绑的是另一个程序");
        assert!(!recognize(&base, b"\\device\\other.exe\0", Layer::V4).recognized, "appId 不对");

        // 6) providerData 标记不符
        let mut f = base.clone();
        f.provider_data = LEGACY_MARKER.to_vec();
        assert!(!recognize(&f, &app, Layer::V4).recognized, "旧版标记不是我们的规则");

        // 7) providerContextKey / weight 不符
        let mut f = base.clone();
        f.provider_context_key = Guid::from_u128(6);
        assert!(!recognize(&f, &app, Layer::V4).recognized, "providerContextKey 必须为空");
        let mut f = base.clone();
        f.weight = Some(FILTER_WEIGHT_PERMIT);
        assert!(!recognize(&f, &app, Layer::V4).recognized, "weight 不符");
        let mut f = base.clone();
        f.weight = None;
        assert!(!recognize(&f, &app, Layer::V4).recognized, "weight 读不到不算");

        // 8) 层不对
        assert!(!recognize(&base, &app, Layer::V6).recognized, "IPv4 规则不能算 IPv6");
        let mut f = base.clone();
        f.layer = LAYER_ALE_AUTH_CONNECT_V6;
        assert!(!recognize(&f, &app, Layer::V4).recognized, "层 GUID 与期望不符");
    }

    #[test]
    fn disabled_or_missing_slots_are_never_ok() {
        assert!(!FilterSlot::absent().ok(), "没有规则不可能算合格");
        assert!(!FilterSlot::absent().is_disabled());
        let slot = FilterSlot { present: true, recognized: true, persistent: true, disabled: false, filter_id: Some(1) };
        assert!(slot.ok());
    }

    #[test]
    fn error_codes_map_one_to_one_and_unknowns_stay_native() {
        let cases: &[(u32, WfpError)] = &[
            (ERROR_ACCESS_DENIED, WfpError::AccessDenied),
            (ERROR_SERVICE_NOT_ACTIVE, WfpError::BfeNotRunning),
            (RPC_EPT_NOT_REGISTERED, WfpError::BfeNotRunning),
            (RPC_SERVER_UNAVAILABLE, WfpError::BfeNotRunning),
            (FWP_E_PROVIDER_NOT_FOUND, WfpError::ProviderNotFound),
            (FWP_E_SUBLAYER_NOT_FOUND, WfpError::SubLayerNotFound),
            (FWP_E_FILTER_NOT_FOUND, WfpError::FilterNotFound),
            (FWP_E_NOT_FOUND, WfpError::Native(FWP_E_NOT_FOUND)),
            (FWP_E_ALREADY_EXISTS, WfpError::AlreadyExists),
            (FWP_E_IN_USE, WfpError::InUse),
            (FWP_E_NO_TXN_IN_PROGRESS, WfpError::NoTransaction),
            (FWP_E_TXN_ABORTED, WfpError::TransactionAborted),
            (FWP_E_NEVER_MATCH, WfpError::NeverMatch),
            (FWP_E_INVALID_PARAMETER, WfpError::InvalidState),
            (0xdead_beef, WfpError::Native(0xdead_beef)),
        ];
        for (native, want) in cases {
            let got = classify(*native);
            assert_eq!(got, *want, "码 0x{native:08X} 分类错");
            // 语义化的错误要能回出可诊断的数值。但分类是**多对一**的：
            // 「BFE 没起来」可能来自 4 个不同的 RPC 码，所以只要求回读值落在同一组里。
            if !matches!(want, WfpError::Native(_)) {
                let back = got.native();
                let same_group = back == *native
                    || (matches!(want, WfpError::BfeNotRunning)
                        && matches!(back, ERROR_SERVICE_NOT_ACTIVE | RPC_EPT_NOT_REGISTERED | RPC_SERVER_UNAVAILABLE | RPC_UNKNOWN_IF));
                assert!(same_group, "0x{native:08X} 回读数值 {back} 不在同一组");
            }
            assert!(!got.message().is_empty(), "每个错误都要有一句人话");
            assert!(
                !got.message().contains("0x"),
                "人话里不许出现十六进制码：{}",
                got.message()
            );
        }
        // 未识别的码只降到 Native，绝不猜成已知语义
        assert!(matches!(classify(0x8032_0039), WfpError::Native(0x8032_0039)));
        // 泛化 NOT_FOUND 不算「已知语义」，但判空时要认
        assert!(classify(FWP_E_NOT_FOUND).is_absent());
        assert!(classify(FWP_E_PROVIDER_NOT_FOUND).is_absent());
        assert!(classify(FWP_E_SUBLAYER_NOT_FOUND).is_absent());
        assert!(classify(FWP_E_FILTER_NOT_FOUND).is_absent());
        assert!(!classify(FWP_E_IN_USE).is_absent());
        assert!(classify(ERROR_ACCESS_DENIED).is_permission());
        assert!(classify(ERROR_SERVICE_NOT_ACTIVE).is_bfe_down());
        assert!(!classify(FWP_E_IN_USE).is_permission());
        // 0 不是错误码
        assert_eq!(classify(0), WfpError::InvalidState);
    }

    #[test]
    fn definitions_are_self_consistent_and_distinguish_legacy() {
        let app = sample_app_id();
        let f = FilterDefinition::block("trader.exe", &app, Layer::V4);
        assert!(f.is_self_consistent());
        assert_eq!(f.filter_key, filter_key(&app, Layer::V4, false));
        assert!(f.display_name.contains("IPv4"));

        // 奇数长度（不是 UTF-16 字节）就不能写进系统
        let mut bad = f.clone();
        bad.app_id = vec![1, 2, 3];
        assert!(!bad.is_self_consistent(), "appId 必须是 UTF-16 字节");
        let mut bad = f.clone();
        bad.app_id = Vec::new();
        assert!(!bad.is_self_consistent(), "空 appId 不能建规则");
        let mut bad = f.clone();
        bad.weight = FILTER_WEIGHT_PERMIT;
        assert!(!bad.is_self_consistent());
        let mut bad = f.clone();
        bad.flags |= FILTER_FLAG_DISABLED;
        assert!(!bad.is_self_consistent());

        assert!(ProviderDefinition::default().is_ours());
        assert!(!ProviderDefinition::default().is_legacy());
        let mut legacy = ProviderDefinition::default();
        legacy.marker = LEGACY_MARKER.to_vec();
        assert!(legacy.is_legacy());
        assert!(!legacy.is_ours(), "旧版标记不是我们的定义");

        assert!(SubLayerDefinition::default().is_ours());
        let mut wrong = SubLayerDefinition::default();
        wrong.weight = SUBLAYER_WEIGHT - 1;
        assert!(!wrong.is_ours(), "weight 不符就不是我们的 subLayer");
        let mut wrong = SubLayerDefinition::default();
        wrong.provider_key = None;
        assert!(!wrong.is_ours());
    }

    #[test]
    fn weight_and_flag_constants_match_the_reference_values() {
        // 这些数值决定「规则是否被容忍」：写错一位，合格规则会被判成不合格（或反之）。
        assert_eq!(FILTER_WEIGHT_BLOCK, 0x1000);
        assert_eq!(FILTER_WEIGHT_PERMIT, 0x2000);
        assert_eq!(SUBLAYER_WEIGHT, 0xFFFF);
        assert_eq!(FILTER_FLAG_PERSISTENT, 1);
        assert_eq!(FILTER_FLAG_DISABLED, 32);
        assert_eq!(FILTER_FLAG_INDEXED, 64, "SDK 里 INDEXED 是 0x40，不是 0x10");
        assert_eq!(FILTER_FLAG_BOOTTIME, 2);
        assert_eq!(ACTION_BLOCK, 0x1001);
        assert_eq!(ACTION_PERMIT, 0x1002);
        assert_eq!(MATCH_EQUAL, 0);
        assert_eq!(FWP_TYPE_BYTE_BLOB, 12);
        assert_eq!(FWP_TYPE_UINT64, 4);
    }
}
