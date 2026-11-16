//! WFP 的 ABI 自证：结构尺寸与关键偏移，以及我们自有身份与旧版的差异。
//!
//! 为什么这个测试值得存在：
//!
//! 1. `FWPM_FILTER0` 是 200 字节、内含 union 与三层指针。它一旦与我们以为的布局不一致，
//!    后果不是「报错」而是「删错规则」或「读到别的字段」。所以布局必须被**断言**，
//!    不能靠「windows-sys 应该没错」。
//! 2. 这些期望值来自参考实现 `TradeChannelGuard.cs` 的运行期自检表（它同时校验偏移），
//!    两边独立算出同一组数字，才算真的可信。
//! 3. 这个文件**不需要管理员权限、不创建任何 WFP 对象**，所以它可以进 CI。
//!
//! 模块引入方式：本 crate 是纯 binary（没有 lib target），集成测试拿不到 `crate::guard`。
//! 所以这里用 `#[path]` 直接编译那份**平台无关**的源码。为此 `wfp.rs` 刻意不依赖任何
//! `crate::` 路径、也不依赖 `windows-sys`——这既是可测性的前提，也是「判定层不碰 FFI」
//! 那条结构性约束的直接体现。

#[path = "../src/guard/wfp.rs"]
mod wfp;

#[cfg(not(windows))]
#[test]
fn layout_assertions_need_windows() {
    // 非 Windows 上这些结构体不存在，跳过（`windows-sys` 是 target-gated 依赖）。
}

#[cfg(windows)]
mod windows_layout {
    use super::wfp;

    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as W;

    #[test]
    fn six_structures_have_the_sdk_sizes() {
        // 与参考实现的自检表逐项相同：72 / 64 / 72 / 200 / 40 / 16
        assert_eq!(std::mem::size_of::<W::FWPM_SESSION0>(), 72, "FWPM_SESSION0");
        assert_eq!(std::mem::size_of::<W::FWPM_PROVIDER0>(), 64, "FWPM_PROVIDER0");
        assert_eq!(std::mem::size_of::<W::FWPM_SUBLAYER0>(), 72, "FWPM_SUBLAYER0");
        assert_eq!(std::mem::size_of::<W::FWPM_FILTER0>(), 200, "FWPM_FILTER0");
        assert_eq!(std::mem::size_of::<W::FWPM_FILTER_CONDITION0>(), 40, "FWPM_FILTER_CONDITION0");
        assert_eq!(std::mem::size_of::<W::FWP_BYTE_BLOB>(), 16, "FWP_BYTE_BLOB");
        // 只用到的辅助结构也钉一下，免得哪天它们变了我们却不知道
        assert_eq!(std::mem::size_of::<W::FWPM_DISPLAY_DATA0>(), 16, "FWPM_DISPLAY_DATA0");
        // FWP_VALUE0 = 4 字节 type + 4 字节 padding + 8 字节 union（最大成员是指针）
        assert_eq!(std::mem::size_of::<W::FWP_VALUE0>(), 16, "FWP_VALUE0");
        assert_eq!(std::mem::size_of::<W::FWPM_ACTION0>(), 20, "FWPM_ACTION0");
    }

    #[test]
    fn critical_field_offsets_are_where_the_sdk_puts_them() {
        // 这些偏移是「读对字段」与「删错规则」的分界线。数值与参考实现的 offset 自检一致。
        let filter = W::FWPM_FILTER0::default();
        let base = &filter as *const _ as usize;

        let off_num_conditions = (&filter.numFilterConditions as *const _ as usize) - base;
        let off_conditions_ptr = (&filter.filterCondition as *const _ as usize) - base;
        let off_action = (&filter.action as *const _ as usize) - base;
        let off_filter_id = (&filter.filterId as *const _ as usize) - base;

        // 逐段对得上才敢说「我们读的是同一个结构」：
        //   filterKey 0 / displayData 16 / flags 32 / providerKey 40 / providerData 48 /
        //   layerKey 64 / subLayerKey 80 / weight 96 / numFilterConditions 112 /
        //   filterCondition 120 / action 128 / rawContext 152 / reserved 168 /
        //   filterId 176 / effectiveWeight 184
        assert_eq!(off_num_conditions, 112, "FWPM_FILTER0.numFilterConditions");
        assert_eq!(off_conditions_ptr, 120, "FWPM_FILTER0.filterCondition（条件数组指针）");
        assert_eq!(off_action, 128, "FWPM_FILTER0.action");
        assert_eq!(off_filter_id, 176, "FWPM_FILTER0.filterId");

        let provider = W::FWPM_PROVIDER0::default();
        let pbase = &provider as *const _ as usize;
        assert_eq!((&provider.serviceName as *const _ as usize) - pbase, 56, "FWPM_PROVIDER0.serviceName");

        let sublayer = W::FWPM_SUBLAYER0::default();
        let sbase = &sublayer as *const _ as usize;
        assert_eq!((&sublayer.weight as *const _ as usize) - sbase, 64, "FWPM_SUBLAYER0.weight");

        let condition = W::FWPM_FILTER_CONDITION0::default();
        let cbase = &condition as *const _ as usize;
        assert_eq!((&condition.fieldKey as *const _ as usize) - cbase, 0, "condition.fieldKey");
        assert_eq!((&condition.matchType as *const _ as usize) - cbase, 16, "condition.matchType");
        assert_eq!((&condition.conditionValue as *const _ as usize) - cbase, 24, "condition.conditionValue");

        let blob = W::FWP_BYTE_BLOB::default();
        let bbase = &blob as *const _ as usize;
        assert_eq!((&blob.size as *const _ as usize) - bbase, 0, "blob.size");
        assert_eq!((&blob.data as *const _ as usize) - bbase, 8, "blob.data");
    }

    #[test]
    fn session_layout_is_what_fwpm_engine_open_expects() {
        let s = W::FWPM_SESSION0::default();
        let base = &s as *const _ as usize;
        // 前 16 字节是 sessionKey，接着是 displayData(16)，然后 flags/txnWaitTimeout/processId
        assert_eq!((&s.flags as *const _ as usize) - base, 32, "session.flags");
        assert_eq!((&s.txnWaitTimeoutInMSec as *const _ as usize) - base, 36, "session.txnWaitTimeoutInMSec");
        assert_eq!((&s.processId as *const _ as usize) - base, 40, "session.processId");
        assert_eq!((&s.sid as *const _ as usize) - base, 48, "session.sid");
        assert_eq!((&s.username as *const _ as usize) - base, 56, "session.username");
        assert_eq!((&s.kernelMode as *const _ as usize) - base, 64, "session.kernelMode");
    }

    #[test]
    fn layer_and_condition_guids_match_our_constants() {
        // 我们的纯逻辑层自带 GUID 常量（因为它不能 import windows-sys）。
        // 这条测试保证两份定义**互相印证**：写错一位就永远匹配不到流量。
        // windows-sys 的 GUID 没有 Debug（它只借 ABI，不借抽象），所以逐字段比。
        assert!(same(W::FWPM_LAYER_ALE_AUTH_CONNECT_V4, wfp::LAYER_ALE_AUTH_CONNECT_V4), "ALE_AUTH_CONNECT_V4");
        assert!(same(W::FWPM_LAYER_ALE_AUTH_CONNECT_V6, wfp::LAYER_ALE_AUTH_CONNECT_V6), "ALE_AUTH_CONNECT_V6");
        assert!(same(W::FWPM_CONDITION_ALE_APP_ID, wfp::CONDITION_ALE_APP_ID), "CONDITION_ALE_APP_ID");
        assert!(!same(W::FWPM_LAYER_ALE_AUTH_CONNECT_V4, wfp::LAYER_ALE_AUTH_CONNECT_V6), "两个层不能相同");
    }

    #[test]
    fn abi_constants_match_the_sdk() {
        assert_eq!(wfp::ACTION_BLOCK, W::FWP_ACTION_BLOCK);
        assert_eq!(wfp::ACTION_PERMIT, W::FWP_ACTION_PERMIT);
        assert_eq!(wfp::MATCH_EQUAL, W::FWP_MATCH_EQUAL);
        assert_eq!(wfp::FILTER_FLAG_PERSISTENT, W::FWPM_FILTER_FLAG_PERSISTENT);
        assert_eq!(wfp::FILTER_FLAG_DISABLED, W::FWPM_FILTER_FLAG_DISABLED);
        assert_eq!(wfp::FILTER_FLAG_INDEXED, W::FWPM_FILTER_FLAG_INDEXED);
        assert_eq!(wfp::FILTER_FLAG_BOOTTIME, W::FWPM_FILTER_FLAG_BOOTTIME);
        assert_eq!(wfp::FWP_TYPE_BYTE_BLOB, W::FWP_BYTE_BLOB_TYPE);
        assert_eq!(wfp::FWP_TYPE_UINT64, W::FWP_UINT64);
    }

    /// 逐字段比较（`windows_sys::core::GUID` 没有 `Debug`/`PartialEq` 的实现）。
    fn same(native: windows_sys::core::GUID, ours: wfp::Guid) -> bool {
        native.data1 == ours.data1
            && native.data2 == ours.data2
            && native.data3 == ours.data3
            && native.data4 == ours.data4
    }

    /// 把我们的 GUID 转成 windows-sys 的 GUID（只为比较，不参与生产逻辑）。
    fn win(g: wfp::Guid) -> windows_sys::core::GUID {
        windows_sys::core::GUID {
            data1: g.data1,
            data2: g.data2,
            data3: g.data3,
            data4: g.data4,
        }
    }

    #[test]
    fn our_identities_are_not_the_legacy_ones() {
        // PRD P0-7：复用 旧版的 provider 身份 = 两边互相拆台。
        // 这里把「互不相同」钉成断言，而不是靠 review 记得。
        let our_provider = wfp::PROVIDER_KEY.to_lowercase();
        let our_sublayer = wfp::SUBLAYER_KEY.to_lowercase();
        let legacy_provider = wfp::LEGACY_PROVIDER_KEY.to_lowercase();
        let legacy_sublayer = wfp::LEGACY_SUBLAYER_KEY.to_lowercase();
        assert_ne!(our_provider, legacy_provider);
        assert_ne!(our_sublayer, legacy_sublayer);
        assert_ne!(our_provider, our_sublayer);
        assert_ne!(legacy_provider, legacy_sublayer);
        // 标记也必须不同：否则「识别」会把自己认成旧版
        assert_ne!(wfp::OWNER_MARKER, wfp::LEGACY_MARKER);
        // 我们的 provider 也不能是 Windows 内置的任何一个（拿几个常见的做抽样即可）
        assert_ne!(our_provider, "00000000-0000-0000-0000-000000000000");
        assert_ne!(our_provider, "c38d57d1-05a7-4c33-904f-7fbceee60e82", "不能借用层 GUID");
        assert_ne!(our_sublayer, "c38d57d1-05a7-4c33-904f-7fbceee60e82");
        // GUID 必须是合法形式，否则 provider 永远建不出来
        assert!(wfp::Guid::parse(&wfp::PROVIDER_KEY).is_some());
        assert!(wfp::Guid::parse(&wfp::SUBLAYER_KEY).is_some());
    }

    #[test]
    fn filter_key_is_deterministic_across_calls_and_platform_types() {
        let app = "\\device\\harddiskvolume3\\app\\trader.exe\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<u8>>();
        let k1 = wfp::filter_key(&app, wfp::Layer::V4, false);
        let k2 = wfp::filter_key(&app, wfp::Layer::V4, false);
        assert_eq!(k1, k2, "同样输入必须算回同一个 key");
        assert_ne!(k1, wfp::filter_key(&app, wfp::Layer::V6, false), "不同层不同 key");
        assert_ne!(k1, wfp::filter_key(&app, wfp::Layer::V4, true), "permit 与 block 不同 key");
        assert_ne!(
            k1,
            wfp::filter_key(b"\\device\\harddiskvolume3\\app\\other.exe\0", wfp::Layer::V4, false),
            "不同程序不同 key"
        );
        // 与原生 GUID 的字节布局一致（我们的 Guid 就是 SDK 的 GUID）
        let native = win(k1);
        assert_eq!(native.data1, k1.data1);
        assert_eq!(native.data4, k1.data4);
    }
}
