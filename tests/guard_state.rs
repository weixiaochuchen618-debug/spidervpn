//! 状态判定（`guard::state::evaluate`）的全分支验证。
//!
//! 判定层是纯函数：不需要管理员、不需要 WFP、不读真实时钟（时钟由 `EvalContext` 注入）。
//! 这里把 PRD §4.1 与架构 §6.6.2 的每一行都钉成一条用例——**特别是「不许乐观」的那几条**：
//!
//! - 没有任何证据 → `Unknown`（永远不许 `Protected`）；
//! - 名单为空 / 全设直连 → `Unprotected`，不是故障、也不是 `Protected`；
//! - 只覆盖一族 / 被禁用 / 非持久 / 认不出来 → `Unprotected`；
//! - 读取失败、BFE 没起、旧版在跑、证据跨开机或跨配置、存储不可信 → `Unknown`。
//!
//! 本文件只覆盖**判定层**。记录字节的严格解析（长度/schema/Sha256/StoreKind）在
//! `src/guard/evidence.rs` 的内联单测里，那里能直接调 `parse_record`。

#[path = "../src/guard/wfp.rs"]
mod wfp;
#[path = "../src/guard/identity.rs"]
mod identity;
#[path = "../src/guard/state.rs"]
mod state;

use std::path::Path;

use identity::{IdentityEnv, IdentityError, ProgramIdentity, ResolvedEntry, UnresolvedEntry};
use state::{
    age_text, config_digest, config_digest_light, evaluate, freshness_of, iso8601_utc,
    summary_for, EvalContext, EvaluationInput, FilterSlot, FixedClock, Freshness, GuardDetection,
    GuardEvidence, GuardReason, GuardRecord, GuardSource, GuardState, GuardStatus, ProgramEvidence,
    VerifyPending, EVIDENCE_MAX_AGE_SECS, RECORD_SCHEMA, STALE_AGING_SECS,
};
use wfp::{Layer, WfpError};

const NOW: f64 = 1_700_000_010.0;
const VERIFIED_AT: f64 = 1_700_000_000.0;

fn resolved(name: &str, path: &str) -> ResolvedEntry {
    ResolvedEntry { name: name.to_string(), path: path.into() }
}

fn identity(name: &str, path: &str) -> ProgramIdentity {
    ProgramIdentity {
        name: name.to_string(),
        path: path.into(),
        app_id: app_id(path),
        device_path: path.to_lowercase(),
    }
}

fn good_slot(id: u64) -> FilterSlot {
    FilterSlot { present: true, recognized: true, persistent: true, disabled: false, filter_id: Some(id) }
}

fn app_id(path: &str) -> Vec<u8> {
    path.encode_utf16().chain(std::iter::once(0u16)).flat_map(|u| u.to_le_bytes()).collect()
}

fn program(name: &str, path: &str) -> ProgramEvidence {
    ProgramEvidence {
        name: name.to_string(),
        path: path.to_string(),
        app_id: app_id(path),
        ipv4: good_slot(1),
        ipv6: good_slot(2),
    }
}

fn detection_ok() -> GuardDetection {
    GuardDetection {
        provider_present: true,
        sublayer_present: true,
        infrastructure_verified: true,
        legacy_guard_present: false,
        bfe_ready: true,
    }
}

fn evidence(programs: Vec<ProgramEvidence>) -> GuardEvidence {
    GuardEvidence {
        programs,
        detection: detection_ok(),
        read_error: None,
        verified_at_epoch: Some(VERIFIED_AT),
        verified_at_tick_ms: None,
        source: GuardSource::ElevatedVerify,
        config_digest: "digest".into(),
        boot_id: "boot".into(),
        extra_owned_filters: 0,
        legacy_running_at_verify: false,
        // 空 = 不做 StoreKind 交叉校验；要测串场的用例自己填。
        store_kind: String::new(),
    }
}

/// 判定上下文：boot/摘要与 [`evidence`] 对齐，时钟固定（不读真实时间）。
fn ctx_at(now: f64) -> EvalContext {
    EvalContext {
        current_boot_id: "boot".into(),
        current_config_digest: "digest".into(),
        verify_pending: VerifyPending::None,
        evidence_trusted: true,
        unsupported: false,
        store_kind: String::new(),
        clock: Box::new(FixedClock::new(now, 0)),
    }
}

fn eval<'a>(
    ev: &'a GuardEvidence,
    entries: &'a [ResolvedEntry],
    unresolved: &'a [UnresolvedEntry],
    ctx: &'a EvalContext,
) -> EvaluationInput<'a> {
    EvaluationInput {
        evidence: ev,
        entries,
        unresolved,
        trade_program_count: (entries.len() + unresolved.len()) as i64,
        trade_program_listed: (entries.len() + unresolved.len()) as i64,
        legacy_conflict: false,
        user_removed: false,
        ctx,
    }
}

#[test]
fn the_happy_path_needs_every_program_times_every_family() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe"), resolved("b.exe", "C:\\app\\b.exe")];
    let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe"), program("b.exe", "C:\\app\\b.exe")]);
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
    assert_eq!(st.state, GuardState::Protected);
    assert_eq!(st.reason, GuardReason::Ok);
    assert_eq!(st.trade_program_count, 2);
    assert_eq!(st.summary, "交易程序 IPv4/IPv6 直连保护已启用；断开通道后仍保留。");
    assert!(st.programs.iter().all(|p| p.ok()));
    // 少一个程序 → 立刻降级（不是「差不多就行了」）
    let entries_one = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let st = evaluate(&eval(&ev, &entries_one, &[], &ctx_at(NOW)));
    assert_eq!(st.state, GuardState::Protected, "只有 a 在名单里时，a 的两族都合格");
    let entries_extra = vec![
        resolved("a.exe", "C:\\app\\a.exe"),
        resolved("b.exe", "C:\\app\\b.exe"),
        resolved("c.exe", "C:\\app\\c.exe"),
    ];
    let st = evaluate(&eval(&ev, &entries_extra, &[], &ctx_at(NOW)));
    assert_eq!(st.state, GuardState::Unprotected, "名单里多了一个没有证据的程序");
    assert_eq!(st.reason, GuardReason::MissingFilter);
}

#[test]
fn missing_disabled_or_unrecognized_slots_all_prevent_protection() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let cases: [(&str, FilterSlot, GuardReason); 5] = [
        ("缺 IPv6", FilterSlot::absent(), GuardReason::MissingFilter),
        ("非持久", FilterSlot { persistent: false, ..good_slot(1) }, GuardReason::MissingFilter),
        ("认不出来", FilterSlot { recognized: false, ..good_slot(1) }, GuardReason::MissingFilter),
        ("被禁用", FilterSlot { disabled: true, ..good_slot(1) }, GuardReason::DisabledFilter),
        ("present 但全假", FilterSlot::absent(), GuardReason::MissingFilter),
    ];
    for (label, slot, want) in cases {
        let mut prog = program("a.exe", "C:\\app\\a.exe");
        prog.ipv6 = slot;
        let ev = evidence(vec![prog]);
        let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
        assert_eq!(st.state, GuardState::Unprotected, "{label}");
        assert_eq!(st.reason, want, "{label}");
    }
}

#[test]
fn empty_list_is_unprotected_empty_and_never_protected() {
    let ev = evidence(vec![]);
    let st = evaluate(&eval(&ev, &[], &[], &ctx_at(NOW)));
    assert_eq!(st.state, GuardState::Unprotected);
    assert_eq!(st.reason, GuardReason::EmptyProgramList);
    assert_eq!(st.trade_program_count, 0);
    assert_eq!(st.trade_program_listed, 0);
    assert_eq!(st.summary, "尚未添加要保护的程序，这不是故障。");
    assert!(!st.is_protected());
}

#[test]
fn minus_one_means_cannot_read_and_is_not_the_same_as_zero() {
    // `TradeProgramListed == -1` = 名单读不到。它与「名单是空的」必须分开：
    // 把「读不到」说成「尚未添加」是另一种不实信息。
    let ev = evidence(vec![]);
    let c = ctx_at(NOW);
    let mut inp = eval(&ev, &[], &[], &c);
    inp.trade_program_listed = -1;
    inp.trade_program_count = -1;
    let st = evaluate(&inp);
    assert_eq!(st.state, GuardState::Unknown);
    assert_eq!(st.reason, GuardReason::ReadError);
    assert_eq!(st.trade_program_count, -1);
    assert_eq!(st.trade_program_listed, -1);
    assert_eq!(st.summary, "交易保护状态无法确认。");
}

#[test]
fn unresolved_entries_cap_the_state() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    let unresolved = vec![UnresolvedEntry {
        name: "old.exe".into(),
        reason: "需要确认程序位置".into(),
        reason_id: "MissingPath".into(),
        path: None,
    }];
    let st = evaluate(&eval(&ev, &entries, &unresolved, &ctx_at(NOW)));
    assert_eq!(st.state, GuardState::Unprotected);
    assert_eq!(st.reason, GuardReason::ProgramUnresolved);
    assert_eq!(st.trade_program_count, 2);
    assert_eq!(st.programs.len(), 2);
    assert!(st.programs[0].participated);
    assert!(!st.programs[1].participated);
    assert_eq!(st.programs[1].unresolved_reason.as_deref(), Some("需要确认程序位置"));
}

#[test]
fn infrastructure_problems_are_unprotected_with_distinct_reasons() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    // provider 与 subLayer 都不在 → 缺失
    let mut ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    ev.detection = GuardDetection { infrastructure_verified: false, ..detection_ok() };
    ev.detection.provider_present = false;
    ev.detection.sublayer_present = false;
    assert_eq!(
        evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW))).reason,
        GuardReason::InfrastructureMissing
    );

    // 都在但定义不符（例如 GUID 被别人占了）→ 冲突
    let mut ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    ev.detection.infrastructure_verified = false;
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
    assert_eq!(st.reason, GuardReason::InfrastructureConflict);
    assert_eq!(st.state, GuardState::Unprotected);
    assert!(st.detection.provider_present, "检测结果要原样透出去，供诊断看");
}

#[test]
fn extra_owned_filters_lower_the_state() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let mut ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    ev.extra_owned_filters = 1;
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
    assert_eq!(st.reason, GuardReason::ExtraFilter);
    assert_eq!(st.state, GuardState::Unprotected);
}

#[test]
fn without_evidence_the_answer_is_unknown() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let ev = GuardEvidence::default();
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
    assert_eq!(st.state, GuardState::Unknown);
    assert_eq!(st.reason, GuardReason::NotVerifiedYet);
    assert_eq!(st.source, GuardSource::None);
    assert_eq!(st.evidence_at, None);
    assert!(!st.is_protected());
}

#[test]
fn read_errors_are_unknown_and_never_flip_to_unprotected() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    for (err, want) in [
        (WfpError::AccessDenied, GuardReason::NoPermission),
        (WfpError::BfeNotRunning, GuardReason::BfeUnavailable),
        (WfpError::Native(0x8032_0033), GuardReason::ReadError),
        (WfpError::InvalidState, GuardReason::ReadError),
    ] {
        let mut ev = evidence(vec![]);
        ev.source = GuardSource::None;
        ev.read_error = Some(err);
        let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
        assert_eq!(st.state, GuardState::Unknown, "{err:?} 不能猜成 Unprotected");
        assert_eq!(st.reason, want, "{err:?}");
    }
}

#[test]
fn a_record_can_carry_the_verdict_and_still_must_be_attributable() {
    // 记录就是本阶段的证据来源，但它只能证明「T 时刻、该 boot、该配置下逐条规则存在」。
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let mut ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    ev.read_error = Some(WfpError::AccessDenied);
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
    assert_eq!(st.state, GuardState::Protected);
    assert_eq!(st.source, GuardSource::ElevatedVerify);
    assert_eq!(st.evidence_age_secs, Some(10));

    // 但只要有一点点不可归属，立刻回落 Unknown（时间不在判据里）。
    // 跨开机与跨配置现在是**两个不同原因**：界面的下一步不一样。
    let mut c = ctx_at(NOW);
    c.current_boot_id = "another-boot".into();
    let st = evaluate(&eval(&ev, &entries, &[], &c));
    assert_eq!(st.reason, GuardReason::BootChanged);
    assert_eq!(st.state, GuardState::Unknown);
    assert!(!st.boot_id_match);

    let mut c = ctx_at(NOW);
    c.current_config_digest = "another-digest".into();
    let st = evaluate(&eval(&ev, &entries, &[], &c));
    assert_eq!(st.reason, GuardReason::ConfigChanged);
    assert_eq!(st.state, GuardState::Unknown);
    assert!(!st.config_digest_match);
}

#[test]
fn a15_a_long_connection_never_decays_into_unknown() {
    // A15：10 分钟内无事件 → 仍 Protected，且卡片能显示「10 分钟前核验」。
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    for minutes in [0u64, 1, 5, 10, 19] {
        let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(VERIFIED_AT + minutes as f64 * 60.0)));
        assert_eq!(st.state, GuardState::Protected, "{minutes} 分钟不许降级");
        assert_ne!(st.freshness, Freshness::Aging, "{minutes} 分钟还不算「较旧」");
        assert_ne!(st.freshness, Freshness::Expired, "{minutes} 分钟更不该过期");
    }
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(VERIFIED_AT + 600.0)));
    assert_eq!(st.age_text, "10 分钟前核验");
    assert_eq!(st.to_json()["GuardEvidenceAge"], "10 分钟前核验");
}

#[test]
fn a17_twenty_five_minutes_is_protected_but_marked_stale() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(VERIFIED_AT + 25.0 * 60.0)));
    assert_eq!(st.state, GuardState::Protected);
    assert_eq!(st.age_text, "较旧：25 分钟前核验");
    assert_eq!(st.freshness, Freshness::Aging, "界面据此显示「重新核验」按钮");
    assert_eq!(st.to_json()["GuardEvidenceStale"], true);
    // 禁止话术：任何字段里都不许出现「实时」
    let text = st.to_json().to_string();
    for banned in ["实时保护", "实时监控", "持续监控"] {
        assert!(!text.contains(banned), "禁止话术：{banned}");
    }
}

#[test]
fn a18_twenty_four_hours_is_the_only_time_based_downgrade() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let mut ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    // 23 小时 59 分：仍 Protected（只是「较旧」）
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(VERIFIED_AT + 23.0 * 3600.0 + 59.0 * 60.0)));
    assert_eq!(st.state, GuardState::Protected);
    assert_eq!(st.freshness, Freshness::Aging);
    // 25 小时：Unknown + 指定文案
    ev.verified_at_epoch = Some(VERIFIED_AT - 25.0 * 3600.0);
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(VERIFIED_AT)));
    assert_eq!(st.reason, GuardReason::EvidenceExpired);
    assert!(st.summary.contains("上次核验已超过 24 小时"), "{}", st.summary);
    assert!(!st.is_protected());
}

#[test]
fn a19_install_readback_counts_but_an_unknown_source_does_not() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let mut ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    ev.source = GuardSource::ElevatedInstallReadback;
    assert_eq!(
        evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW))).state,
        GuardState::Protected
    );
    ev.source = GuardSource::ElevatedVerify;
    assert_eq!(
        evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW))).state,
        GuardState::Protected
    );
    ev.source = GuardSource::None;
    assert_eq!(evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW))).state, GuardState::Unknown);
}

#[test]
fn a20_age_buckets_are_exact() {
    assert_eq!(age_text(0), "刚刚核验");
    assert_eq!(age_text(59), "刚刚核验");
    assert_eq!(age_text(60), "1 分钟前核验");
    assert_eq!(age_text(20 * 60 - 1), "19 分钟前核验");
    assert_eq!(age_text(20 * 60), "较旧：20 分钟前核验");
    // ≥ 60 分钟不再写「1380 分钟」这种丑数字
    assert_eq!(age_text(23 * 3600), "较旧：23 小时前核验");
    assert!(age_text(24 * 3600).contains("超过 24 小时"));
    // 四档边界逐点钉住
    assert_eq!(freshness_of(59), Freshness::JustVerified);
    assert_eq!(freshness_of(60), Freshness::Recent);
    assert_eq!(freshness_of(STALE_AGING_SECS - 1), Freshness::Recent);
    assert_eq!(freshness_of(STALE_AGING_SECS), Freshness::Aging);
    assert_eq!(freshness_of(EVIDENCE_MAX_AGE_SECS - 1), Freshness::Aging);
    assert_eq!(freshness_of(EVIDENCE_MAX_AGE_SECS), Freshness::Expired);
    assert_eq!(STALE_AGING_SECS, 1_200);
    assert_eq!(EVIDENCE_MAX_AGE_SECS, 86_400);
}

#[test]
fn bfe_down_and_legacy_running_are_unknown() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let mut ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    ev.detection.bfe_ready = false;
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
    assert_eq!(st.reason, GuardReason::BfeUnavailable);
    assert_eq!(st.state, GuardState::Unknown);

    let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    let c = ctx_at(NOW);
    let mut inp = eval(&ev, &entries, &[], &c);
    inp.legacy_conflict = true;
    let st = evaluate(&inp);
    assert_eq!(st.reason, GuardReason::LegacyConflict);
    assert_eq!(st.state, GuardState::Unknown);
}

#[test]
fn unsupported_platform_says_so_instead_of_unprotected() {
    let ev = GuardEvidence::default();
    let mut c = ctx_at(NOW);
    c.unsupported = true;
    let mut inp = eval(&ev, &[], &[], &c);
    inp.trade_program_count = -1;
    inp.trade_program_listed = -1;
    let st = evaluate(&inp);
    assert_eq!(st.state, GuardState::Unknown);
    assert_eq!(st.reason, GuardReason::Unsupported);
    assert!(st.unsupported);
    assert_eq!(st.summary, "当前系统不支持交易程序直连保护。");
    assert_eq!(GuardStatus::unsupported().reason, GuardReason::Unsupported);
}

#[test]
fn evidence_for_another_executable_protects_nothing() {
    let entries = vec![resolved("new.exe", "C:\\app\\new.exe")];
    let ev = evidence(vec![program("old.exe", "C:\\app\\old.exe")]);
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
    assert_eq!(st.state, GuardState::Unprotected);
    assert_eq!(st.reason, GuardReason::MissingFilter);
    assert!(!st.programs[0].ipv4.present, "没找到证据就是没有槽位");
    assert!(st.programs[0].device_path.is_none());
}

#[test]
fn path_matching_is_case_insensitive_like_windows() {
    let entries = vec![resolved("a.exe", "C:\\APP\\A.EXE")];
    let ev = evidence(vec![program("a.exe", "c:\\app\\a.exe")]);
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
    assert_eq!(st.state, GuardState::Protected, "Windows 路径大小写不敏感");
}

#[test]
fn summaries_are_the_three_canonical_sentences() {
    assert_eq!(
        summary_for(GuardState::Protected, GuardReason::Ok),
        "交易程序 IPv4/IPv6 直连保护已启用；断开通道后仍保留。"
    );
    assert_eq!(
        summary_for(GuardState::Unprotected, GuardReason::MissingFilter),
        "交易程序直连保护未完整启用，请检查保护规则。"
    );
    assert_eq!(
        summary_for(GuardState::Unprotected, GuardReason::EmptyProgramList),
        "尚未添加要保护的程序，这不是故障。"
    );
    assert_eq!(
        summary_for(GuardState::Unprotected, GuardReason::NoTradePrograms),
        "名单里没有需要保护的程序（当前都设为直连或日常）。"
    );
    assert_eq!(summary_for(GuardState::Unknown, GuardReason::NotVerifiedYet), "交易保护状态无法确认。");
    // 禁止话术：全句子表扫一遍。
    // 注意「已解除」**不在**禁用列表里：`UserRemoved` 的中性文案必须说出这件事（Q8），
    // 禁用它是旧口径（当时还没有「用户主动解除」这个状态）。
    let states = [GuardState::Protected, GuardState::Unprotected, GuardState::Unknown];
    let reasons = [
        GuardReason::Ok,
        GuardReason::EmptyProgramList,
        GuardReason::NoTradePrograms,
        GuardReason::InfrastructureMissing,
        GuardReason::InfrastructureConflict,
        GuardReason::MissingFilter,
        GuardReason::ExtraFilter,
        GuardReason::DisabledFilter,
        GuardReason::ProgramUnresolved,
        GuardReason::UserRemoved,
        GuardReason::NoPermission,
        GuardReason::ReadError,
        GuardReason::BfeUnavailable,
        GuardReason::LegacyConflict,
        GuardReason::InstallFailed,
        GuardReason::SyncRefusedForeign,
        GuardReason::NotVerifiedYet,
        GuardReason::BootChanged,
        GuardReason::ConfigChanged,
        GuardReason::EvidenceExpired,
        GuardReason::EvidenceUnprotected,
        GuardReason::StoreMismatch,
        GuardReason::Corrupt,
        GuardReason::Unsupported,
    ];
    for s in states {
        for r in reasons {
            let text = summary_for(s, r);
            assert!(!text.is_empty(), "{s:?}/{r:?} 必须有句子");
            for banned in ["走交易线路", "子进程", "开机即保护", "一切正常", "正在实时保护"] {
                assert!(!text.contains(banned), "{s:?}/{r:?} 出现了禁用话术：{text}");
            }
        }
    }
}

#[test]
fn json_shape_matches_the_frontend_contract() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
    let v = st.to_json();
    assert_eq!(v["Guard"], "Protected");
    assert_eq!(v["TradeProgramCount"], 1);
    assert_eq!(v["TradeProgramListed"], 1);
    assert_eq!(v["GuardSummary"], "交易程序 IPv4/IPv6 直连保护已启用；断开通道后仍保留。");
    // 顶层字段：前端只渲染，不自己推断
    assert_eq!(v["GuardVerifyPending"], "None");
    assert_eq!(v["GuardEvidenceFreshness"], "JustVerified");
    assert_eq!(v["GuardEvidenceTrusted"], true);
    assert_eq!(v["GuardEvidenceBootId"], true);
    assert_eq!(v["GuardConfigDigest"], true);
    assert_eq!(v["GuardEvidence"]["Source"], "ElevatedVerify");
    assert_eq!(v["GuardEvidence"]["VerifiedAtUtc"], "2023-11-14T22:13:20Z");
    assert_eq!(v["GuardEvidence"]["AgeSeconds"], 10);
    assert_eq!(v["GuardEvidence"]["AgeText"], "刚刚核验");
    assert_eq!(v["GuardEvidence"]["Reason"], "Ok");
    assert_eq!(v["GuardEvidence"]["ReasonConclusive"], true);
    assert_eq!(v["GuardEvidence"]["Unsupported"], false);
    assert_eq!(v["GuardEvidence"]["LegacyGuardPresent"], false);
    assert_eq!(v["GuardEvidence"]["Detection"]["ProviderPresent"], true);
    assert_eq!(v["GuardEvidence"]["Detection"]["SubLayerPresent"], true);
    assert_eq!(v["GuardEvidence"]["Detection"]["InfrastructureVerified"], true);
    assert_eq!(v["GuardEvidence"]["Detection"]["BfeReady"], true);
    let p = &v["GuardEvidence"]["Programs"][0];
    assert_eq!(p["Name"], "a.exe");
    assert_eq!(p["Path"], "C:\\app\\a.exe");
    assert_eq!(p["Participated"], true);
    assert_eq!(p["Protected"], true);
    assert_eq!(p["UnresolvedReason"], serde_json::Value::Null);
    assert_eq!(p["IPv4"]["Present"], true);
    assert_eq!(p["IPv4"]["Recognized"], true);
    assert_eq!(p["IPv4"]["Persistent"], true);
    assert_eq!(p["IPv4"]["Disabled"], false);
    assert_eq!(p["IPv4"]["FilterId"], 1);
    assert_eq!(p["IPv6"]["FilterId"], 2);
}

#[test]
fn config_digest_is_stable_order_insensitive_and_content_sensitive() {
    let a = identity("a.exe", "C:\\app\\a.exe");
    let b = identity("b.exe", "C:\\app\\b.exe");
    let d1 = config_digest(&[a.clone(), b.clone()], &[], false);
    let d2 = config_digest(&[b, a.clone()], &[], false);
    assert_eq!(d1, d2, "顺序变化不该让证据作废");
    assert_eq!(d1.len(), 64);
    assert_ne!(d1, config_digest(&[a.clone()], &[], false));
    assert_ne!(
        d1,
        config_digest(&[a.clone(), identity("b.exe", "C:\\app\\B2.exe")], &[], false)
    );
    // 大小写不敏感
    assert_eq!(
        config_digest(&[a.clone()], &[], false),
        config_digest(&[identity("A.EXE", "C:\\APP\\A.EXE")], &[], false)
    );
    // 意图参与摘要：解除后旧证据必须对不上（Q8）
    assert_ne!(
        config_digest(&[a.clone()], &[], false),
        config_digest(&[a], &[], true)
    );
    // 未解析条目参与摘要：它们会让状态最多 Unprotected
    let un = vec![UnresolvedEntry {
        name: "x.exe".into(),
        reason: "需要确认程序位置".into(),
        reason_id: "MissingPath".into(),
        path: None,
    }];
    assert_ne!(
        config_digest(&[], &[], false),
        config_digest(&[], &un, false)
    );
    assert_eq!(config_digest(&[], &[], false), config_digest(&[], &[], false));
}

#[test]
fn identity_and_light_digests_agree() {
    struct Noop;
    impl IdentityEnv for Noop {
        fn exists(&self, _p: &Path) -> bool {
            true
        }
        fn is_reparse_point(&self, _p: &Path) -> bool {
            false
        }
        fn app_id(&self, p: &Path) -> Result<Vec<u8>, IdentityError> {
            Ok(app_id(&p.to_string_lossy()))
        }
    }
    let id = identity::resolve_entry("a.exe", Some("C:\\app\\a.exe"), &Noop).unwrap();
    let same = config_digest(std::slice::from_ref(&id), &[], false);
    // 两个入口必须可互换，否则「写证据」与「读证据」会落到不同摘要上（静默永久故障）。
    assert_eq!(same, config_digest_light(&[resolved("a.exe", "C:\\app\\a.exe")], &[], false));
}

#[test]
fn iso8601_is_utc() {
    assert_eq!(iso8601_utc(0.0), "1970-01-01T00:00:00Z");
    assert_eq!(iso8601_utc(1_700_000_000.5), "2023-11-14T22:13:20Z");
    assert_eq!(iso8601_utc(951_782_400.0), "2000-02-29T00:00:00Z");
    assert_eq!(iso8601_utc(1_709_164_800.0), "2024-02-29T00:00:00Z");
}

#[test]
fn the_evidence_record_round_trips_and_rejects_anything_it_does_not_understand() {
    let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    let rec = GuardRecord::from_evidence(&ev, "nonce-1", std::process::id(), true, 7);
    assert_eq!(rec.schema_version, RECORD_SCHEMA);
    assert_eq!(rec.nonce, "nonce-1");
    assert!(rec.verify_seal(), "写出的记录必须自带可校验的 Sha256");

    // 序列化往返：字段逐项相同，封条仍然有效
    let bytes = serde_json::to_vec(&rec).unwrap();
    let back: GuardRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back, rec);
    assert!(back.verify_seal());
    assert!(!back.is_user_removed());

    let ev2 = back.to_evidence();
    assert_eq!(ev2.source, GuardSource::ElevatedVerify);
    assert_eq!(ev2.programs.len(), 1);
    assert!(ev2.programs[0].ipv4.ok() && ev2.programs[0].ipv6.ok());
    assert_eq!(ev2.verified_at_epoch, Some(VERIFIED_AT), "时间必须原样还原");

    // 记录被当证据用时，判定结果与原始证据一致
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let st = evaluate(&eval(&ev2, &entries, &[], &ctx_at(NOW)));
    assert_eq!(st.state, GuardState::Protected);
    assert_eq!(st.source, GuardSource::ElevatedVerify);

    // 任何字段被改动而没重算封条 → 损坏（挡误改/损坏，不挡管理员）
    let mut tampered = rec.clone();
    tampered.programs[0].ipv4.disabled = true;
    assert!(!tampered.verify_seal());
    // 重算封条后又是一个自洽的记录——这正是「Sha256 不是防伪」的含义
    tampered.seal();
    assert!(tampered.verify_seal());

    // schema 不认识 → 拒绝（绝不做宽松兜底）。这里钉住字段本身；
    // `parse_record` 的拒绝顺序（长度→JSON→schema→StoreKind→封条→来源）在 evidence.rs 内联单测里。
    let mut bad = rec.clone();
    bad.schema_version = 42;
    assert_ne!(bad.schema_version, RECORD_SCHEMA);

    // 「用户主动解除」是标记，不是证据
    let mut removed = rec.clone();
    removed.source = state::SOURCE_USER_REMOVED.to_string();
    assert!(removed.is_user_removed());
    assert_eq!(removed.to_evidence().source, GuardSource::None, "标记不得冒充证据来源");
}

#[test]
fn slots_and_layers_survive_the_record_encoding() {
    let slot = FilterSlot { present: true, recognized: true, persistent: true, disabled: true, filter_id: Some(99) };
    let rec: state::RecordSlot = slot.into();
    let back: FilterSlot = rec.into();
    assert_eq!(back, slot);
    assert_eq!(Layer::ALL.len(), 2);
    let prog = ProgramEvidence { ipv4: good_slot(1), ipv6: good_slot(2), ..program("a.exe", "x") };
    assert!(prog.slot(Layer::V4).ok());
    assert!(prog.slot(Layer::V6).ok());
}

// ---------------------------------------------------------------------------
// 新增分支：三种空态、用户解除、存储可信、缺失时龄、本次核验结果
// ---------------------------------------------------------------------------

#[test]
fn a24_all_direct_entries_are_unprotected_without_a_red_alert() {
    // 名单里有 2 条进程，但都设成直连/日常 → 没有需要保护的对象。
    // 这不是用户做错了什么，不得进「未完整开启」的红色告警（A24/A25）。
    let ev = evidence(vec![]);
    let c = ctx_at(NOW);
    let mut inp = eval(&ev, &[], &[], &c);
    inp.trade_program_count = 0;
    inp.trade_program_listed = 2;
    let st = evaluate(&inp);
    assert_eq!(st.state, GuardState::Unprotected);
    assert_eq!(st.reason, GuardReason::NoTradePrograms);
    assert_eq!(st.summary, "名单里没有需要保护的程序（当前都设为直连或日常）。");
    assert!(st.reason.is_conclusive(), "这是确定的事实，不是「还不知道」");
}

#[test]
fn user_removed_is_a_neutral_state_not_a_failure() {
    // 无证据 + 用户主动解除 → 说「已解除」，不是「无法确认」
    let ev = GuardEvidence::default();
    let c = ctx_at(NOW);
    let entries = [resolved("a.exe", "C:\\app\\a.exe")];
    let mut inp = eval(&ev, &entries, &[], &c);
    inp.user_removed = true;
    let st = evaluate(&inp);
    assert_eq!(st.state, GuardState::Unprotected);
    assert_eq!(st.reason, GuardReason::UserRemoved);
    assert_eq!(st.summary, "交易保护已解除；下次连接会重新启用。");

    // 即使还残留着旧证据，也不能说「已保护」——用户刚亲手关掉它
    let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    let c = ctx_at(NOW);
    let mut inp = eval(&ev, &entries, &[], &c);
    inp.user_removed = true;
    let st = evaluate(&inp);
    assert_eq!(st.state, GuardState::Unprotected);
    assert_eq!(st.reason, GuardReason::UserRemoved);
}

#[test]
fn untrusted_or_mismatched_storage_can_never_be_protected() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);

    // 存储能被本进程写 → 内容再漂亮也不可信（P0-16/A21）
    let mut c = ctx_at(NOW);
    c.evidence_trusted = false;
    let st = evaluate(&eval(&ev, &entries, &[], &c));
    assert_eq!(st.state, GuardState::Unknown);
    assert_eq!(st.reason, GuardReason::EvidenceUnprotected);
    assert!(!st.evidence_trusted);

    // 生产读到测试记录（或反之）→ 串场，不认
    let mut ev2 = ev.clone();
    ev2.store_kind = "Registry".into();
    let mut c = ctx_at(NOW);
    c.store_kind = "IsolatedFile".into();
    let st = evaluate(&eval(&ev2, &entries, &[], &c));
    assert_eq!(st.state, GuardState::Unknown);
    assert_eq!(st.reason, GuardReason::StoreMismatch);
}

#[test]
fn a_record_without_any_time_reading_is_corrupt_not_old() {
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let mut ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    ev.verified_at_epoch = None;
    ev.verified_at_tick_ms = None;
    let st = evaluate(&eval(&ev, &entries, &[], &ctx_at(NOW)));
    assert_eq!(st.state, GuardState::Unknown);
    assert_eq!(st.reason, GuardReason::Corrupt, "没有时龄就不能猜「旧」或「新」");
    assert_eq!(st.evidence_age_secs, None);
    assert_eq!(st.age_text, "");
}

#[test]
fn verify_pending_never_changes_the_three_state() {
    // A23：断开后重新核验被拒 → 仍是 Protected（较旧）+ 本次未能重新核验，
    // **不得**一夜回到 Unknown。
    let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
    let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
    for pending in [VerifyPending::Declined, VerifyPending::Failed, VerifyPending::Unknown] {
        let mut c = ctx_at(VERIFIED_AT + 25.0 * 60.0);
        c.verify_pending = pending;
        let st = evaluate(&eval(&ev, &entries, &[], &c));
        assert_eq!(st.state, GuardState::Protected, "{pending:?} 不许改三态");
        assert_eq!(st.freshness, Freshness::Aging);
        assert_eq!(st.verify_pending, pending);
        assert_eq!(st.to_json()["GuardVerifyPending"], pending.as_str());
    }
}
