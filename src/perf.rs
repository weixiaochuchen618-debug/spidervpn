//! 线路响应采样与聚合。
//!
//! 采样点只有一个：每次**真实测得的延迟**（连接自检、界面「测一次」、界面打开了
//! 窗口时的每 30 秒补测）。写盘是追加式的按小时文件 `perf\YYYYMMDD-HH.jsonl`：
//! 启动不扫全量，查 30 分钟只读两个文件、查 24 小时最多读 25 个。
//!
//! 聚合形状对齐 旧版的 `QualityHistory`（`Series[].Aggregate.Buckets`），
//! 前端 `qualityHistory()` 直接画曲线，不需要第二套投影。

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 一行采样。字段名短，但含义固定：`at` 是 Unix 秒。
///
/// `ms` 为 `None` 表示**这次探测没有拿到可用读数**（超时/连接失败/引擎没起）。
/// 这种行不画点，但必须记：首页的「未响应比例」是 `未响应/有效尝试`，只记成功
/// 的那一份会让它永远显示 `0/M（0%）`——那是断言「一次都没失败」，不是事实。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub at_unix: i64,
    pub line_id: String,
    pub profile: String,
    pub ms: Option<u64>,
    /// 空串 = 有读数；否则是 旧版的原因词（`MeasurementTimeout` 等）。
    pub reason: String,
}

impl Sample {
    fn to_line(&self) -> String {
        json!({
            "at": self.at_unix,
            "lineId": self.line_id,
            "profile": self.profile,
            "ms": self.ms,
            "reason": self.reason,
        })
        .to_string()
    }

    fn from_line(line: &str) -> Option<Self> {
        let v: Value = serde_json::from_str(line).ok()?;
        Some(Self {
            at_unix: v.get("at").and_then(Value::as_i64)?,
            line_id: v.get("lineId").and_then(Value::as_str).unwrap_or("").to_string(),
            profile: v.get("profile").and_then(Value::as_str).unwrap_or("").to_string(),
            ms: v.get("ms").and_then(Value::as_u64),
            // 旧文件没有这个字段：当成功样本处理（当时只写成功）。
            reason: v.get("reason").and_then(Value::as_str).unwrap_or("").to_string(),
        })
    }

    /// 旧版的分档：`>=500` 较差、`>200` 一般、其余良好；没读数 = 未知。
    pub fn quality(&self) -> &'static str {
        match self.ms {
            None => "Unknown",
            Some(ms) if ms >= 500 => "Poor",
            Some(ms) if ms > 200 => "Fair",
            Some(_) => "Good",
        }
    }
}

/// 统计口径对齐 旧版的 `LQStatistics`。
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Stats {
    pub sample_count: u32,
    pub measured: u32,
    pub timeouts: u32,
    pub controller: u32,
    pub average: Option<f64>,
    pub median: Option<f64>,
    pub min: Option<u64>,
    pub max: Option<u64>,
    pub p95: Option<u64>,
}

impl Stats {
    fn of(samples: &[&Sample]) -> Self {
        let mut values: Vec<u64> = samples.iter().filter_map(|s| s.ms).collect();
        let mut timeouts = 0;
        let mut controller = 0;
        for sample in samples {
            match sample.reason.as_str() {
                "MeasurementTimeout" => timeouts += 1,
                "ControllerUnavailable" => controller += 1,
                _ => {}
            }
        }
        values.sort_unstable();
        let mut stats = Stats {
            sample_count: samples.len() as u32,
            measured: values.len() as u32,
            timeouts,
            controller,
            ..Stats::default()
        };
        if !values.is_empty() {
            let sum: u64 = values.iter().sum();
            stats.average = Some((sum as f64 / values.len() as f64 * 10.0).round() / 10.0);
            stats.min = values.first().copied();
            stats.max = values.last().copied();
            // P95 用「向上取整的名次」而不是插值：与旧版同一个数。
            let rank = ((values.len() as f64) * 0.95).ceil() as usize;
            stats.p95 = Some(values[rank.saturating_sub(1).min(values.len() - 1)]);
            stats.median = Some(if values.len() % 2 == 1 {
                values[values.len() / 2] as f64
            } else {
                ((values[values.len() / 2 - 1] + values[values.len() / 2]) as f64) / 2.0
            });
        }
        stats
    }

    fn to_json(&self) -> Value {
        json!({
            "SampleCount": self.sample_count,
            "MeasuredCount": self.measured,
            "UnavailableCount": self.sample_count - self.measured,
            "TimeoutCount": self.timeouts,
            "ControllerUnavailableCount": self.controller,
            "AverageLatencyMs": opt_num(self.average),
            "MedianLatencyMs": opt_num(self.median),
            "MinLatencyMs": self.min,
            "MaxLatencyMs": self.max,
            "P95LatencyMs": self.p95,
        })
    }
}

fn opt_num(value: Option<f64>) -> Value {
    match value {
        Some(v) if v.fract() == 0.0 => json!(v as u64),
        Some(v) => json!(v),
        None => Value::Null,
    }
}

fn hour_file(root: &Path, at_unix: i64) -> PathBuf {
    let (y, m, d, h) = civil_from_unix(at_unix);
    root.join("perf").join(format!("{y:04}{m:02}{d:02}-{h:02}.jsonl"))
}

/// 追加一条采样。写失败只记一行日志，不影响测量本身——曲线缺一个点不该让测速失败。
pub fn record(root: &Path, line_id: &str, profile: &str, ms: u64, at: SystemTime) {
    append(root, line_id, profile, Some(ms), "", at);
}

/// 追加一条**失败**采样（这次探测没拿到可用读数）。曲线不画它，但统计要算它。
pub fn record_failure(root: &Path, line_id: &str, profile: &str, reason: &str, at: SystemTime) {
    append(root, line_id, profile, None, reason, at);
}

fn append(
    root: &Path,
    line_id: &str,
    profile: &str,
    ms: Option<u64>,
    reason: &str,
    at: SystemTime,
) {
    let at_unix = at.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let sample = Sample {
        at_unix,
        line_id: line_id.to_string(),
        profile: profile.to_string(),
        ms,
        reason: reason.to_string(),
    };
    let path = hour_file(root, at_unix);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    use std::io::Write;
    match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut file) => {
            let _ = writeln!(file, "{}", sample.to_line());
        }
        Err(e) => eprintln!("采样写入失败（不影响测速）：{e}"),
    }
}

/// 读 `[start, now]` 之间的采样，按线路过滤。
pub fn load(root: &Path, line_id: &str, start_unix: i64, end_unix: i64) -> Vec<Sample> {
    let mut out = Vec::new();
    let mut hour = start_unix - start_unix.rem_euclid(3600);
    // 上限 26 个小时文件：查 24 小时最多 25 个，多读一个兜住边界。
    for _ in 0..26 {
        if hour > end_unix {
            break;
        }
        let path = hour_file(root, hour);
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                if let Some(sample) = Sample::from_line(line) {
                    if sample.at_unix >= start_unix
                        && sample.at_unix <= end_unix
                        && (line_id.is_empty() || sample.line_id == line_id)
                    {
                        out.push(sample);
                    }
                }
            }
        }
        hour += 3600;
    }
    out.sort_by_key(|s| s.at_unix);
    out
}

/// 旧版的 `QualityHistory` 形状。空数据也返回 `Series`（一条空序列），
/// 前端据此显示「这个时间段尚无测量记录」，不需要另判 null。
pub fn history(root: &Path, line_id: &str, window: &str, now: SystemTime) -> Value {
    let now_unix = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let (span, buckets, label) = match window {
        "Day" => (86_400, 24, "Day"),
        _ => (1_800, 30, "ThirtyMinutes"),
    };
    let start = now_unix - span;
    let samples = load(root, line_id, start, now_unix);
    let width = span / buckets;

    let mut series: Vec<Value> = Vec::new();
    let mut profiles: Vec<String> = Vec::new();
    for sample in &samples {
        let profile = if sample.profile.is_empty() { "标准".to_string() } else { sample.profile.clone() };
        if !profiles.contains(&profile) {
            profiles.push(profile);
        }
    }
    if profiles.is_empty() {
        profiles.push(String::new());
    }
    for profile in &profiles {
        let mine: Vec<&Sample> = samples
            .iter()
            .filter(|s| {
                let p = if s.profile.is_empty() { "标准" } else { s.profile.as_str() };
                p == profile.as_str()
            })
            .collect();
        let mut sums = vec![0u64; buckets as usize];
        let mut counts = vec![0u32; buckets as usize];
        let mut grouped: Vec<Vec<&Sample>> = vec![Vec::new(); buckets as usize];
        for sample in &mine {
            let index = ((sample.at_unix - start) / width).clamp(0, buckets - 1) as usize;
            if let Some(ms) = sample.ms {
                sums[index] += ms;
                counts[index] += 1;
            }
            grouped[index].push(sample);
        }
        let bucket_values: Vec<Value> = (0..buckets as usize)
            .map(|index| {
                let stats = Stats::of(&grouped[index]);
                if counts[index] == 0 {
                    // 空桶（含「这一次没读数」的桶）必须是 null：前端靠它断线，
                    // 填 0 会画出一条假的「延迟 0 ms」直线。
                    json!({"AverageLatencyMs": Value::Null, "MeasuredCount": 0,
                           "UnavailableCount": stats.sample_count,
                           "MedianLatencyMs": Value::Null, "P95LatencyMs": Value::Null})
                } else {
                    json!({
                        "AverageLatencyMs": sums[index] / counts[index] as u64,
                        "MeasuredCount": counts[index],
                        "UnavailableCount": stats.sample_count - stats.measured,
                        "MedianLatencyMs": opt_num(stats.median),
                        "P95LatencyMs": stats.p95,
                    })
                }
            })
            .collect();
        let stats = Stats::of(&mine);
        series.push(json!({
            "Binding": {
                "Exit": if line_id.is_empty() { "" } else { line_id },
                "ProfileId": profile,
            },
            "Aggregate": {
                "StartAtUtc": rfc3339(start),
                "EndAtUtc": rfc3339(now_unix),
                "Statistics": stats.to_json(),
                "Buckets": bucket_values,
            }
        }));
    }
    json!({
        "NodeId": line_id,
        "Window": label,
        "Loading": false,
        "Reason": if samples.is_empty() { "NoSamples" } else { "" },
        "Series": series,
    })
}

/// 首页那张统计卡要的 `Lines[].Quality30m`（旧版的形状）。
///
/// 与 `history` 的区别：这里只给**一条线路的一个连接方式**，30 个一分钟桶，
/// 外加逐桶平均/P50/P95 序列与整窗统计。宿主的读取与「引擎在不在跑」无关：
/// 刚断开的人也要能看到过去 30 分钟的读数（旧版同款口径）。
pub fn summary(root: &Path, line_id: &str, profile: &str, now: SystemTime) -> Value {
    let now_unix = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let span = 1_800i64;
    let buckets = 30usize;
    let start = now_unix - span;
    let width = span / buckets as i64;
    let all = load(root, line_id, start, now_unix);
    let samples: Vec<&Sample> = all
        .iter()
        .filter(|s| {
            profile.is_empty() || (if s.profile.is_empty() { "标准" } else { s.profile.as_str() }) == profile
        })
        .collect();

    let mut grouped: Vec<Vec<&Sample>> = vec![Vec::new(); buckets];
    for sample in &samples {
        let index = ((sample.at_unix - start) / width).clamp(0, (buckets - 1) as i64) as usize;
        grouped[index].push(sample);
    }
    let per_bucket: Vec<Stats> = grouped.iter().map(|items| Stats::of(items)).collect();
    let samples_json: Vec<Value> = per_bucket
        .iter()
        .map(|s| match s.average {
            Some(v) => json!(v.round() as u64),
            None => Value::Null,
        })
        .collect();
    let medians: Vec<Value> = per_bucket.iter().map(|s| opt_num(s.median)).collect();
    let p95s: Vec<Value> = per_bucket.iter().map(|s| json!(s.p95)).collect();
    let total = Stats::of(&samples);
    let last = samples.last();

    json!({
        "SampleCount": total.sample_count,
        "MeasuredCount": total.measured,
        "UnavailableCount": total.sample_count - total.measured,
        "TimeoutCount": total.timeouts,
        "ControllerUnavailableCount": total.controller,
        "Samples": samples_json,
        "MedianSamples": medians,
        "P95Samples": p95s,
        "MedianLatencyMs": opt_num(total.median),
        "P95LatencyMs": total.p95,
        "AverageLatencyMs": opt_num(total.average),
        "AtUtc": rfc3339(now_unix),
        "LastAtUtc": last.map(|s| rfc3339(s.at_unix)),
        "LastLatencyMs": last.and_then(|s| s.ms),
        "LastReason": last.map(|s| if s.reason.is_empty() { "Measured".to_string() } else { s.reason.clone() }),
    })
}

/// 最近 `count` 条采样（含失败），按时间升序。用来判「连续 N 次变差」。
pub fn recent(root: &Path, line_id: &str, profile: &str, count: usize, now: SystemTime) -> Vec<Sample> {
    let now_unix = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let all = load(root, line_id, now_unix - 1_800, now_unix);
    let mut picked: Vec<Sample> = all
        .into_iter()
        .filter(|s| {
            profile.is_empty() || (if s.profile.is_empty() { "标准" } else { s.profile.as_str() }) == profile
        })
        .collect();
    let skip = picked.len().saturating_sub(count);
    picked.drain(..skip);
    picked
}

fn rfc3339(unix: i64) -> String {
    let (y, m, d, h) = civil_from_unix(unix);
    let rem = unix.rem_euclid(86_400);
    let (minute, second) = ((rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{minute:02}:{second:02}Z")
}

/// Unix 秒 → 公历年月日时（UTC）。只做本地聚合，不引第三方日历库。
fn civil_from_unix(unix: i64) -> (i64, u32, u32, u32) {
    let days = unix.div_euclid(86_400);
    let hour = (unix.rem_euclid(86_400) / 3600) as u32;
    // Howard Hinnant 的 civil_from_days。
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn tmp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tcrs-perf-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn at(unix: i64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(unix as u64)
    }

    #[test]
    fn samples_land_in_hour_files_and_survive_a_reload() {
        let root = tmp_root("record");
        record(&root, "hk", "标准", 120, at(1_700_000_000));
        record(&root, "hk", "标准", 180, at(1_700_000_030));
        record(&root, "jp", "兼容", 900, at(1_700_000_030));
        let got = load(&root, "hk", 1_699_999_000, 1_700_001_000);
        assert_eq!(got.len(), 2, "只取指定线路：{got:?}");
        assert_eq!(got[0].ms, Some(120));
        let all = load(&root, "", 1_699_999_000, 1_700_001_000);
        assert_eq!(all.len(), 3);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn thirty_minute_window_buckets_by_minute_and_keeps_gaps() {
        let root = tmp_root("hist30");
        let now = 1_700_000_000;
        // 第 0 分钟、第 10 分钟各一条；其余分钟留空。
        record(&root, "hk", "标准", 100, at(now - 1_790));
        record(&root, "hk", "标准", 300, at(now - 1_190));
        let h = history(&root, "hk", "ThirtyMinutes", at(now));
        assert_eq!(h["Window"], "ThirtyMinutes");
        assert_eq!(h["Series"][0]["Aggregate"]["Buckets"].as_array().unwrap().len(), 30);
        let stats = &h["Series"][0]["Aggregate"]["Statistics"];
        assert_eq!(stats["MeasuredCount"], 2);
        assert_eq!(stats["AverageLatencyMs"], 200);
        let buckets = h["Series"][0]["Aggregate"]["Buckets"].as_array().unwrap();
        assert_eq!(buckets[0]["AverageLatencyMs"], 100);
        assert!(buckets[1]["AverageLatencyMs"].is_null(), "空桶必须是 null，不能填 0");
        assert_eq!(buckets[1]["MeasuredCount"], 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_store_says_so_instead_of_pretending() {
        let root = tmp_root("empty");
        let h = history(&root, "hk", "Day", at(1_700_000_000));
        assert_eq!(h["Reason"], "NoSamples");
        assert_eq!(h["Series"][0]["Aggregate"]["Statistics"]["MeasuredCount"], 0);
        assert!(h["Series"][0]["Aggregate"]["Statistics"]["AverageLatencyMs"].is_null());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn day_window_reads_across_hour_files() {
        let root = tmp_root("histday");
        let now = 1_700_000_000;
        record(&root, "hk", "标准", 500, at(now - 20 * 3600));
        record(&root, "hk", "标准", 700, at(now - 3600));
        let h = history(&root, "hk", "Day", at(now));
        assert_eq!(h["Series"][0]["Aggregate"]["Statistics"]["MeasuredCount"], 2);
        assert_eq!(h["Series"][0]["Aggregate"]["Buckets"].as_array().unwrap().len(), 24);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rfc3339_matches_the_unix_time() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn summary_carries_bucket_series_and_honest_counts() {
        let root = tmp_root("summary");
        let now = 1_700_000_000;
        record(&root, "hk", "标准", 100, at(now - 1_790));
        record(&root, "hk", "标准", 300, at(now - 1_190));
        record_failure(&root, "hk", "标准", "MeasurementTimeout", at(now - 60));
        let s = summary(&root, "hk", "标准", at(now));
        // 两个成功 + 一次失败：Samples 里只有一个点（失败不画），但统计要算三次尝试。
        assert_eq!(s["MeasuredCount"], 2);
        assert_eq!(s["SampleCount"], 3);
        assert_eq!(s["UnavailableCount"], 1);
        assert_eq!(s["TimeoutCount"], 1);
        assert_eq!(s["Samples"].as_array().unwrap().len(), 30);
        assert_eq!(s["Samples"][0], 100);
        assert!(s["Samples"][29].is_null(), "失败的那个桶不能填 0：{s}");
        assert_eq!(s["LastReason"], "MeasurementTimeout");
        assert!(s["LastLatencyMs"].is_null());
        assert_eq!(s["MedianLatencyMs"], 200);
        assert_eq!(s["P95LatencyMs"], 300);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn summary_filters_by_profile_so_udp_and_tcp_do_not_mix() {
        let root = tmp_root("profile");
        let now = 1_700_000_000;
        record(&root, "hk", "标准", 90, at(now - 100));
        record(&root, "hk", "兼容", 800, at(now - 100));
        let udp = summary(&root, "hk", "标准", at(now));
        let tcp = summary(&root, "hk", "兼容", at(now));
        assert_eq!(udp["MedianLatencyMs"], 90);
        assert_eq!(tcp["MedianLatencyMs"], 800);
        // 质量分档照旧版：>=500 较差、>200 一般。
        assert_eq!(tcp["LastLatencyMs"], 800);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recent_returns_the_tail_in_order() {
        let root = tmp_root("recent");
        let now = 1_700_000_000;
        for (i, ms) in [100u64, 200, 600].iter().enumerate() {
            record(&root, "hk", "标准", *ms, at(now - 300 + i as i64 * 30));
        }
        let tail = recent(&root, "hk", "标准", 2, at(now));
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].ms, Some(200));
        assert_eq!(tail[1].ms, Some(600));
        assert_eq!(tail[1].quality(), "Poor");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn failure_samples_do_not_fake_a_point_on_the_curve() {
        let root = tmp_root("failure-curve");
        let now = 1_700_000_000;
        record_failure(&root, "hk", "标准", "MeasurementTimeout", at(now - 500));
        let h = history(&root, "hk", "ThirtyMinutes", at(now));
        let buckets = h["Series"][0]["Aggregate"]["Buckets"].as_array().unwrap();
        assert!(buckets.iter().all(|b| b["AverageLatencyMs"].is_null()));
        assert_eq!(h["Series"][0]["Aggregate"]["Statistics"]["UnavailableCount"], 1);
        let _ = std::fs::remove_dir_all(&root);
    }
}
