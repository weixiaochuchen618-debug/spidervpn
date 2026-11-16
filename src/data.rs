//! 数据目录布局。
//!
//! 只做一件事：把本程序要用的目录建出来，并在首次运行时写一份身份文件。
//! 与旧版的数据根（ProgramData 下那个目录）没有任何交集，路径来自 `isolation`。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub struct Layout {
    pub root: PathBuf,
    pub logs: PathBuf,
    pub perf: PathBuf,
    pub webview: PathBuf,
}

/// 建目录是幂等的；身份文件只在不存在时写，绝不覆盖已有内容
/// （否则每次启动都会改写一份「首次运行时间」，那是自欺）。
pub fn ensure_layout(root: &Path) -> io::Result<Layout> {
    let logs = root.join("logs");
    let perf = root.join("perf");
    let webview = root.join("WebView2");
    for d in [root.to_path_buf(), logs.clone(), perf.clone(), webview.clone()] {
        fs::create_dir_all(&d)?;
    }

    let identity = root.join("identity.json");
    if !identity.exists() {
        // 手写 JSON：这里只有 4 个固定字段，引 serde 不划算。
        let body = format!(
            "{{\n  \"product\": \"{}\",\n  \"data_root\": \"{}\",\n  \"schema\": 1,\n  \"created_by\": \"rust-rewrite\"\n}}\n",
            crate::isolation::Rewrite::PRODUCT_NAME,
            root.display().to_string().replace('\\', "\\\\")
        );
        fs::write(&identity, body)?;
    }

    Ok(Layout { root: root.to_path_buf(), logs, perf, webview })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tcrs-test-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn creates_all_subdirs() {
        let root = tmp("layout");
        let l = ensure_layout(&root).expect("应当建目录成功");
        assert!(l.root.is_dir());
        assert!(l.logs.is_dir());
        assert!(l.perf.is_dir());
        assert!(l.webview.is_dir());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn identity_is_not_overwritten() {
        let root = tmp("identity");
        ensure_layout(&root).unwrap();
        let f = root.join("identity.json");
        fs::write(&f, "{\"product\":\"marker\"}").unwrap();
        // 第二次初始化不能把已存在的身份文件改掉
        ensure_layout(&root).unwrap();
        let after = fs::read_to_string(&f).unwrap();
        assert!(after.contains("marker"), "身份文件被覆盖了：{}", after);
        let _ = fs::remove_dir_all(&root);
    }
}
