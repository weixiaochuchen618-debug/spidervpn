//! Harmless standalone G2 fixture. CI builds this source with rustc as an
//! EXE, not as a product command. No networking, service, proxy or WFP APIs.
fn version_line() -> &'static str { "sing-box G2 isolated fixture" }

#[cfg(not(test))]
fn main() {
    use std::io::Write;
    let mode = std::env::args().nth(1).expect("fixture mode");
    assert!(matches!(mode.as_str(), "version" | "hold"));
    let marker = std::env::var_os("SPIDERVPN_G2_FIXTURE_MARKER").expect("explicit disposable marker");
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(marker).unwrap();
    writeln!(f, "{}", std::process::id()).unwrap();
    f.sync_all().unwrap();
    drop(f);
    if mode == "version" { println!("{}", version_line()); }
    else { std::thread::sleep(std::time::Duration::from_secs(60)); }
}

#[test]
fn standalone_fixture_reply_is_not_a_production_engine() {
    assert_eq!(version_line(), "sing-box G2 isolated fixture");
}
