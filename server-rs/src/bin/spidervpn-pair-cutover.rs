//! Standalone, opt-in Linux root read-only legacy Python service preflight.
//! NEVER a migration/import authorization; NO old service or WG mutation.
#![cfg(target_os="linux")]

fn main(){
    let result=std::env::args_os().skip(1).collect::<Vec<_>>();
    if !result.is_empty(){
        eprintln!("spidervpn-pair-cutover: no arguments accepted; preflight denied");
        std::process::exit(2);
    }
    match spidervpn_pairing_authority::legacy_cutover::observe_old_python_shutdown(){
        Ok(report) => {
            assert!(!report.authorizes_legacy_import());
            assert!(!report.authorizes_new_pairing_listener());
            println!("Observed tc-pair.service persistently masked and inactive, \
                and no tc-pair.py process in two /proc snapshots. \
                PRE-FLIGHT ONLY. NO authorization to migrate, bind a new listener, \
                or modify WireGuard; uncooperative writers are not ruled out.");
        }
        Err(_) => {
            eprintln!("spidervpn-pair-cutover: old Python shutdown not independently verified; \
                NO migration or listener authorization");
            std::process::exit(2);
        }
    }
}
