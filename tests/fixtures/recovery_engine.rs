// Deliberately harmless compiled engine fixture, NOT sing-box vendor code.
use std::io::{Read,Write};
fn main(){
    let exe=std::env::current_exe().unwrap();
    println!("D3_ENGINE_OK pid={} fixture=0x454e4733 exe={}",std::process::id(),exe.display());
    std::io::stdout().flush().unwrap();
    if std::env::args().nth(1).as_deref()==Some("--wait-fixture"){
        println!("D3_ENGINE_WAIT_READY pid={}",std::process::id());
        std::io::stdout().flush().unwrap();
        let mut b=[0u8;1];let _=std::io::stdin().read(&mut b).unwrap();
    }
}
