use std::env;
use std::io::Write;
use std::net::TcpStream;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

fn notify_ready(port: u16) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    writeln!(stream, "ready:{}", process::id()).unwrap();
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn stackpulse_rust_leaf() {
    let mut value = 1_u64;
    while !STOP.load(Ordering::Relaxed) {
        value = value.wrapping_mul(33).wrapping_add(17);
        std::hint::black_box(value);
    }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn stackpulse_rust_middle() {
    stackpulse_rust_leaf();
    std::hint::black_box(());
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn stackpulse_rust_entry() {
    stackpulse_rust_middle();
    std::hint::black_box(());
}

fn main() {
    let port = env::args().nth(1).unwrap().parse().unwrap();
    notify_ready(port);
    stackpulse_rust_entry();
}
