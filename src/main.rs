use bgdb::{run, tracee::Tracee};
use std::env;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        panic!("Expected 2 args for debug target");
    }
    run(Tracee::start(&args[1]).unwrap());
}
