use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use nix::sys::wait::{waitpid, WaitStatus};
use rustyline::{error::ReadlineError, Editor};
use std::io::{self, prelude::*};

#[cfg(target_arch = "x86_64")]
mod arch {
    pub const LSB_MASK: usize = 0xffff_ffff_ffff_ff00;
    pub const BITNESS: u32 = 64;
}

#[cfg(target_arch = "x86")]
mod arch {
    pub const LSB_MASK: usize = 0xffff_ff00;
    pub const BITNESS: u32 = 32;
}

mod repl;
pub mod tracee;

use arch::*;
use tracee::Tracee;

pub fn run(mut tracee: Tracee) {
    println!("PID: {}", tracee.pid());
    let mut rl = Editor::<()>::new().unwrap();
    dbg!(BITNESS);
    let mut wait_status = None;
    waitpid(tracee.pid(), None).expect("waitpid failed");
    loop {
        if let Some(status) = wait_status {
            if let WaitStatus::Exited(_, _) = status {
                println!("Child process exited.");
                break;
            }
        }
        let cur_instr = tracee.instr_at(tracee.regs().rip as _);
        decode_and_print_instr(tracee.regs().rip, cur_instr);
        let readline = rl.readline("bgdb> ");
        match readline {
            Ok(line) => match repl::parse_command(&line) {
                Ok(cmd) => {
                    wait_status = repl::eval_command(&mut tracee, cmd);
                }
                Err(e) => {
                    eprintln!("{}", e);
                    wait_status = None;
                    continue;
                }
            },
            Err(ReadlineError::Eof) => {
                tracee.kill().expect("Could not kill child");
                break;
            }
            Err(err) => panic!("{}", err),
        }
    }
}

fn decode_instr(rip: u64, instr: usize) -> String {
    let mut output = String::new();
    let instr = instr.to_le_bytes(); // Decoder borrows the slice for its lifetime
    let mut decoder = Decoder::new(BITNESS, &instr, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut decoded_instr = Instruction::new();

    decoder.set_ip(rip);
    decoder.decode_out(&mut decoded_instr);
    formatter.format(&decoded_instr, &mut output);

    output
}

fn decode_and_print_instr(rip: u64, instr: usize) {
    let output = decode_instr(rip, instr);
    println!("{:#016x}:    {:#016x}.    {}", rip, instr, output);
    io::stdout().flush().expect("Error flushing stdout");
}
