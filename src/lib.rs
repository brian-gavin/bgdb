use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use libc::{c_long, user_regs_struct};
use nix::{
    sys::{
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
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
    let mut rl = Editor::<()>::new();
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
        decode_and_print_cur_instr(tracee.pid(), tracee.regs());
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
            Err(err) => panic!(err),
        }
    }
}

pub(crate) fn instr_at(pid: Pid, addr: usize) -> c_long {
    dbg!(pid, addr);
    ptrace::read(pid, addr as _).expect("ptrace(PEEKTEXT) failed")
}

fn cur_instr(pid: Pid, regs: &user_regs_struct) -> c_long {
    instr_at(pid, regs.rip as usize)
}

fn decode_cur_instr(pid: Pid, regs: &user_regs_struct) -> String {
    let mut output = String::new();
    let instr = cur_instr(pid, regs);
    let instr_bytes = instr.to_le_bytes();
    let mut decoder = Decoder::new(BITNESS, &instr_bytes, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut decoded_instr = Instruction::new();

    decoder.set_ip(regs.rip);
    decoder.decode_out(&mut decoded_instr);
    formatter.format(&decoded_instr, &mut output);

    output
}

fn decode_and_print_cur_instr(pid: Pid, regs: &user_regs_struct) {
    dbg!(regs.rip);
    let output = decode_cur_instr(pid, regs);
    let instr = cur_instr(pid, regs);
    println!("{:#016x}:    {:#016x}.    {}", regs.rip, instr, output);
    io::stdout().flush().expect("Error flushing stdout");
}
