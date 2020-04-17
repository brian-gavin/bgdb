use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use libc::{c_long, c_void, user_regs_struct, PTRACE_PEEKTEXT};
use rustyline::{error::ReadlineError, Editor};
use std::{
    io::{self, prelude::*},
    ptr,
};

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
mod wrappers;

use arch::*;
use tracee::Tracee;
use wrappers::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WaitStatus(i32);

pub fn run(mut tracee: Tracee) {
    let mut rl = Editor::<()>::new();
    dbg!(BITNESS);
    let mut wait_status = None;
    waitpid(tracee.pid(), 0).expect("waitpid failed");
    loop {
        if let Some(WaitStatus(status)) = wait_status {
            if WIFEXITED(status) {
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
            Err(ReadlineError::Eof) => break,
            Err(err) => panic!(err),
        }
    }
}

pub(crate) fn instr_at(pid: u32, addr: usize) -> c_long {
    dbg!(pid, addr);
    ptrace(PTRACE_PEEKTEXT, pid, addr as *mut c_void, ptr::null_mut())
        .expect("ptrace(PEEKTEXT) failed")
}

pub(crate) fn as_mut_ptr_cvoid<T>(r: &mut T) -> *mut c_void {
    r as *mut _ as *mut c_void
}

fn cur_instr(pid: u32, regs: &user_regs_struct) -> c_long {
    instr_at(pid, regs.rip as usize)
}

fn decode_cur_instr(pid: u32, regs: &user_regs_struct) -> String {
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

fn decode_and_print_cur_instr(pid: u32, regs: &user_regs_struct) {
    dbg!(regs.rip);
    let output = decode_cur_instr(pid, regs);
    let instr = cur_instr(pid, regs);
    println!("{:#016x}:    {:#016x}.    {}", regs.rip, instr, output);
    io::stdout().flush().expect("Error flushing stdout");
}
