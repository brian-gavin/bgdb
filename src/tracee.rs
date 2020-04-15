use crate::{arch::*, as_mut_ptr_cvoid, instr_at, wrappers::*};
use libc::{
    c_void, user_regs_struct, PTRACE_CONT, PTRACE_GETREGS, PTRACE_POKETEXT, PTRACE_SETREGS,
    PTRACE_SINGLESTEP, PTRACE_TRACEME,
};
use std::{io, os::unix::process::CommandExt, process, ptr};

pub const INT3: usize = 0xcc;

pub struct Tracee {
    _program_name: String,
    child: process::Child,
    regs_cache: Option<user_regs_struct>,
}

impl Tracee {
    pub fn new(program_name: &str) -> io::Result<Self> {
        let tracee = Tracee {
            _program_name: program_name.to_string(),
            child: start_child(program_name)?,
            regs_cache: None,
        };
        Ok(tracee)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn regs(&mut self) -> &user_regs_struct {
        if let Some(ref regs) = self.regs_cache {
            regs
        } else {
            self.populate_regs();
            self.regs_cache.as_ref().unwrap()
        }
    }

    pub fn single_step(&mut self) {
        ptrace(
            PTRACE_SINGLESTEP,
            self.pid(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
        .expect("ptrace(SINGLE_STEP) failed.");
        // invalidate the regs cache since `rip` was advanced
        self.regs_cache = None;
    }

    pub fn cont(&mut self) {
        ptrace(PTRACE_CONT, self.pid(), ptr::null_mut(), ptr::null_mut())
            .expect("ptrace(CONT) failed.");
        self.regs_cache = None;
    }

    pub fn insert_breakpoint(&mut self, addr: usize) {
        // insert the int3 instsruction at the addr
        let orig_data = instr_at(self.pid(), addr) as usize;
        let int3_data = (orig_data & LSB_MASK) | INT3;

        ptrace(
            PTRACE_POKETEXT,
            self.pid(),
            addr as *mut c_void,
            int3_data as *mut c_void,
        )
        .expect("ptrace(POKETEXT) failed.");

        // continue and stop at the breakpoint
        self.cont();
        let _status = waitpid(self.pid(), 0).expect("waitpid failed.");

        // restore pre-breakpoint state
        self.regs_mut().rip -= 1;
        ptrace(
            PTRACE_POKETEXT,
            self.pid(),
            addr as *mut c_void,
            orig_data as *mut c_void,
        )
        .expect("ptrace(POKETEXT) failed.");
        ptrace(
            PTRACE_SETREGS,
            self.pid(),
            ptr::null_mut(),
            as_mut_ptr_cvoid(self.regs_mut()),
        )
        .expect("ptrace(SETREGS) failed.");
    }

    /// for internal modification of the registers directly and usage in `PTRACE_SETREGS` calls,
    /// where a normally immutable reference to the regs needs to be cast to `*mut c_void`.
    fn regs_mut(&mut self) -> &mut user_regs_struct {
        if let Some(ref mut regs) = self.regs_cache {
            regs
        } else {
            self.populate_regs();
            self.regs_cache.as_mut().unwrap()
        }
    }

    fn populate_regs(&mut self) {
        let mut regs = default_user_regs_struct();
        ptrace(
            PTRACE_GETREGS,
            self.child.id(),
            ptr::null_mut(),
            as_mut_ptr_cvoid(&mut regs),
        )
        .expect("ptrace(GETREGS) failed.");
        dbg!(regs.rip);
        self.regs_cache = Some(regs);
    }
}

fn start_child(program_name: &str) -> io::Result<process::Child> {
    let mut child = process::Command::new(program_name);
    let pre_exec = || {
        ptrace(PTRACE_TRACEME, 0, ptr::null_mut(), ptr::null_mut())?;
        Ok(())
    };
    unsafe {
        child.pre_exec(pre_exec);
    }
    child.spawn()
}
