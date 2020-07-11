use crate::{arch::*, instr_at};
use libc::user_regs_struct;
use nix::{sys::ptrace, unistd::Pid};
use std::{collections::HashMap, io, os::unix::process::CommandExt, process};

pub const INT3: usize = 0xcc;

pub struct Breakpoint {
    pub original_data: usize,
    pub number: usize,
}

pub struct Tracee {
    _program_name: String,
    child: process::Child,
    regs_cache: Option<user_regs_struct>,
    breakpoints: HashMap<usize, Breakpoint>,
}

impl Tracee {
    pub fn new(program_name: &str) -> io::Result<Self> {
        let tracee = Tracee {
            _program_name: program_name.to_string(),
            child: start_child(program_name)?,
            regs_cache: None,
            breakpoints: HashMap::new(),
        };
        Ok(tracee)
    }

    pub fn pid(&self) -> Pid {
        Pid::from_raw(self.child.id() as _)
    }

    pub fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
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
        ptrace::step(self.pid(), None).expect("ptrace(SINGLE_STEP) failed.");
        // invalidate the regs cache since `rip` was advanced
        self.regs_cache = None;
    }

    pub fn cont(&mut self) {
        ptrace::cont(self.pid(), None).expect("ptrace(CONT) failed.");
        self.regs_cache = None;
    }

    pub fn insert_breakpoint(&mut self, addr: usize) {
        // insert the int3 instsruction at the addr
        let original_data = instr_at(self.pid(), addr) as usize;
        let int3_data = (original_data & LSB_MASK) | INT3;

        self.breakpoints.insert(
            addr,
            Breakpoint {
                original_data,
                number: self.breakpoints.len() + 1,
            },
        );

        ptrace::write(self.pid(), addr as _, int3_data as _).expect("ptrace(POKETEXT) failed.");
    }

    pub fn restore_breakpoint(&mut self) {
        // restore pre-breakpoint state
        self.regs_mut().rip -= 1;
        let addr = self.regs().rip;
        let breakpoint = self.breakpoints.get(&(addr as usize)).expect(&format!(
            "restoring breakpoint of non-breakpoint addr {:x}",
            addr
        ));
        ptrace::write(self.pid(), addr as _, breakpoint.original_data as _)
            .expect("ptrace(POKETEXT) failed.");
        ptrace::setregs(self.pid(), self.regs().clone()).expect("ptrace(SETREGS) failed.");
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
        let regs = ptrace::getregs(self.pid()).expect("ptrace(GETREGS) failed.");
        dbg!(regs.rip);
        self.regs_cache = Some(regs);
    }
}

fn start_child(program_name: &str) -> io::Result<process::Child> {
    let mut child = process::Command::new(program_name);
    let pre_exec = || {
        ptrace::traceme().expect("ptrace(TRACEME) failed.");
        Ok(())
    };
    unsafe {
        child.pre_exec(pre_exec);
    }
    child.spawn()
}
