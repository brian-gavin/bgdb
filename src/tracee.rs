use crate::arch::*;
use libc::user_regs_struct;
use nix::{sys::ptrace, unistd::Pid};
use std::{
    cell::{Ref, RefCell, RefMut},
    collections::HashMap,
    io,
    os::unix::process::CommandExt,
    process,
};

pub const INT3: usize = 0xcc;

struct Breakpoint {
    original_data: usize,
}

pub struct Tracee {
    _program_name: String,
    child: process::Child,
    regs_cache: RefCell<Option<user_regs_struct>>,
    breakpoints: HashMap<usize, Breakpoint>,
}

impl Tracee {
    pub fn new(program_name: &str) -> io::Result<Self> {
        let tracee = Tracee {
            _program_name: program_name.to_string(),
            child: start_child(program_name)?,
            regs_cache: RefCell::new(None),
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

    pub fn regs(&self) -> Ref<'_, user_regs_struct> {
        let _ = self
            .regs_cache
            .borrow_mut()
            .get_or_insert_with(|| self.getregs());
        Ref::map(self.regs_cache.borrow(), |o| o.as_ref().unwrap())
    }

    /// for internal modification of the registers directly
    fn regs_mut(&mut self) -> RefMut<'_, user_regs_struct> {
        RefMut::map(self.regs_cache.borrow_mut(), |o| {
            o.get_or_insert_with(|| self.getregs())
        })
    }

    fn getregs(&self) -> user_regs_struct {
        ptrace::getregs(self.pid()).expect("ptrace(GETREGS) failed.")
    }

    pub fn instr_at(&self, addr: usize) -> usize {
        ptrace::read(self.pid(), addr as _).expect("ptrace(PEEKTEXT) failed") as _
    }

    pub fn single_step(&mut self) {
        ptrace::step(self.pid(), None).expect("ptrace(SINGLE_STEP) failed.");
        // invalidate the regs cache since `rip` was advanced
        self.regs_cache.replace(None);
    }

    pub fn cont(&mut self) {
        ptrace::cont(self.pid(), None).expect("ptrace(CONT) failed.");
        self.regs_cache.replace(None);
    }

    pub fn insert_breakpoint(&mut self, addr: usize) {
        // insert the int3 instsruction at the addr
        let original_data = self.instr_at(addr) as usize;
        let int3_data = (original_data & LSB_MASK) | INT3;

        self.breakpoints.insert(
            addr,
            Breakpoint {
                original_data,
                // number: self.breakpoints.len() + 1,
            },
        );

        unsafe {
            ptrace::write(self.pid(), addr as _, int3_data as _).expect("ptrace(POKETEXT) failed.");
        }
    }

    pub fn restore_breakpoint(&mut self) {
        // restore pre-breakpoint state
        self.regs_mut().rip -= 1;
        let addr = self.regs().rip;
        let breakpoint = self.breakpoints.get(&(addr as usize)).expect(&format!(
            "restoring breakpoint of non-breakpoint addr {:x}",
            addr
        ));
        unsafe {
            ptrace::write(self.pid(), addr as _, breakpoint.original_data as _)
                .expect("ptrace(POKETEXT) failed.");
        }
        ptrace::setregs(self.pid(), self.regs().clone()).expect("ptrace(SETREGS) failed.");
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
