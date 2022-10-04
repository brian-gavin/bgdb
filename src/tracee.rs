use crate::arch::*;
use gimli::{DW_AT_high_pc, DW_AT_low_pc, DebuggingInformationEntry, Dwarf};
use libc::user_regs_struct;
use memmap2::Mmap;
use nix::{sys::ptrace, unistd::Pid};
use object::Object;
use std::{
    borrow::Cow,
    cell::{Ref, RefCell, RefMut},
    collections::HashMap,
    error::Error,
    fs::File,
    io,
    os::unix::process::CommandExt,
    process,
    rc::Rc,
};

pub const INT3: usize = 0xcc;

struct Breakpoint {
    original_data: usize,
}

type DwarfReader = gimli::EndianRcSlice<gimli::RunTimeEndian>;

struct DwarfWrapper {
    dwarf: gimli::Dwarf<DwarfReader>,
}

pub struct Tracee {
    dwarf: DwarfWrapper,
    child: process::Child,
    regs_cache: RefCell<Option<user_regs_struct>>,
    breakpoints: HashMap<usize, Breakpoint>,
}

fn read_object_file(program_name: &str) -> Result<DwarfWrapper, Box<dyn Error>> {
    let f = File::open(program_name)?;
    let mmap = unsafe { Mmap::map(&f)? };
    let obj = object::File::parse(&*mmap)?;
    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    fn load_section<'data: 'file, 'file, O, Endian>(
        id: gimli::SectionId,
        file: &'file O,
        endian: Endian,
    ) -> Result<gimli::EndianRcSlice<Endian>, gimli::Error>
    where
        O: object::Object<'data, 'file>,
        Endian: gimli::Endianity,
    {
        use object::ObjectSection;

        let data = file
            .section_by_name(id.name())
            .and_then(|section| section.uncompressed_data().ok())
            .unwrap_or(Cow::Borrowed(&[]));
        Ok(gimli::EndianRcSlice::new(Rc::from(&*data), endian))
    }
    let dwarf = gimli::Dwarf::load(|id| load_section(id, &obj, endian))?;
    Ok(DwarfWrapper { dwarf })
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

fn by_pc(pc: u64) -> impl Fn(&DebuggingInformationEntry<DwarfReader>) -> gimli::Result<bool> {
    move |entry| {
        let low_pc = entry
            .attr(DW_AT_low_pc)?
            .and_then(|a| a.udata_value())
            .unwrap_or_default();
        let high_pc = entry
            .attr(DW_AT_high_pc)?
            .and_then(|a| a.udata_value())
            .unwrap_or_default();
        Ok(low_pc <= pc && pc <= high_pc)
    }
}

impl DwarfWrapper {
    fn find_die_by_pc_and_parse<FParse, T>(
        &self,
        pc: u64,
        parse: FParse,
    ) -> gimli::Result<Option<T>>
    where
        FParse: Fn(&DebuggingInformationEntry<DwarfReader>) -> gimli::Result<T>,
    {
        self.find_die_and_parse(by_pc(pc), parse)
    }

    fn find_die_and_parse<FBy, FParse, T>(&self, by: FBy, parse: FParse) -> gimli::Result<Option<T>>
    where
        FBy: Fn(&DebuggingInformationEntry<DwarfReader>) -> gimli::Result<bool>,
        FParse: Fn(&DebuggingInformationEntry<DwarfReader>) -> gimli::Result<T>,
    {
        let mut it = self.dwarf.units();
        while let Some(header) = it.next()? {
            let unit = self.dwarf.unit(header)?;
            let mut it = unit.entries();
            while let Some(entry) = it.next_sibling()? {
                if by(entry)? {
                    return Ok(Some(parse(entry)?));
                }
            }
        }
        Ok(None)
    }
}

impl Tracee {
    pub fn start(program_name: &str) -> Result<Self, Box<dyn Error>> {
        let tracee = Tracee {
            dwarf: read_object_file(program_name)?,
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
