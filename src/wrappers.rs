use std::{
    convert::TryInto,
    ffi::{CStr, CString},
    io, mem,
};

pub fn default_user_regs_struct() -> libc::user_regs_struct {
    unsafe { mem::zeroed() }
}

#[allow(dead_code)]
pub fn perror(s: &str) {
    let s = CString::new(s).unwrap().as_c_str().as_ptr();
    unsafe {
        libc::perror(s);
    }
}

#[allow(non_snake_case, dead_code)]
pub fn WIFSTOPPED(status: libc::c_int) -> bool {
    unsafe { libc::WIFSTOPPED(status) }
}

#[allow(non_snake_case)]
pub fn WIFEXITED(status: libc::c_int) -> bool {
    unsafe { libc::WIFEXITED(status) }
}

#[allow(non_snake_case, dead_code)]
pub fn WSTOPSIG(status: libc::c_int) -> libc::c_int {
    unsafe { libc::WSTOPSIG(status) }
}

#[allow(dead_code)]
pub fn strsignal(signal: libc::c_int) -> &'static str {
    dbg!(signal);
    let cstr = unsafe { CStr::from_ptr(libc::strsignal(signal)) };
    cstr.to_str().expect("strsignal returned an invalid str")
}

pub fn waitpid(pid: u32, options: libc::c_int) -> io::Result<libc::c_int> {
    let pid: libc::pid_t = pid.try_into().unwrap();
    let mut status: libc::c_int = 0;
    let rv = {
        let status_ptr: *mut libc::c_int = &mut status;
        unsafe { libc::waitpid(pid, status_ptr, options) }
    };
    if rv < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(status)
    }
}

pub fn ptrace(
    request: libc::c_uint,
    child_pid: u32,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> io::Result<libc::c_long> {
    let child_pid: libc::c_int = child_pid
        .try_into()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let rv = unsafe { libc::ptrace(request, child_pid, addr, data) };
    if rv == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rv)
    }
}
