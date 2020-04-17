use crate::{
    wrappers::{waitpid, WIFSTOPPED, WSTOPSIG},
    Tracee, WaitStatus,
};
use libc::SIGTRAP;

#[derive(Debug, Copy, Clone)]
pub enum Command {
    Noop,
    Next,
    Cont,
    BreakAddr(usize),
}

pub fn parse_command(line: &str) -> Result<Command, String> {
    let split: Vec<_> = line.split(' ').collect();
    if split.is_empty() {
        return Ok(Command::Noop);
    }
    let cmd_str = split[0];
    if cmd_str == "break" {
        let arg = split
            .get(1)
            .ok_or(String::from("'break' command needs address"))?;
        usize::from_str_radix(&arg, 16)
            .map(|n| Command::BreakAddr(n))
            .map_err(|e| format!("{}", e))
    } else if cmd_str == "next" {
        Ok(Command::Next)
    } else if cmd_str == "cont" {
        Ok(Command::Cont)
    } else {
        Err(format!("Invalid command: '{}'", cmd_str))
    }
}

pub fn eval_command(tracee: &mut Tracee, cmd: Command) -> Option<WaitStatus> {
    use Command::*;
    dbg!(cmd);
    match cmd {
        Noop => None,
        Next => {
            tracee.single_step();
            let status = waitpid(tracee.pid(), 0).expect("waitpid failed");
            Some(WaitStatus(status))
        }
        Cont => {
            tracee.cont();
            let status = waitpid(tracee.pid(), 0).expect("waitpid failed");
            if WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP {
                println!("Stopped at a breakpoint!");
                tracee.restore_breakpoint();
            }
            Some(WaitStatus(status))
        }
        BreakAddr(addr) => {
            tracee.insert_breakpoint(addr);
            None
        }
    }
}
