use crate::Tracee;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};

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
            let status = waitpid(tracee.pid(), None).expect("waitpid failed");
            Some(status)
        }
        Cont => {
            tracee.cont();
            let status = waitpid(tracee.pid(), None).expect("waitpid failed");
            if let WaitStatus::Stopped(_, Signal::SIGTRAP) = status {
                println!("Stopped at a breakpoint!");
                tracee.restore_breakpoint();
            }
            Some(status)
        }
        BreakAddr(addr) => {
            tracee.insert_breakpoint(addr);
            None
        }
    }
}
