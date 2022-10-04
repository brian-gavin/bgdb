use crate::Tracee;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};

#[derive(Debug, Clone)]
pub enum Command {
    Noop,
    Next,
    Cont,
    BreakAddr(usize),
    BreakFunction(String),
    BreakLine(String, usize),
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
            .ok_or(String::from("'break' command needs argument"))?;
        if let Some(fn_name) = arg.strip_prefix("fn:") {
            Ok(Command::BreakFunction(fn_name.to_string()))
        } else if let Some((file, lno)) = arg.split_once(":") {
            usize::from_str_radix(lno, 10)
                .map(|lno| Command::BreakLine(file.to_string(), lno))
                .map_err(|e| format!("{}", e))
        } else {
            usize::from_str_radix(&arg, 16)
                .map(|n| Command::BreakAddr(n))
                .map_err(|e| format!("{}", e))
        }
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
    dbg!(&cmd);
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
        BreakFunction(fn_name) => {
            tracee
                .insert_breakpoint_function(&fn_name)
                .expect("dwarf error");
            None
        }
        BreakLine(_, _) => todo!(),
    }
}
