use crate::Tracee;

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
        split
            .get(1)
            .ok_or(String::from("'break' command needs address"))?
            .parse::<usize>()
            .map(|n| Command::BreakAddr(n))
            .map_err(|_| String::from("Could not parse int from address."))
    } else if cmd_str == "next" {
        Ok(Command::Next)
    } else if cmd_str == "cont" {
        Ok(Command::Cont)
    } else {
        Err(format!("Invalid command: '{}'", cmd_str))
    }
}

pub fn eval_command(tracee: &mut Tracee, cmd: Command) {
    use Command::*;
    dbg!(cmd);
    match cmd {
        Noop => (),
        Next => tracee.single_step(),
        Cont => tracee.cont(),
        BreakAddr(addr) => {
            tracee.insert_breakpoint(addr);
        }
    }
}
