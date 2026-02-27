use sae::{args::{Cfg, parse_args}, lib::{lock_command, open_command, print_help, save_command}};

fn main() -> Result<(), String> {
    let cfg = match parse_args() {
        Ok(x) => {x}
        Err(e) => {return Err(e.to_string());}
    };
    match cfg {
        Cfg::Lock(src, dst, opts) => {if let Err(e) = lock_command(src, dst, opts) {return Err(e.to_string());}}
        Cfg::Open(src, dst, opts) => {if let Err(e) = open_command(src, dst, opts) {return Err(e.to_string());}}
        Cfg::Save => {if let Err(e) = save_command() {return Err(e.to_string());}}
        Cfg::Help => {print_help();}
    }
    Ok(())
}