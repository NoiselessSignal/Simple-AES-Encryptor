use std::{env::{self, consts::OS}, process::exit};
use sae::lib::{parse, run};

fn main() {

    if OS != "linux" {eprintln!("Error: Unsupported OS."); exit(1)}
    
    let mut args = env::args();
    args.next();
    
    let cfg = parse(args);
    run(cfg);
}