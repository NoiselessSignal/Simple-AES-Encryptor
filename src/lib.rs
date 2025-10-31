pub mod lib {

use std::{env::Args, fs, io::{self, ErrorKind, Write}, os::unix::fs::symlink, path::{Path, PathBuf}, process::exit};
use aes_gcm::{aead::{Aead, OsRng}, AeadCore, Aes256Gcm, Key, KeyInit};
use blake3::Hash;
use serde::{Deserialize, Serialize};
use serde_binary::binary_stream::Endian;
use users::get_current_username;

struct Set(bool);

enum Mode {
    PasswordChange(Set),
    PasswordStatus,
    PasswordVerify,
    EncryptFile,
    EncryptDir,
    Decrypt,
}

pub struct Cfg {
    target: PathBuf,
    mode: Mode,
    show: bool,
    delete: bool,
    quiet: bool,
    cache: bool,
}

pub fn parse(mut args: Args) -> Cfg {

    let mut cfg = Cfg { mode: Mode::EncryptFile, target: PathBuf::new(), show: false, delete: false, quiet: false, cache: false };

    let command = args.next();
    if command.is_none() {eprintln!("Error: Expected command.\nUse 'help' for more info."); exit(1)}

    fn parse_opt(args: &mut Args, cfg: &mut Cfg, allow_s: bool, allow_q: bool, allow_c: bool, allow_d: bool) {
        for s in args.by_ref() {
            if &s == "-s" || &s == "--show" {
                if !allow_s {eprintln!("Error: Option --show is not available for this command."); exit(1)}
                if cfg.show {eprintln!("Error: Same option found twice: --show"); exit(1)}
                cfg.show = true
            }
            else if &s == "-q" || &s == "--quiet" {
                if !allow_q {eprintln!("Error: Option --quiet is not available for this command."); exit(1)}
                if cfg.quiet {eprintln!("Error: Same option found twice: --quiet"); exit(1)}
                cfg.quiet = true
            }
            else if &s == "-d" || &s == "--delete" {
                if !allow_d {eprintln!("Error: Option --delete is not available for this command."); exit(1)}
                if cfg.delete {eprintln!("Error: Same option found twice: --delete"); exit(1)}
                cfg.delete = true
            }
            else if &s == "-c" || &s == "--cache" {
                if !allow_c {eprintln!("Error: Option --cache is not available for this command."); exit(1)}
                if cfg.cache {eprintln!("Error: Same option found twice: --cache"); exit(1)}
                cfg.cache = true
            }
            else {
                eprintln!("Error: Unrecognized option.\nUse 'help' for more info."); exit(1)
            }
        }
    }

    match command.unwrap().as_str() {
        "pwd" => {
            let mut set = true;
            let arg = args.next();
            if arg.is_none() {eprintln!("Error: Expected command.\nUse 'help' for more info."); exit(1)}
            match arg.unwrap().as_str() {
                "set" => {
                    parse_opt(&mut args, &mut cfg, true, true, false, false);
                    cfg.mode = Mode::PasswordChange(Set(set));
                    cfg
                }
                "del" => {
                    parse_opt(&mut args, &mut cfg, false, true, false, false);
                    set = false;
                    cfg.mode = Mode::PasswordChange(Set(set));
                    cfg
                }
                "status" => {
                    if args.next().is_some() {eprintln!("Error: This subcommand takes no options."); exit(1)}
                    cfg.mode = Mode::PasswordStatus;
                    cfg
                }
                "verify" => {
                    parse_opt(&mut args, &mut cfg, true, false, false, false);
                    cfg.mode = Mode::PasswordVerify;
                    cfg
                }
                _ => {eprintln!("Error: Unrecognized command.\nUse 'help' for more info."); exit(1)}
            }
        }
        "enc" => {
            cfg.target = match args.next() {
                Some(s) => {s.into()}
                None => {eprintln!("Error: Expected target.\nUse 'help' for more info."); exit(1)}
            };
            if !cfg.target.exists() {eprintln!("Error: Target not found."); exit(1)}
            else if cfg.target.is_file() {cfg.mode = Mode::EncryptFile}
            else if cfg.target.is_dir() {cfg.mode = Mode::EncryptDir}
            else {eprintln!("Error: Target is invalid."); exit(1)}
            parse_opt(&mut args, &mut cfg, true, true, true, true);
            if cfg.show && cfg.cache {eprintln!("Error: Incompatable options found: --show and --cache"); exit(1)}
            cfg
        }
        "dec" => {
            cfg.target = match args.next() {
                Some(s) => {s.into()}
                None => {eprintln!("Error: Expected target.\nUse 'help' for more info."); exit(1)}
            };
            if !cfg.target.exists() {eprintln!("Error: Target not found."); exit(1)}
            else if cfg.target.is_file() {cfg.mode = Mode::Decrypt}
            else {eprintln!("Error: Target is invalid."); exit(1)}
            parse_opt(&mut args, &mut cfg, true, true, true, true);
            if cfg.show && cfg.cache {eprintln!("Error: Incompatable options found: --show and --cache"); exit(1)}
            cfg
        }
        "help" => {print_help(); exit(0)}
        _ => {eprintln!("Error: Unrecognized command.\nUse 'help' for more info."); exit(1)}
    }
}

fn paths() -> Paths {
    let mut uname = "".to_string();
    if let Some(name) = get_current_username().unwrap().to_str() {uname.push_str(name);}
    else {eprintln!("Error: Username is invalid."); exit(1)}

    let confpath = {
        if uname == "root" {format!("/{uname}/.config")}
        else {format!("/home/{uname}/.config")}
    };
    let cachepath = format!("{}/sae", &confpath);
    let hashpath = format!("{}/hash", &cachepath);
    Paths {
        confpath: confpath.into(),
        cachepath: cachepath.into(),
        hashpath: hashpath.into()
    }
}

fn get_pwd_hash(cfg: &Cfg) -> Hash {
    if !cfg.cache {
        if cfg.show {
            let mut uinput = "".to_string();
            print!("Password: ");
            if io::stdout().flush().is_err() {eprintln!("Error: Failed to clear I/O buffer."); exit(1)}
            if io::stdin().read_line(&mut uinput).is_err() {eprintln!("Error: Failed to read input."); exit(1)}
            let mut uinput_chars: Vec<char> = uinput.chars().collect();
            uinput_chars.pop();
            let pwd: String = uinput_chars.iter().collect();
            blake3::hash(pwd.as_bytes())
        }
        else {
            let pwd = match rpassword::prompt_password("Password: ") {
                Ok(s) => {s}
                Err(_) => {eprintln!("Error: Failed to read input."); exit(1)}
            };
            blake3::hash(pwd.as_bytes())
        }
    }
    else {
        let paths = paths();
        match fs::exists(&paths.hashpath) {
            Ok(exists) => {if !exists {eprintln!("Error: Cache is empty or doesn't exist."); exit(1)}}
            Err(_) => {eprintln!("Error: Failed to check cache."); exit(1)}
        }
        match fs::read(&paths.hashpath) {
            Ok(bytes) => {
                let bytes_array: [u8; 32] = match bytes.try_into() {
                    Ok(x) => {x}
                    Err(_) => {eprintln!("Error: Hash value in cache is invalid length."); exit(1)}
                };
                Hash::from_bytes(bytes_array)
            }
            Err(_) => {eprintln!("Error: Failed to read cache."); exit(1)}
        }
    }
}

pub fn run(cfg: Cfg) {

    match cfg.mode {
        
        Mode::PasswordStatus => {
            let paths = paths();
            if let Ok(exists) = fs::exists(&paths.hashpath) {
                if exists {println!("Cache is full.")}
                else {println!("Cache is empty or doesn't exist.")}
            }
            else {eprintln!("Error: Failed to check cache."); exit(1)}
        }
        Mode::PasswordVerify => {
            let paths = paths();
            match fs::read(&paths.hashpath) {
                Ok(bytes) => {
                    if bytes.len() != 32 {eprintln!("Error: Cached value is incorrect length."); exit(1)}
                    let cached_hash = {
                        let bytes_array: [u8; 32] = match bytes.try_into() {
                            Ok(x) => {x}
                            Err(_) => {eprintln!("Error: Value in cache is invalid length."); exit(1)}
                        };
                        Hash::from_bytes(bytes_array)
                    };
                    let compare_hash = get_pwd_hash(&cfg);
                    if cached_hash == compare_hash {println!("Match!")}
                    else {println!("Different!")}
                }
                Err(e) => {
                    if e.kind() == ErrorKind::NotFound {eprintln!("Error: Cache is empty or doesn't exist."); exit(1)}
                    else {eprintln!("Error: Failed to read cache."); exit(1)}
                }
            }
        }
        Mode::PasswordChange(ref set) => {
            
            let paths = paths();

            if !set.0 {
                if let Err(e) = fs::remove_file(&paths.hashpath) {
                    if e.kind() == ErrorKind::NotFound {eprintln!("Erorr: Cache is empty or doesn't exist."); exit(1)}
                    else {eprintln!("Error: Failed to clear cache."); exit(1)}
                }
                if !cfg.quiet {println!("Cache cleared.")}
                exit(0);
            }

            match fs::create_dir(&paths.confpath) {
                Ok(_) => {if !cfg.quiet {println!("Created {:?}", &paths.confpath)}}
                Err(e) => {
                    if e.kind() != ErrorKind::AlreadyExists {eprintln!("Error: Failed to create {:?}", paths.confpath); exit(1)}
                }
            }
            match fs::create_dir(&paths.cachepath) {
                Ok(_) => {if !cfg.quiet {println!("Created {:?}", &paths.cachepath)}}
                Err(e) => {
                    if e.kind() != ErrorKind::AlreadyExists {eprintln!("Error: Failed to create {:?}", paths.cachepath); exit(1)}
                }
            }
            match fs::exists(&paths.hashpath) {
                Ok(exists) => {
                    if exists {eprintln!("Error: Cache is already full."); exit(1)}
                }
                Err(_) => {eprintln!("Error: Failed to check cache."); exit(1)}
            }

            let pwd_hash = get_pwd_hash(&cfg);
            
            if fs::write(&paths.hashpath, pwd_hash.as_bytes()).is_err() {
                eprintln!("Error: Failed to write to {:?}", &paths.hashpath); exit(1)
            }
            if !cfg.quiet {println!("Cache saved.")}
        }
        Mode::EncryptFile => {

            if !cfg.quiet {println!("Found target: {:?}", &cfg.target)}
            if !cfg.quiet {println!("Reading bytes...")}

            let data = match fs::read(&cfg.target) {
                Ok(b) => {b}
                Err(_) => {
                    if !cfg.quiet {println!("FAIL.")}
                    eprintln!("Error: Failed to read bytes from target."); exit(1)
                }
            };

            if !cfg.quiet {println!("SUCCESS.")}
            
            let newname = format!("{}.enc", &cfg.target.display());
            match fs::exists(&newname) {
                Ok(exists) => {if exists {eprintln!("Error: Objective already exists."); exit(1)}}
                Err(_) => {eprintln!("Error: Failed to check objective's status."); exit(1)}
            }
            let file = File::new(cfg.target.to_owned(), data);
            
            if !cfg.quiet {println!("Converting...")}
            
            let bytes = match serde_binary::to_vec(&Item::F(file), Endian::Big) {
                Ok(b) => {b}
                Err(_) => {
                    if !cfg.quiet {println!("FAIL.")}
                    eprintln!("Error: Failed to convert target data to binary."); exit(1)
                }
            };

            if !cfg.quiet {println!("SUCCESS.")}

            let pwd_hash = get_pwd_hash(&cfg);

            if !cfg.quiet {println!("Encrypting...")}
            
            let enc_bytes = match encrypt(&bytes, pwd_hash) {
                Ok(b) => {b}
                Err(e) => {
                    if !cfg.quiet {println!("FAIL.")}
                    eprintln!("{e}"); exit(1)
                }
            };

            if !cfg.quiet {println!("SUCCESS.")}
            
            if fs::write(newname, enc_bytes).is_err() {
                eprintln!("Error: Failed to write result to disk."); exit(1)
            }
            
            if !cfg.quiet {println!("Wrote result to disk.")}
            
            if cfg.delete {
                if fs::remove_file(&cfg.target).is_err() {eprintln!("Error: Failed to remove target."); exit(1)}
                if !cfg.quiet {println!("Removed target: {:?}", &cfg.target)}
            }
        }
        Mode::EncryptDir => {

            if !cfg.quiet {println!("Found target: {:?}", &cfg.target)}
            if !cfg.quiet {println!("Reading bytes...")}

            let dir = match Dir::read_from(&cfg.target) {
                Ok(d) => {d}
                Err(e) => {
                    if !cfg.quiet {println!("FAIL.")}
                    eprintln!("Error: {e}"); exit(1)
                }
            };

            if !cfg.quiet {println!("SUCCESS.")}
            if !cfg.quiet {println!("Converting...")}

            let bytes = match serde_binary::to_vec(&Item::D(dir), Endian::Big) {
                Ok(b) => {b}
                Err(_) => {
                    if !cfg.quiet {println!("FAIL.")}
                    eprintln!("Error: Failed to convert target data to binary."); exit(1)
                }
            };

            if !cfg.quiet {println!("SUCCESS.")}

            let pwd = get_pwd_hash(&cfg);
            
            if !cfg.quiet {println!("Encrypting...")}

            let enc_bytes = match encrypt(&bytes, pwd) {
                Ok(b) => {b}
                Err(e) => {eprintln!("{e}"); exit(1)}
            };

            if !cfg.quiet {println!("SUCCESS.")}
            
            let newname = format!("{}.enc", &cfg.target.display());
            if fs::write(newname, enc_bytes).is_err() {
                eprintln!("Error: Failed to write result to disk."); exit(1)
            }
            
            if !cfg.quiet {println!("Wrote result to disk.")}            
            
            if cfg.delete {
                if fs::remove_dir_all(&cfg.target).is_err() {eprintln!("Error: Failed to remove target."); exit(1)}
                if !cfg.quiet {println!("Removed target: {:?}", &cfg.target)}
            }
        }
        Mode::Decrypt => {
            
            if !cfg.quiet {println!("Found target: {:?}", &cfg.target)}
            if !cfg.quiet {println!("Reading bytes...")}
            
            let enc_bytes = match fs::read(&cfg.target) {
                Ok(b) => {b}
                Err(_) => {
                    if !cfg.quiet {println!("FAIL.")}
                    eprintln!("Error: Failed to read target."); exit(1)
                }
            };

            if !cfg.quiet {println!("SUCCESS.")}
            let pwd = get_pwd_hash(&cfg);
            if !cfg.quiet {println!("Decrypting...")}

            let bytes = match decrypt(&enc_bytes, pwd) {
                Ok(b) => {b}
                Err(e) => {
                    if !cfg.quiet {println!("FAIL.")}
                    eprintln!("{e}"); exit(1)
                }
            };

            if !cfg.quiet {println!("SUCCESS.")}
            if !cfg.quiet {println!("Converting...")}

            let item: Item = match serde_binary::from_vec(bytes, Endian::Big) {
                Ok(i) => {i}
                Err(_) => {
                    if !cfg.quiet {println!("FAIL.")}
                    eprintln!("Error: Failed to convert from binary."); exit(1)
                }
            };

            if !cfg.quiet {println!("SUCCESS.")}

            match item {
                Item::F(file) => {
                    
                    if !cfg.quiet {println!("Identified data: file.")}
                    
                    match fs::exists(&file.path) {
                        Ok(exists) => {if exists {eprintln!("Error: Objective already exists."); exit(1)}}
                        Err(_) => {eprintln!("Error: Failed to check if objective exists."); exit(1)}
                    }

                    if fs::write(&file.path, &file.data).is_err() {eprintln!("Error: Failed to write result to disk."); exit(1)}
                    if !cfg.quiet {println!("Wrote result to disk.")}
                    
                    if cfg.delete {
                        if fs::remove_file(&cfg.target).is_err() {eprintln!("Error: Failed to remove target."); exit(1)}
                        if !cfg.quiet {println!("Removed target: {:?}", &cfg.target)}
                    }
                }
                Item::D(dir) => {
                    
                    if !cfg.quiet {println!("Identified data: directory.")}
                    
                    match fs::exists(&dir.path) {
                        Ok(exists) => {if exists {eprintln!("Error: Objective already exists."); exit(1)}}
                        Err(_) => {eprintln!("Error: Failed to check if objective exists."); exit(1)}
                    }

                    match dir.write_self() {
                        Ok(_) => {if !cfg.quiet {println!("Wrote result to disk.")}}
                        Err(_) => {eprintln!("Error: Failed to write result to disk."); exit(1)}
                    }

                    if cfg.delete {
                        if fs::remove_file(&cfg.target).is_err() {eprintln!("Error: Failed to remove target."); exit(1)}
                        if !cfg.quiet {println!("Removed target.")}
                    }
                }
            }
        }
    }
}

struct Paths {
    confpath: PathBuf,
    cachepath: PathBuf,
    hashpath: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct File {
    path: PathBuf,
    data: Vec<u8>
}
impl File {
    fn new(path: PathBuf, data: Vec<u8>) -> Self {
        File { path, data }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Sl {
    orig: PathBuf,
    path: PathBuf,
}
impl Sl {
    fn new(path: PathBuf, orig: PathBuf) -> Self {
        Sl { path, orig }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Dir {
    path: PathBuf,
    files: Vec<File>,
    symlinks: Vec<Sl>,
    subdirs: Vec<Dir>,
}

impl Dir {

    fn read_from(path: &Path) -> Result<Self, String> {

        let dir = match fs::read_dir(path) {
            Ok(d) => {d}
            Err(_) => {return Err(format!("Failed to read directory {:?}", path))}
        };
        let mut result = Dir {
            path: path.to_path_buf(),
            files: vec![],
            symlinks: vec![],
            subdirs: vec![],
        };

        for e in dir {

            let entry = match e {
                Ok(val) => {val}
                Err(_) => {return Err("Failed to read one or more directory entries.".to_string())}
            };
            if entry.path().is_symlink() {
                let orig = match entry.path().read_link() {
                    Ok(p) => {p}
                    Err(_) => {return Err(format!("Failed to read symlink {:?}", entry.path()))}
                };
                let path = entry.path();
                result.symlinks.push(Sl::new(path, orig));
            }
            else if entry.path().is_file() {
                let data = match fs::read(entry.path()) {
                    Ok(f) => {f}
                    Err(_) => {return Err(format!("Failed to read file {:?}", entry.path()))}
                };
                result.files.push(File::new(entry.path(), data));
            }
            else if entry.path().is_dir() {
                match Dir::read_from(&entry.path()) {
                    Ok(dir) => {result.subdirs.push(dir)}
                    Err(e) => {return Err(e)}
                };
            }
        }
        
        Ok(result)
    }

    pub fn write_self(&self) -> Result<(), io::Error> {
        fs::create_dir(&self.path)?;
        for f  in &self.files {fs::write(&f.path, &f.data)?}
        for sl in &self.symlinks {symlink(&sl.orig, &sl.path)?}
        for dir in &self.subdirs {dir.write_self()?}
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum Item {
    F(File),
    D(Dir)
}

#[derive(Debug, Serialize, Deserialize)]
struct DataStruct {
    data: Vec<u8>,
    nonce: Vec<u8>
}

fn encrypt(data: &[u8], hash: Hash) -> Result<Vec<u8>, String> {

    let key: &Key<Aes256Gcm> = hash.as_bytes().into();
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    match cipher.encrypt(&nonce,data) {
        Ok(enc) => {
            let ds = DataStruct {data: enc, nonce: nonce.to_vec()};
            let encdata = match serde_binary::to_vec(&ds, Endian::Big) {
                Ok(ed) => {ed}
                Err(_) => {return Err("Error: Failed to convert encrypted data to binary.".to_string())}
            };
            Ok(encdata)
        },
        Err(_) => {Err("Error: Encryption failed.".to_string())}
    }
}

fn decrypt(encdata: &[u8], hash: Hash) -> Result<Vec<u8>, String> {

    let ds: DataStruct = match serde_binary::from_slice(encdata, Endian::Big) {
        Ok(val) => {val}
        Err(_) => {return Err("Error: Failed to convert binary to encrypted data.".to_string())}
    };

    let key: &Key<Aes256Gcm> = hash.as_bytes().into();
    let cipher = Aes256Gcm::new(key);
    let nonce = aes_gcm::Nonce::from_slice(&ds.nonce);

    match cipher.decrypt(nonce ,ds.data.as_slice()) {
        Ok(data) => {Ok(data)}
        Err(_) => {Err("Error: Decryption failed.".to_string())}
    }
}

fn print_help() {
println!("Simple AES Encryptor (SAE), v. 0.1.0

SAE uses AES-256 for encryption and BLAKE3 for password hashing.

Commands:
    
    enc : encrypts file/directory
    $ sae enc [TARGET] <OPTIONS>

    dec : decrypts file/directory
    $ sae enc [TARGET] <OPTIONS>
    
    pwd : cache a password for this user
        
        Subcommands:
        
        set : save password hash
        $ sae pwd set <OPTIONS>
        
        del : remove password hash
        $ sae pwd del <OPTIONS>
        
        status : check if cache is full or empty
        $ sae pwd status

        verify : compare typed password with the hash
        $ sae pwd verify <OPTIONS>

    help : print this page
    $ sae help

Options:

    -c (--cache)  : use the cached password hash
    -s (--show)   : don't obfuscate password input
    -d (--delete) : remove target after operation
    -q (--quiet)  : hide terminal log");
}

}
