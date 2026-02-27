use std::{env::{args, current_dir}, ffi::{OsStr, OsString}, fs, io::Read, path::PathBuf};

pub enum Cfg {
    Lock(Src, Option<Dst>, Opts),
    Open(Src, Option<Dst>, Opts),
    Save,
    Help,
}

pub fn parse_args() -> Result<Cfg, ParseError> {

    let mut args = args();
    args.next();

    let command = match args.next() {
        Some(s) => {s}
        None => {return Err(ParseError::NoCommand);}
    };

    if !["lock", "open", "save", "help"].contains(&command.as_str()) {return Err(ParseError::UnrecognizedCommand);}
    if command.as_str() == "help" {return Ok(Cfg::Help);}
    if command.as_str() == "save" {return Ok(Cfg::Save);}
    
    let src = match args.next() {
        Some(s) => {PathBuf::from(s)}
        None => {return Err(ParseError::NoSrcPath);}
    };
    let mut opts = Opts { delete: false, cache: false };

    let arg = match args.next() {
        Some(s) => {s}
        None => {
            if command.as_str() == "lock" {return Ok(Cfg::Lock(Src(src), None, opts));}
            else {return Ok(Cfg::Open(Src(src), None, opts));}
        }
    };

    if &arg == "into" {
        let dst = match args.next() {
            Some(s) => {PathBuf::from(s)}
            None => {return Err(ParseError::NoDstAfterInto);}
        };
        if !dst.is_dir() {return Err(ParseError::DstNotADir);}
        if let Err(e) = opts.modify(args.next()) {return Err(ParseError::OptsError(e));}
        if let Err(e) = opts.modify(args.next()) {return Err(ParseError::OptsError(e));}
        if args.next().is_some() {return Err(ParseError::TooMany);}
        if &command == "lock" {return Ok(Cfg::Lock(Src(src), Some(Dst(dst)), opts));}
        else {return Ok(Cfg::Open(Src(src), Some(Dst(dst)), opts));}
    }
    else {
        if let Err(e) = opts.modify(Some(arg)) {return Err(ParseError::OptsError(e));}
        if let Err(e) = opts.modify(args.next()) {return Err(ParseError::OptsError(e));}
        if args.next().is_some() {return Err(ParseError::TooMany);}
        if &command == "lock" {return Ok(Cfg::Lock(Src(src), None, opts));}
        else {return Ok(Cfg::Open(Src(src), None, opts));}
    }
}

pub enum ParseError {
    NoCommand,
    NoSrcPath,
    UnrecognizedCommand,
    NoDstAfterInto,
    DstNotADir,
    OptsError(OptsError),
    TooMany
}

impl ParseError {

    pub fn to_string(self) -> String {
        match self {
            Self::DstNotADir => {"Destination is not a directory.".to_string()}
            Self::NoDstAfterInto => {"No destination path provided after 'into'.".to_string()}
            Self::NoCommand => {"No command provided.".to_string()}
            Self::NoSrcPath => {"No source path provided.".to_string()}
            Self::OptsError(e) => {e.to_string()}
            Self::TooMany => {"Too many arguments provided.".to_string()}
            Self::UnrecognizedCommand => {"Unrecognized command found.".to_string()}
        }
    }
}

pub struct Opts { pub delete: bool, pub cache: bool }

impl Opts {

    fn modify(&mut self, arg: Option<String>) -> Result<bool, OptsError> {
        let opt = match arg {
            Some(s) => {s}
            None => {return Ok(false);}
        };
        match opt.as_str() {
            "-c" => {
                if !self.cache {self.cache = true; return Ok(true);}
                else {return Err(OptsError::RepeatedOption("--cache".to_string()));}
            }
            "--cache" => {
                if !self.cache {self.cache = true; return Ok(true);}
                else {return Err(OptsError::RepeatedOption("--cache".to_string()));}
            }
            "-d" => {
                if !self.delete {self.delete = true; return Ok(true);}
                else {return Err(OptsError::RepeatedOption("--delete".to_string()));}
            }
            "--delete" => {
                if !self.delete {self.delete = true; return Ok(true);}
                else {return Err(OptsError::RepeatedOption("--delete".to_string()));}
            }
            _ => {return Err(OptsError::UnrecognizedOption);}
        }
    }
}

pub enum OptsError {
    RepeatedOption(String),
    UnrecognizedOption,
}

impl OptsError {

    fn to_string(self) -> String {
        match self {
            Self::RepeatedOption(s) => {format!("Repeated option {s} found.")}
            Self::UnrecognizedOption => {"Unrecognized option found.".to_string()}
        }
    }
}

pub struct Src(pub PathBuf);
pub struct Dst(pub PathBuf);

pub enum SrcType {
    OpenFile(Src, Name, Parent),
    OpenDir(Src, Name, Parent),
    LockedFile(Src, Parent),
    LockedDir(Src, Parent),
}
pub struct Name(pub OsString);
pub struct Parent(pub PathBuf);

impl SrcType {
    
    pub fn from(src: Src) -> Result<Self, SrcAnalysisError> {

        if !src.0.exists() {return Err(SrcAnalysisError::NotFound);}
        if !src.0.is_file() && !src.0.is_dir() {return Err(SrcAnalysisError::InvalidType);}

        let name = match src.0.file_name() {
            Some(s) => {s.to_os_string()}
            None => {return Err(SrcAnalysisError::NoName);}
        };
        let parent = match src.0.parent() {
            Some(p) => {
                let path_os = p.as_os_str();
                if path_os.is_empty() {
                    match current_dir() {
                        Ok(p) => {p}
                        Err(e) => {return Err(SrcAnalysisError::CurrentDirFetchError(e.to_string()));}
                    }
                }
                else {p.to_path_buf()}
            }
            None => {
                if src.0.is_dir() && src.0.is_absolute() {return Err(SrcAnalysisError::IsRootDir);}
                match current_dir() {
                    Ok(p) => {p}
                    Err(e) => {return Err(SrcAnalysisError::CurrentDirFetchError(e.to_string()));}
                }
            }
        };

        if src.0.is_file() {
            let mut file = match fs::File::open(&src.0) {
                Ok(f) => {f}
                Err(e) => {return Err(SrcAnalysisError::FileOpenError(src.0, e.to_string()));}
            };
            let length = match file.metadata() {
                Ok(md) => {md.len()}
                Err(e) => {return Err(SrcAnalysisError::FileMetadataReadError(src.0, e.to_string()));}
            };
            if length < 7 {return Ok(SrcType::OpenFile(src, Name(name), Parent(parent)));}
            let mut header = [0u8; 7];
            if let Err(e) = file.read_exact(&mut header) {return Err(SrcAnalysisError::FileReadError(src.0, e.to_string()));}
            if &header == b"saefile" {return Ok(SrcType::LockedFile(src, Parent(parent)));}
            else {return Ok(SrcType::OpenFile(src, Name(name), Parent(parent)));}
        }
        else {
            if src.0.join(PathBuf::from(&OsStr::new(".saedir"))).exists() {return Ok(SrcType::LockedDir(src, Parent(parent)));}
            else {return Ok(SrcType::OpenDir(src, Name(name), Parent(parent)));}
        }
    }
}

pub enum SrcAnalysisError {
    NotFound,
    NoName,
    IsRootDir,
    InvalidType,
    CurrentDirFetchError(String),
    FileMetadataReadError(PathBuf, String),
    FileOpenError(PathBuf, String),
    FileReadError(PathBuf, String),
}

impl SrcAnalysisError {

    pub fn to_string(self) -> String {
        match self {
            Self::CurrentDirFetchError(s) => {format!("Failed to identify current directory: {s}")}
            Self::FileMetadataReadError(p, s) => {format!("Failed to read file metadata at {p:?}: {s}")}
            Self::FileOpenError(p, s) => {format!("Failed to open file at {p:?}: {s}")}
            Self::FileReadError(p, s) => {format!("Failed to read file at {p:?}: {s}")}
            Self::InvalidType => {"Target file has invalid format.".to_string()}
            Self::IsRootDir => {"Target directory seems to be root.".to_string()}
            Self::NoName => {"Target has no name.".to_string()}
            Self::NotFound => {"Target not found.".to_string()}
        }
    }
}