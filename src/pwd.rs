use std::{fs, io, path::PathBuf, process::exit};
use blake3::{Hash, hash};
use users::get_current_username;

fn cached_hash_path() -> PathBuf {
    let uname = get_current_username().unwrap();
    let user_dir_path = PathBuf::from("/home").join(PathBuf::from(&uname));
    let cache_file_path = user_dir_path.join(".config/sae/hash");
    cache_file_path
}

pub fn read_cache() -> Result<Hash, CacheAccessError> {
    let cache_path = cached_hash_path();
    if !cache_path.exists() {return Err(CacheAccessError::NotFound);}
    if !cache_path.is_file() {return Err(CacheAccessError::InvalidFormat);}
    let pwd_hash_bytes = match fs::read(cache_path) {
        Ok(s) => {s}
        Err(e) => {return Err(CacheAccessError::FailedRead(e.to_string()));}
    };
    let bytes_array: [u8; 32] = match pwd_hash_bytes.try_into() {
        Ok(x) => {x}
        Err(_) => {return Err(CacheAccessError::InvalidLength);}
    };
    Ok(Hash::from_bytes(bytes_array))
}

pub fn set_cache() -> Result<(), CacheAccessError> {

    match read_cache() {
        Ok(_) => {return Err(CacheAccessError::AlreadyExists);}
        Err(e) => {
            if e != CacheAccessError::NotFound {return Err(e);}
        }
    };
    let cache_path = cached_hash_path();
    let sae_dir_path = cache_path.parent().unwrap().to_path_buf();
    let hidden_dir_path = sae_dir_path.parent().unwrap().to_path_buf();
    let user_dir_path = hidden_dir_path.parent().unwrap().to_path_buf();

    let pwd_hash = match rpassword::prompt_password("Password: ") {
        Ok(s) => {hash(s.as_bytes())}
        Err(e) => {return Err(CacheAccessError::PromptReadError(e.to_string()));}
    };
    
    if !user_dir_path.exists() || !user_dir_path.is_dir() {return Err(CacheAccessError::UserDirError)}
    
    if !hidden_dir_path.exists() {
        if let Err(e) = fs::create_dir(&hidden_dir_path) {
            return Err(CacheAccessError::FailedToCreateDir(hidden_dir_path, e.to_string()));
        }
    }
    if !sae_dir_path.exists() {
        if let Err(e) = fs::create_dir(&sae_dir_path) {
            return Err(CacheAccessError::FailedToCreateDir(sae_dir_path, e.to_string()));
        }
    }
    if !cache_path.exists() {
        if let Err(e) = fs::write(&cache_path, pwd_hash.as_bytes()) {
            return Err(CacheAccessError::FailedToWriteCFile(cache_path, e.to_string()));
        }
    }
    Ok(())
}

pub fn delete_cache() -> Result<(), CacheAccessError> {

    loop {
        let uinput = {
            let mut uinput = "".to_string();
            println!("Remove saved password hash for this user? [y/n]");
            if let Err(e) = io::stdin().read_line(&mut uinput) {return Err(CacheAccessError::PromptReadError(e.to_string()))}
            let mut uinput_chars: Vec<char> = uinput.chars().collect();
            uinput_chars.pop();
            let uinput: String = uinput_chars.iter().collect();
            uinput
        };
        match uinput.as_str() {
            "y" => {break;}
            "n" => {exit(0)}
            _ => {continue;}
        }
    }
    
    let cache_path = cached_hash_path();
    if !cache_path.exists() {return Err(CacheAccessError::NotFound);}
    if !cache_path.is_file() {return Err(CacheAccessError::InvalidFormat);}
    if let Err(e) = fs::remove_file(cache_path) {return Err(CacheAccessError::DeleteError(e.to_string()));}
    Ok(())
}

pub fn compare_pwd() -> Result<bool, CacheAccessError> {
    
    let user_hash = match rpassword::prompt_password("Password: ") {
        Ok(s) => {hash(s.as_bytes())}
        Err(e) => {return Err(CacheAccessError::PromptReadError(e.to_string()));}
    };
    let existing_hash = read_cache()?;

    if user_hash == existing_hash {Ok(true)} else {Ok(false)}
}

#[derive(PartialEq)]
pub enum CacheAccessError {
    NotFound,
    InvalidFormat,
    InvalidLength,
    FailedRead(String),
    AlreadyExists,
    UserDirError,
    FailedToCreateDir(PathBuf, String),
    FailedToWriteCFile(PathBuf, String),
    DeleteError(String),
    PromptReadError(String),
}

impl CacheAccessError {

    pub fn to_string(self) -> String {
        match self {
            Self::AlreadyExists => {"Cache already exists.".to_string()}
            Self::UserDirError => {"User directory not found.".to_string()}
            Self::FailedToCreateDir(p, s) => {format!("Failed to create directory {p:?}: {s}")}
            Self::FailedToWriteCFile(p, s) => {format!("Failed to write cache {p:?}: {s}")}
            Self::NotFound => {"Cache not found.".to_string()}
            Self::DeleteError(s) => {format!("Failed to remove cache: {s}")}
            Self::PromptReadError(s) => {format!("Failed to read terminal prompt: {s}")}
            Self::FailedRead(s) => {format!("Failed to read cache: {s}")}
            Self::InvalidFormat => {"Cache data has invalid format.".to_string()}
            Self::InvalidLength => {"Cache data has invalid length.".to_string()}
        }
    }
}