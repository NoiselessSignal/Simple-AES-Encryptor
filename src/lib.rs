pub mod pwd;
pub mod args;
pub mod crypto;

pub mod lib {

use std::{
    env::set_current_dir,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::{ffi::{OsStrExt, OsStringExt}, fs::symlink},
    path::PathBuf,
};
use blake3::hash;
use jwalk::WalkDir;
use crate::{args::args::*, crypto::crypto::*, pwd::pwd::*};

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn lock_command(src: Src, dst: Option<Dst>, opts: Opts) -> Result<(), GeneralError> {
    
    let src_type = match SrcType::from(src) {
        Ok(x) => {x}
        Err(e) => {return Err(GeneralError::SrcAnalysisError(e));}
    };

    let pwd_hash = if opts.cache {
        match read_cache() {
            Ok(h) => {h}
            Err(e) => {return Err(GeneralError::CacheAccessError(e));}
        }
    }
    else {
        match rpassword::prompt_password("Password: ") {
            Ok(s) => {hash(s.as_bytes())}
            Err(e) => {return Err(GeneralError::PwdError(e.to_string()));}
        }
    };
    match src_type {

        SrcType::OpenFile(src, name, parent) => {
        
            let file_bytes = match fs::read(&src.0) {
                Ok(b) => {b}
                Err(e) => {return Err(GeneralError::FileReadError(src.0, e.to_string()));}
            };
            let mut enc_file_obj = encrypt_bytes(file_bytes, pwd_hash)?;
            let name_bytes = name.0.as_bytes().to_vec();
            let mut enc_name_obj = encrypt_bytes(name_bytes, pwd_hash)?;
            let mut new_name = name.0;
            new_name.push(OsStr::new(".sae"));
        
            let dst = match dst {
                Some(d) => {
                    let new_path = d.0.join(new_name);
                    Dst(new_path)
                }
                None => {Dst(parent.0.join(new_name))}
            };
            
            let mut enc_name_obj_length = get_length_of_slice_as_bytes(&enc_name_obj);
            let mut total = b"saefile".to_vec();
            total.append(&mut enc_name_obj_length);
            total.append(&mut enc_name_obj);
            total.append(&mut enc_file_obj);

            if let Err(e) = fs::write(&dst.0, total) {return Err(GeneralError::FileWriteError(dst.0, e.to_string()));}
            if opts.delete {
                if let Err(e) = fs::remove_file(&src.0) {return Err(GeneralError::RemovingOriginalFileError(e.to_string()));}
            }
        }

        SrcType::OpenDir(src, name, parent) => {

            if let Err(e) = set_current_dir(&parent.0) {return Err(GeneralError::SetCurrentDirError(e.to_string()));}

            let mut new_name = name.0.clone();
            new_name.push(OsStr::new("-sae"));

            let dst = match dst {
                Some(d) => {
                    let new_path = d.0.join(new_name);
                    Dst(new_path)
                }
                None => {Dst(parent.0.join(new_name))}
            };
            if let Err(e) = fs::create_dir(&dst.0) {return Err(GeneralError::DirWriteError(dst.0, e.to_string()));}
            let saedir_path = dst.0.join(".saedir");
            let mut saedir = match OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(src.0.join(&saedir_path))
            {
                Ok(f) => {f}
                Err(e) => {return Err(GeneralError::FileWriteError(saedir_path, e.to_string()));}
            };

            let dirwalk = WalkDir::new(&name.0).skip_hidden(false);
            let mut dirpaths = vec![];
            let mut filepaths = vec![];
            let mut linkpaths = vec![];
        
            for entry in dirwalk {
                let entry = match entry {
                    Ok(e) => {e}
                    Err(e) => {return Err(GeneralError::EntryReadError(e.to_string()));}
                };
                let path = entry.path();
                
                if path.is_file() {filepaths.push(path);}
                else if path.is_dir() {dirpaths.push(path);}
                else if path.is_symlink() {
                    let point = match path.read_link() {
                        Ok(p) => {p}
                        Err(e) => {return Err(GeneralError::LinkReadError(path, e.to_string()))}
                    };
                    linkpaths.push((path, point));
                }
            }

            let mut dirpath_buffer = vec![];
            for path in dirpaths {
                let path_bytes = path.as_os_str().as_bytes().to_vec();
                let mut enc_path_obj = encrypt_bytes(path_bytes, pwd_hash)?;
                let mut enc_path_obj_length = get_length_of_slice_as_bytes(&enc_path_obj);
                dirpath_buffer.append(&mut enc_path_obj_length);
                dirpath_buffer.append(&mut enc_path_obj);
            }
            if let Err(e) = saedir.write(&dirpath_buffer) {return Err(GeneralError::FileWriteError(saedir_path, e.to_string()));}
            drop(dirpath_buffer);

            for path in filepaths {
                let filename = match path.file_name() {
                    Some(s) => {s.to_os_string()}
                    None => {return Err(GeneralError::FileHasNoName(path));}
                };
                let hashname = hash(filename.as_bytes()).to_string(); drop(filename);
                let mut enc_path_obj = encrypt_bytes(path.as_os_str().as_bytes().to_vec(), pwd_hash)?;
                let file_bytes = match fs::read(&path) {
                    Ok(b) => {b}
                    Err(e) => {return Err(GeneralError::FileReadError(path, e.to_string()));}
                };
                let mut enc_file_obj = encrypt_bytes(file_bytes, pwd_hash)?;
                let mut enc_path_obj_length = get_length_of_slice_as_bytes(&enc_path_obj);
                let mut total = b"saedirf".to_vec();
                total.append(&mut enc_path_obj_length);
                total.append(&mut enc_path_obj);
                total.append(&mut enc_file_obj);

                let output_path = &dst.0.join(&hashname);
                if let Err(e) = fs::write(output_path, total) {
                    return Err(GeneralError::FileWriteError(output_path.to_owned(), e.to_string()));
                }
            }

            for (path, orig) in linkpaths {
                let filename = match path.file_name() {
                    Some(s) => {s.to_os_string()}
                    None => {return Err(GeneralError::FileHasNoName(path));}
                };
                let hashname = hash(filename.as_bytes()).to_string();
                let path_bytes = path.as_os_str().as_bytes().to_vec();
                let point_bytes = orig.as_os_str().as_bytes().to_vec();
                let mut enc_path_obj = encrypt_bytes(path_bytes, pwd_hash)?;
                let mut enc_point_obj = encrypt_bytes(point_bytes, pwd_hash)?;
                let mut enc_path_obj_length = get_length_of_slice_as_bytes(&enc_path_obj);
                let mut total = b"saedirl".to_vec();
                total.append(&mut enc_path_obj_length);
                total.append(&mut enc_path_obj);
                total.append(&mut enc_point_obj);

                let output_path = &dst.0.join(&hashname);
                if let Err(e) = fs::write(output_path, total) {
                    return Err(GeneralError::FileWriteError(output_path.to_owned(), e.to_string()));
                }
            }

            if opts.delete {
                if let Err(e) = fs::remove_dir_all(&src.0) {return Err(GeneralError::RemovingOriginalDirError(e.to_string()));}
            }
        }
        SrcType::LockedFile(..) => {return Err(GeneralError::AlreadyLocked);}
        SrcType::LockedDir(..) => {return Err(GeneralError::AlreadyLocked);}
    }

    Ok(())
}

pub fn open_command(src: Src, dst: Option<Dst>, opts: Opts) -> Result<(), GeneralError> {
    
    let src_type = match SrcType::from(src) {
        Ok(x) => {x}
        Err(e) => {return Err(GeneralError::SrcAnalysisError(e));}
    };
    
    let pwd_hash = if opts.cache {
        match read_cache() {
            Ok(h) => {h}
            Err(e) => {return Err(GeneralError::CacheAccessError(e));}
        }
    }
    else {
        match rpassword::prompt_password("Password: ") {
            Ok(s) => {hash(s.as_bytes())}
            Err(e) => {return Err(GeneralError::PwdError(e.to_string()));}
        }
    };

    match src_type {
        
        SrcType::LockedFile(src, parent) => {
            
            let enc_bytes = match fs::read(&src.0) {
                Ok(b) => {b}
                Err(e) => {return Err(GeneralError::FileReadError(src.0, e.to_string()));}
            };
            
            let enc_name_obj_length = match enc_bytes.get(7..27) {
                Some(b) => {try_slice_into_usize(b)?}
                None => {return Err(GeneralError::InvalidFormat);}
            };
            let enc_name_obj = match enc_bytes.get(27..27+enc_name_obj_length) {
                Some(b) => {b.to_vec()}
                None => {return Err(GeneralError::InvalidFormat);}
            };
            let original_name = OsString::from_vec(decrypt_bytes(enc_name_obj, pwd_hash)?);

            let enc_file_obj = match enc_bytes.get(27+enc_name_obj_length..) {
                Some(b) => {b.to_vec()}
                None => {return Err(GeneralError::InvalidFormat);}
            };
            drop(enc_bytes);
            let file_bytes = decrypt_bytes(enc_file_obj, pwd_hash)?;

            let dst = match dst {
                Some(d) => {
                    let new_path = d.0.join(original_name);
                    Dst(new_path)
                }
                None => {Dst(parent.0.join(original_name))}
            };
            if let Err(e) = fs::write(&dst.0, file_bytes) {
                return Err(GeneralError::FileWriteError(dst.0, e.to_string()));
            }
            if opts.delete {
                if let Err(e) = fs::remove_file(&src.0) {return Err(GeneralError::RemovingOriginalFileError(e.to_string()));}
            }
        }
        SrcType::LockedDir(src, parent) => {

            if let Err(e) = set_current_dir(&parent.0) {return Err(GeneralError::SetCurrentDirError(e.to_string()));}

            let saedir_path = &src.0.join(".saedir");
            let dirpaths_buffer = match fs::read(saedir_path) {
                Ok(b) => {b}
                Err(e) => {return Err(GeneralError::FileReadError(saedir_path.to_owned(), e.to_string()));}
            };

            let dst = match dst {
                Some(d) => {d}
                None => {Dst(parent.0)}
            };

            let mut c = 0;
            let mut dirpaths = vec![];
            loop {
                let length = match dirpaths_buffer.get(c..c+20) {
                    Some(b) => {try_slice_into_usize(b)?}
                    None => {if c == 0 {return Err(GeneralError::InvalidSaeDirFormat)} else {break;}}
                };
                let enc_path_obj = match dirpaths_buffer.get(c+20..c+20+length) {
                    Some(b) => {b.to_vec()}
                    None => {return Err(GeneralError::InvalidSaeDirFormat);}
                };
                let path = PathBuf::from(OsString::from_vec(decrypt_bytes(enc_path_obj, pwd_hash)?));
                dirpaths.push(path);
                c = c+20+length;
            }
            
            for dirpath in &dirpaths {
                let output_path = &dst.0.join(dirpath);
                if let Err(e) = fs::create_dir(output_path) {return Err(GeneralError::DirWriteError(output_path.to_owned(), e.to_string()));}
            }

            let enc_dir = match fs::read_dir(&src.0) {
                Ok(x) => {x}
                Err(e) => {return Err(GeneralError::DirReadError(src.0, e.to_string()));}
            };
            for entry in enc_dir {
                let entry = match entry {
                    Ok(e) => {e}
                    Err(e) => {return Err(GeneralError::EntryReadError(e.to_string()));}
                };
                let path = entry.path();
                let name = path.file_name().unwrap();
                if name == OsStr::new(".saedir") {continue;}
                
                let enc_bytes = match fs::read(&path) {
                    Ok(b) => {b}
                    Err(e) => {return Err(GeneralError::FileReadError(path, e.to_string()));}
                };
                let header = match enc_bytes.get(0..7) {
                    Some(b) => {b}
                    None => {return Err(GeneralError::InvalidSaedDirEntry(path));}
                };
                if header == b"saedirf" {
                    let enc_path_obj_length = match enc_bytes.get(7..27) {
                        Some(b) => {try_slice_into_usize(b)?}
                        None => {return Err(GeneralError::InvalidSaedDirEntry(path));}
                    };
                    let enc_path_obj = match enc_bytes.get(27..27+enc_path_obj_length) {
                        Some(b) => {b.to_vec()}
                        None => {return Err(GeneralError::InvalidSaedDirEntry(path));}
                    };
                    let original_path = PathBuf::from(OsString::from_vec(decrypt_bytes(enc_path_obj, pwd_hash)?));
                    let enc_file_obj = match enc_bytes.get(27+enc_path_obj_length..) {
                        Some(b) => {b.to_vec()}
                        None => {return Err(GeneralError::InvalidSaedDirEntry(path));}
                    };
                    drop(enc_bytes);
                    let file_bytes = decrypt_bytes(enc_file_obj, pwd_hash)?;
                    let output_path = &dst.0.join(original_path);
                    if let Err(e) = fs::write(output_path, file_bytes) {
                        return Err(GeneralError::FileWriteError(output_path.to_owned(), e.to_string()));
                    }
                }
                else if header == b"saedirl" {
                    let enc_path_obj_length = match enc_bytes.get(7..27) {
                        Some(b) => {try_slice_into_usize(b)?}
                        None => {return Err(GeneralError::InvalidSaedDirEntry(path));}
                    };
                    let enc_path_obj = match enc_bytes.get(27..27+enc_path_obj_length) {
                        Some(b) => {b.to_vec()}
                        None => {return Err(GeneralError::InvalidSaedDirEntry(path));}
                    };
                    let original_path = PathBuf::from(OsString::from_vec(decrypt_bytes(enc_path_obj, pwd_hash)?));
                    let enc_point_obj = match enc_bytes.get(27+enc_path_obj_length..) {
                        Some(b) => {b.to_vec()}
                        None => {return Err(GeneralError::InvalidSaedDirEntry(path));}
                    };
                    drop(enc_bytes);
                    let point = PathBuf::from(OsString::from_vec(decrypt_bytes(enc_point_obj, pwd_hash)?));
                    let output_path = &dst.0.join(original_path);
                    if let Err(e) = symlink(point, output_path) {
                        return Err(GeneralError::FileWriteError(output_path.to_owned(), e.to_string()));
                    }
                }
                else {return Err(GeneralError::InvalidSaedDirEntry(path));}
            }

            if opts.delete {
                if let Err(e) = fs::remove_dir_all(&src.0) {return Err(GeneralError::RemovingOriginalDirError(e.to_string()));}
            }
        }
        SrcType::OpenFile(..) => {return Err(GeneralError::AlreadyOpen);}
        SrcType::OpenDir(..) => {return Err(GeneralError::AlreadyOpen);}
    }

    Ok(())
}

pub fn save_command() -> Result<(), GeneralError> {
    
    enum OptNum {Status, Compare, Set, Del}

    let mut opt_num = OptNum::Status;

    loop {
        let uinput = {
            let mut uinput = "".to_string();
            println!("[1] Status\n[2] Compare\n[3] Set\n[4] Delete");
            if let Err(e) = io::stdin().read_line(&mut uinput) {return Err(GeneralError::CacheAccessError(CacheAccessError::FailedRead(e.to_string())))}
            let mut uinput_chars: Vec<char> = uinput.chars().collect();
            uinput_chars.pop();
            let uinput: String = uinput_chars.iter().collect();
            uinput
        };
        match uinput.as_str() {
            "1" => {break;}
            "2" => {opt_num = OptNum::Compare; break;}
            "3" => {opt_num = OptNum::Set; break;}
            "4" => {opt_num = OptNum::Del; break;}
            _ => {continue;}
        }
    }

    match opt_num {
        OptNum::Status => {
            match read_cache() {
                Ok(_) => {println!("Exists.");}
                Err(e) => {
                    if e == CacheAccessError::NotFound {println!("Doesn't exist.");}
                    else {return Err(GeneralError::CacheAccessError(e));}
                }
            }
        }
        OptNum::Compare => {
            match compare_pwd() {
                Ok(b) => {
                    if b {println!("\nMatch!")}
                    else {println!("\nDifferent!")}
                }
                Err(e) => {return Err(GeneralError::CacheAccessError(e));}
            }
        }
        OptNum::Set => {if let Err(e) = set_cache() {return Err(GeneralError::CacheAccessError(e));}}
        OptNum::Del => {if let Err(e) = delete_cache() {return Err(GeneralError::CacheAccessError(e));}}
    }

    Ok(())
}

pub enum GeneralError {
    InvalidFormat,
    AlreadyLocked,
    AlreadyOpen,
    InvalidSaeDirFormat,
    FileReadError(PathBuf, String),
    FileWriteError(PathBuf, String),
    DirWriteError(PathBuf, String),
    DirReadError(PathBuf, String),
    SrcAnalysisError(SrcAnalysisError),
    SetCurrentDirError(String),
    EntryReadError(String),
    FileHasNoName(PathBuf),
    EncryptionError,
    DecryptionError,
    InvalidSaedDirEntry(PathBuf),
    LinkReadError(PathBuf, String),
    PwdError(String),
    CacheAccessError(CacheAccessError),
    RemovingOriginalFileError(String),
    RemovingOriginalDirError(String),
}

impl GeneralError {

    pub fn to_string(self) -> String {
        match self {
            Self::EncryptionError => {format!("Encryption operation failed.")}
            Self::DecryptionError => {format!("Decryption operation failed.")}
            Self::InvalidFormat => {"Target file format is invalid.".to_string()}
            Self::AlreadyLocked => {"Target is already encrypted.".to_string()}
            Self::AlreadyOpen => {"Target is already unencrypted.".to_string()}
            Self::DirReadError(p, s) => {format!("Failed to read directory at {p:?}: {s}")}
            Self::DirWriteError(p, s) => {format!("Failed to make directory at {p:?}: {s}")}
            Self::EntryReadError(s) => {format!("Failed to read entry in target directory: {s}")}
            Self::FileHasNoName(p) => {format!("File at {p:?} has no name.")}
            Self::FileReadError(p, s) => {format!("Failed to read file at {p:?}: {s}")}
            Self::FileWriteError(p, s) => {format!("Failed to write file at {p:?}: {s}")}
            Self::InvalidSaeDirFormat => {"Hidden \".saedir\" object in the encrypted directory is invalid.".to_string()}
            Self::InvalidSaedDirEntry(p) => {format!("Encrypted entry in directory at {p:?} is invalid.")}
            Self::LinkReadError(p, s) => {format!("Failed to read symlink at {p:?}: {s}")}
            Self::SetCurrentDirError(s) => {format!("Failed to change current directory: {s}")}
            Self::SrcAnalysisError(s) => {s.to_string()}
            Self::PwdError(s) => {format!("Failed to read password prompt: {s}")}
            Self::CacheAccessError(e) => {e.to_string()}
            Self::RemovingOriginalFileError(s) => {format!("Failed to remove original target file: {s}")}
            Self::RemovingOriginalDirError(s) => {format!("Failed to remove original target directory: {s}")}
        }
    }
}

pub fn print_help() {
println!("Simple AES Encryptor (SAE), v. {VERSION}

SAE uses AES-256 for encryption and BLAKE3 for password hashing.

Commands:
    
    lock: encrypt file/directory
    $ sae lock [PATH] <OPTIONS>

    open: decrypt file/directory
    $ sae open [PATH] <OPTIONS>

    into: specify an output directory
    $ sae lock [PATH] into [OUTPUT] <OPTIONS>
    
    save: access cache for this user
    $ sae save

    help: print this page
    $ sae help

Options:

    -d (--delete) : remove target after operation
    -c (--cache)  : use the cached password hash");
}

}