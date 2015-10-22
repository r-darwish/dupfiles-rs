use std::env::args;
use std::path::Path;
use std::fs::DirEntry;
use std::io;
use std::collections::HashMap;
use std::env;
use openssl::crypto::hash::hash;
use openssl::crypto::hash::Type as HashType;
use walker::Walker;
use memmap::{Mmap, Protection};

extern crate walker;
extern crate openssl;
extern crate memmap;

type Sha1 = [u8; 20];
type FileHash = (u64, Sha1);


fn hash_file(path: &Path) -> io::Result<Sha1> {
    let file_mmap = try!(Mmap::open_path(path, Protection::Read));
    let bytes: &[u8] = unsafe { file_mmap.as_slice() };
    let hash_vec = hash(HashType::SHA1, bytes);
    let mut hash_arr : Sha1 = [0; 20];
    assert_eq!(hash_vec.len(), hash_arr.len());
    for i in 0..hash_arr.len() {
        hash_arr[i] = hash_vec[i];
    }
    Ok(hash_arr)
}

fn index_file(entry: &DirEntry, index_map: &mut HashMap<FileHash, Vec<String>>)
    -> io::Result<()> {

    let file_type = try!(entry.file_type());
    if !file_type.is_file() {
        return Ok(());
    }

    let file_size = try!(entry.metadata().map(|m| m.len()));
    if file_size == 0 {
        return Ok(());
    }

    let hash = try!(hash_file(entry.path().as_path()));
    let key = (file_size, hash);

    if !index_map.contains_key(&key) {
        index_map.insert(key, Vec::<String>::new());
    }

    let mut vec = index_map.get_mut(&key).unwrap();
    vec.push(String::from(entry.path().as_path().to_str().unwrap()));

    Ok(())
}

fn main() {
    let dir = args().nth(1).unwrap_or(String::from(env::current_dir().unwrap().as_path().to_str().unwrap()));
    let walker = Walker::new(&(Path::new(&dir))).unwrap();

    let mut index_map = HashMap::new();

    for entry_result in walker {
        match entry_result {
            Ok(entry) => {
                match index_file(&entry, &mut index_map) {
                    Ok(_) => {},
                    Err(err) => {
                        println!("Error in {}: {}", entry.path().as_path().to_str().unwrap(), err); }
                }
            }
            Err(err) => { println!("Entry Error: {}", err) }
        }
    }

    for files in index_map.values() {
        if files.len() <= 1 {
            continue;
        }
        println!("{} duplicated files:", files.len());

        for file in files {
            println!("  {}", file);
        }

        println!("");
    }

}
