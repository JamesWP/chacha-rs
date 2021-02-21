mod chacha;

use chacha::ChaChaState;
use io::{Write, stdout};
use rand::Rng;
use sha2::{Digest, Sha256};
use core::panic;
use std::{fs::{File, OpenOptions}, hash, io, ops::Deref, time::SystemTime};

use clap::{clap_app, SubCommand};
use memmap::{Mmap, MmapOptions};

const NONCE_LEN: usize = 12;
const MAGIC_STR: &[u8; 10] = b"CHACHA--RS";
const HEADER_LEN: usize = NONCE_LEN + MAGIC_STR.len();

fn get_key() -> [u8; 32] {
    print!("passphrase> ");
    io::stdout().flush();

    let stdin = io::stdin();
    let mut passphrase_buf = String::new();
    stdin.read_line(&mut passphrase_buf).unwrap();

    // create a Sha256 object
    let mut hasher = Sha256::new();
    hasher.update(passphrase_buf.as_bytes());

    let digest = hasher.finalize();
    let digest = digest.as_slice();
    
    assert_eq!(32, digest.len());
    
    let mut key = [0;32];
    key.copy_from_slice(digest);

    key
}

fn get_nonce() -> [u8; NONCE_LEN] {
    // nonce is time and random:

    // get time bytes x8
    let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let time = time.as_secs().to_le_bytes();
    
    // get random bytes x4
    let mut rng = rand::thread_rng();
    let rand: u32 = rng.gen();
    let rand = rand.to_le_bytes();

    // construct nonce 8+4 = 12
    let mut nonce = [0u8;NONCE_LEN];

    {
        let (nonce_time, nonce_extra) = nonce.split_at_mut(time.len());
        
        nonce_time.copy_from_slice(&time);
        nonce_extra.copy_from_slice(&rand);
    }

    nonce
}


fn do_encrypt(
    key: [u8; 32],
    cleartext_filepath: &str,
    output_filepath: &str,
) -> std::io::Result<()> {
    println!("input: {:?}, output: {:?}, key:{:02x?}", cleartext_filepath, output_filepath, key);
    // create nonce
    let nonce = get_nonce();
    
    // open readfile
    let cleartext = File::open(cleartext_filepath)?;

    let cleartext_data  = &unsafe { MmapOptions::new().map(&cleartext)? }[..];

    println!("datasize: {}", cleartext_data.len());

    // open writefile
    let mut output_options = OpenOptions::new();
    output_options.read(true).write(true).truncate(true).create(true);

    let output = output_options.open(output_filepath)?;

    // set writefile to correct size
    let output_size = cleartext_data.len() + HEADER_LEN;
    output.set_len(output_size as u64)?;

    let output_data  = unsafe { Mmap::map(&output)?  };
    let output_data = &mut output_data.make_mut()?[..];

    
    let (output_header, output_data) = output_data.split_at_mut(HEADER_LEN);
    
    // write prelude
    let (output_magic, output_nonce) = output_header.split_at_mut(MAGIC_STR.len());
    output_magic.copy_from_slice(&MAGIC_STR[..]);
    output_nonce.copy_from_slice(&nonce);
    
    // write encrypted bytes
    let mut chacha = ChaChaState::new(&key,&nonce);
    chacha.encrypt_decrypt(cleartext_data, output_data);

    Ok(())
}

fn do_decrypt(
    key: [u8; 32],
    encrypted_filepath: &str,
    cleartext_filepath: &str,
) -> std::io::Result<()> {
    println!("input: {:?}, output: {:?}, key:{:02x?}", encrypted_filepath, cleartext_filepath, key);

    // open encrypted file
    let encrypted = File::open(encrypted_filepath)?;

    let encrypted_data  = &unsafe { MmapOptions::new().map(&encrypted)? }[..];

    // check size
    assert!(encrypted_data.len() > HEADER_LEN);

    let (encrypted_header, encrypted_data) = encrypted_data.split_at(HEADER_LEN);

    let (encrypted_magic, nonce) = encrypted_header.split_at(MAGIC_STR.len());

    // check magic
    assert_eq!(encrypted_magic, &MAGIC_STR[..]);

    // check nonce
    assert_eq!(nonce.len(), NONCE_LEN);
    let mut nonce_array:[u8;12] = [0;12];
    nonce_array.copy_from_slice(nonce);
    let nonce = nonce_array;

    // open output file    
    let mut output_options = OpenOptions::new();
    output_options.read(true).write(true).truncate(true).create(true);

    let output = output_options.open(cleartext_filepath)?;

    // set output file length
    let output_size = encrypted_data.len();
    output.set_len(output_size as u64)?;

    let output_data  = unsafe { Mmap::map(&output)?  };
    let output_data = &mut output_data.make_mut()?[..];

    // write decrypted bytes
    let mut chacha = ChaChaState::new(&key,&nonce);
    chacha.encrypt_decrypt(encrypted_data, output_data);

    Ok(())
}

fn main() -> std::io::Result<()> {
    let matches = clap_app!(myapp =>
        (version: "0.0")
        (author: "James P. jameswp@github")
        (about: "ChaCha-rs encrypt and decrypt files")
        (@subcommand encrypt =>
            (about: "encrypt file")
            (@arg INPUT: +required "Sets the input filename to use")
            (@arg OUTPUT: +required "Sets the output filename to use")
        )
        (@subcommand decrypt =>
            (about: "decrypt file")
            (@arg INPUT: +required "Sets the input filename to use")
            (@arg OUTPUT: +required "Sets the output filename to use")
        )
    )
    .get_matches();

    // println!("matches {:#?}", matches);

    let key = get_key();

    let subcommand = matches.subcommand.unwrap();
    let input = subcommand.matches.value_of("INPUT").unwrap();
    let output = subcommand.matches.value_of("OUTPUT").unwrap();

    match &subcommand.name[..] {
        "encrypt" => do_encrypt(key, input, output),
        "decrypt" => do_decrypt(key, input, output),
        _ => panic!("unexpected subcommand"),
    }
}
