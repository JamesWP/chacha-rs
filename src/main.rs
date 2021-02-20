mod chacha;

use core::panic;
use std::ops::Deref;

use clap::{clap_app, SubCommand};

fn get_key() -> [u8; 32] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
}

fn get_nonce() -> [u8; 12] {
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
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
    // open writefile
    // set writefile to correct size
    // write prelude

    // write encrypted bytes

    // close files
    Ok(())
}

fn do_decrypt(
    key: [u8; 32],
    encoded_filepath: &str,
    cleartext_filepath: &str,
) -> std::io::Result<()> {
    println!("input: {:?}, output: {:?}, key:{:032x?}", encoded_filepath, cleartext_filepath, key);
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

    println!("matches {:#?}", matches);

    let key = get_key();

    let subcommand = matches.subcommand.unwrap();
    let input = subcommand.matches.value_of("INPUT").unwrap();
    let output = subcommand.matches.value_of("OUTPUT").unwrap();

    match &subcommand.name[..] {
        "encrypt" => do_encrypt(key, input, output),
        "decypt" => do_decrypt(key, input, output),
        _ => panic!("unexpected subcommand"),
    }
}
