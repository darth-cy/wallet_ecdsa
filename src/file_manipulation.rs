use ring::digest::{Context, Digest, SHA256};
use std::fs::File;
use hex;
use std::io::{Read, BufReader, BufRead};

pub fn calculate_file_hash(path: &String) -> Result<String, ()> {
    let input = File::open(path).expect("open-file");
    let reader = BufReader::new(input);
    let digest = sha256_digest(reader)?;
    return Ok(hex::encode(digest));
}

fn sha256_digest<R: Read>(mut reader: R) -> Result<Digest, ()> {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}

pub fn get_private_key(private_key_file: &File) -> Option<String> {
    let buffered = BufReader::new(private_key_file);

    for line in buffered.lines() {
        let content = line.expect("read-line");

        if content.contains("Private Key[*]:") {
            let key = content.split("Private Key[*]:").nth(1).unwrap().trim();

            return Some(String::from(key));
        }
    }

    return None;
}

pub fn get_public_key(public_key_file: &File) -> Option<(String, String)> {
    let buffered = BufReader::new(public_key_file);

    let mut public_key_address = None;
    let mut public_key = None;

    for line in buffered.lines() {
        let content = line.expect("read-line");

        if content.contains("Address:") {
            let address = content.split("Address:").nth(1).unwrap().trim();
            public_key_address = Some(String::from(address));
        }
        if content.contains("Uncompressed Public Key:") {
            let key = content.split("Uncompressed Public Key:").nth(1).unwrap().trim();
            public_key = Some(String::from(key));
        }
    }

    if public_key_address.is_some() && public_key.is_some() {
        return Some((public_key_address.unwrap(), public_key.unwrap()));
    } else {
        return None;
    }
}

pub fn get_signature(signature_file: &File) -> Option<String> {
    let buffered = BufReader::new(signature_file);
    let mut r = String::from("");

    for line in buffered.lines() {
        let content = line.expect("read-line");
        r.push_str(&content);
    }

    return Some(r);
}
