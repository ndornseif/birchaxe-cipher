// Copyright 2024 N. Dornseif
//
// Dual-licensed under Apache 2.0 and MIT terms.

//! BIRCHAXE is a 256bit feisel block cipher using 512bit keys.
//! This module contains filesystem functions

use std::io::prelude::*;
use std::fs::File;
use std::io::{
    BufReader,
    BufWriter
};

use crate::crypt;
use crate::utils;

// The cipher ID is used to identify the version of the cipher used in a cipherfile
// Changes to implementation that cause incompatibility must also change the cipher ID 
pub static CIPHER_ID: [u8; 4] = [0x00, 0x00, 0x01, 0x00];

// The number of blocks that will be loaded into ram at a time.
pub static MAX_BLOCKS: u64 = 50_000_000;

/// Generates a crypt header
/// 
/// A crypt header is a string of bytes that give the decrypting tool info
/// Nonce, version and rounds used
fn generate_cryt_header(nonce: [u8; 32], round_count: u16) -> [u8; 64]{
    let mut header = [0u8; 64];
    header[0..4].copy_from_slice(&CIPHER_ID);
    header[4..6].copy_from_slice(&(round_count.to_le_bytes()));
    header[6..38].copy_from_slice(&nonce);
    header
}

/// Reads a crypt header
/// 
/// A crypt header is a string of bytes that give the decrypting tool info
/// Nonce, version and rounds used
fn read_cryt_header(header: [u8; 64], cipher_id: &mut [u8; 4], round_count: &mut u16, nonce: &mut [u8; 32]) {
    *cipher_id = (&header[0..4]).try_into().unwrap();
    *round_count = u16::from_le_bytes(header[4..6].try_into().unwrap());
    *nonce = (&header[6..38]).try_into().unwrap();
}

/// Read 256 byte blocks from a file
///
/// Takes in a File reader and fills vec blocks with 256bit blocks. 
/// If the file is not divisible into blocks the last block will be padded with zeros and the number of padded bytes saved in "padding".
fn read_blocks(file_reader: &mut BufReader<File>, padding: &mut usize) -> std::io::Result<Vec<[u8; 32]>> {
    let file_len_bytes = (*file_reader).get_ref().metadata()?.len() as f64;
    let file_len_blocks = (file_len_bytes / 32.0).ceil() as usize;
    let mut blocks: Vec<[u8; 32]> = Vec::with_capacity(file_len_blocks);
    let mut read_buffer = [0u8; 32];
    let mut limit_not_reached = None;
    for i in 0..MAX_BLOCKS {
        let mut bytes_read = (*file_reader).read(&mut read_buffer[..])?;
        // Reached end of file
        if bytes_read == 0{
            limit_not_reached = Some(i);
            break;
        // Last block is not long enough pad with zeros for now
        } else if bytes_read < 32 {
            *padding = 32 - bytes_read;
            // Is zero padding neccesary or can last block data be left in place?
            while bytes_read < 32{
                read_buffer[bytes_read] = 0;
                bytes_read += 1;
            }
        }
        let mut block = [0u8; 32];
        block[..].copy_from_slice(&read_buffer);
        blocks.push(block);
    }
    if limit_not_reached.is_none() {
        std::io::Error::other(format!("Trying to read more than MAX_BLOCKS: {:?} blocks into ram.", MAX_BLOCKS));
    }
    Ok(blocks)
}

/// Read in an encrypted file
///
/// Open encrypted file, read header and HMAC. Return leftover read data as 256bit blocks.
pub fn read_cipherfile(file_path: &str, padding: &mut usize, crypt_header: &mut [u8; 64], hmac: &mut [u8; 32]) -> std::io::Result<Vec<[u8; 32]>> {
    let file_i = File::open(file_path)?;
    let mut file_reader = BufReader::new(file_i);
    let mut read_buffer = [0u8; 64];
    // First 64 bytes of cipherfile are header
    let mut bytes_read = file_reader.read(&mut read_buffer[..])?;
    if bytes_read == 64 {
        *crypt_header = read_buffer;
    } else { 
        std::io::Error::other(format!("Cipherfile is to short. Cant find 64 byte header in beginning. Bytes read: {:?}", bytes_read));
    }

    // Second 32 bytes of cipherfile are HMAC
    let mut read_buffer = [0u8; 32];
    bytes_read = file_reader.read(&mut read_buffer[..])?;
    if bytes_read == 32 {
        *hmac = read_buffer;
    } else { 
        std::io::Error::other(format!("Cipherfile is to short. Cant find 32 byte HMAC after header. Bytes read: {:?}", bytes_read + 64));
    }
    Ok(read_blocks(&mut file_reader, padding)?)
}

/// Read in unencrypted file
///
/// Open a plaintext file and return read data as 256bit blocks.
pub fn read_plaintextfile(file_path: &str, padding: &mut usize) -> std::io::Result<Vec<[u8; 32]>> {
    let mut f_read = BufReader::new(File::open(file_path)?);
    Ok(read_blocks(&mut f_read, padding)?)
}

/// Verify that HMAC matches expected value
///
/// Calculate a HMAC based on data, key and header and compare to supplied expected value.
pub fn verify_hmac(expected_hmac: &[u8; 32], verify_data: &Vec<[u8; 32]>, verify_key: &[u8; 64], verify_header: &[u8; 64]) -> Result<(), String> {
    let calculated_hmac = crypt::generate_hmac(verify_data, verify_key, verify_header);
    if *expected_hmac != calculated_hmac{
        return Err(format!("HMAC mismatch! Data corrupt or manipulated. Expected: {} Calculated: {}", utils::byte_array_to_hex(expected_hmac), utils::byte_array_to_hex(&calculated_hmac)));
    }
    Ok(())
}

/// Write out 256bit blocks to a file
///
/// Takes in a vec of blocks and writes them to a file. The last block size is reduced by the number of bytes specified in "padding".
fn write_blocks(file_writer: &mut BufWriter<File>, padding: &mut usize, blocks: &Vec<[u8; 32]>) -> std::io::Result<()> {
    let mut block_sequence = blocks.iter().peekable();
    while let Some(block) = block_sequence.next() {
        // We have reached the last block so remove the padding
        if block_sequence.peek().is_none() {
            file_writer.write(&block[0..(16-*padding)])?;
        } else {
            file_writer.write(block)?;
        }
    }
    Ok(())
}

/// Write out encrypted data to file
///
/// Write header, HMAC and data bocks out to a file.
pub fn write_cipherfile(file_path: &str, blocks: &Vec<[u8; 32]>, padding: &mut usize, crypt_header: &mut [u8; 64], hmac: &mut [u8; 32]) -> std::io::Result<()> {
    let mut file_writer = BufWriter::new(File::create(file_path)?);
    // First 64 bytes of cipherfile are the header.
    file_writer.write(crypt_header)?;
    // Next 32 bytes are HMAC.
    file_writer.write(hmac)?;
    write_blocks(&mut file_writer, padding, blocks)?;
    Ok(())
}

/// Write out plaintext data to file
///
/// Write data bocks out to a file.
pub fn write_plaintextfile(file_path: &str, blocks: &Vec<[u8; 32]>, padding: &mut usize) -> std::io::Result<()> {
    let mut file_writer = BufWriter::new(File::create(file_path)?);
    write_blocks(&mut file_writer, padding, blocks)?;
    Ok(())
}


#[cfg(test)]
mod unit_tests {
    const TEST_KEY: [u8; 64] = [0x64, 0x54, 0x82, 0x64, 0xb3, 0x10, 0x1e, 0x0, 0x8b, 0xd8, 0xc, 0xb9, 0xf2, 0x7b, 0x8a, 0x89, 0xaa, 0x3b, 0x6d, 0x36, 0x1d, 0x47, 0x1f, 0x4d, 0xa8, 0xa6, 0x1f, 0xc2, 0x12, 0x66, 0x67, 0x7b, 0xb6, 0xf6, 0x11, 0x98, 0xad, 0x77, 0x66, 0x67, 0xbe, 0x5a, 0xbb, 0x9b, 0xef, 0xaa, 0x2a, 0x71, 0xdc, 0xad, 0x2c, 0x6a, 0xe5, 0xc8, 0x2b, 0xcf, 0xea, 0x2c, 0x9d, 0xe7, 0x1a, 0x83, 0x4a, 0xe7];
    // Larger than 255 to ensure that both bytes used to save the round count are properly encoded and decoded.
    const TEST_ROUNDS: u16 = 475;
    const TEST_NONCE: [u8; 32] = [44, 7, 114, 184, 174, 250, 236, 1, 211, 183, 59, 179, 138, 241, 217, 132, 22, 138, 161, 0, 109, 159, 161, 210, 39, 239, 67, 99, 144, 233, 89, 12];
    const TEST_DATA: [[u8; 32]; 2] = [[92, 84, 127, 145, 179, 94, 43, 212, 198, 159, 76, 6, 7, 221, 174, 188, 90, 136, 232, 50, 205, 163, 144, 48, 46, 191, 124, 247, 159, 213, 163, 211], [255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]];
    const TEST_HMAC: [u8; 32] = [64, 53, 189, 247, 251, 179, 114, 129, 147, 44, 1, 179, 100, 176, 102, 88, 83, 136, 114, 252, 156, 106, 4, 67, 38, 136, 226, 166, 52, 56, 75, 13];
    use super::*;

    #[test]
    /// Checks if data can be properly encoded into and decoded from a crypt header.
    fn header_encode_decode() {
        let header = generate_cryt_header(TEST_NONCE, TEST_ROUNDS);
        let mut read_id = [0u8; 4];
        let mut read_round_count = 0u16;
        let mut read_nonce = [0u8; 32];
        println!("{:?}", header);
        read_cryt_header(header, &mut read_id, &mut read_round_count, &mut read_nonce);
        assert_eq!(read_id, CIPHER_ID, "Cipher ID improperly decoded from header.");
        assert_eq!(read_round_count, TEST_ROUNDS, "Round counter improperly decoded from header.");
        assert_eq!(read_nonce, TEST_NONCE, "Nonce improperly decoded from header.");
    }

    #[test]
    // Check that test cipherfile is properly read
    // Testfile contains header and hmac as well as 32 random bytes followed by 2 0xFF bytes.
    // These should be decoded as two blocks with 30 bytes of padding.
    fn cipherfile_reading() {
        let expected_header = generate_cryt_header(TEST_NONCE, TEST_ROUNDS);
        let mut padding: usize = 0;
        let mut read_header = [0u8; 64];
        let mut read_hmac = [0u8; 32];
        let file_content = read_cipherfile(&String::from("testfiles/unit_tests/cipherfile_reading.bin"), &mut padding, &mut read_header, &mut read_hmac).unwrap();
        assert_eq!(file_content, TEST_DATA, "Test data improperly read from test file.");
        assert_eq!(padding, 30, "Padding improperly decoded from test file.");
        assert_eq!(read_header, expected_header, "Header improperly read from test file.");
        assert_eq!(read_hmac, TEST_HMAC, "HMAC improperly read from test file.");
    }

    #[test]
    // Check that test cipherfile is properly read
    // Testfile contains 32 random bytes followed by 2 0xFF bytes.
    // These should be decoded as two blocks with 30 bytes of padding.
    fn plaintextfile_reading() {
        let mut padding: usize = 0;
        let file_content = read_plaintextfile(&String::from("testfiles/unit_tests/plaintextfile_reading.bin"), &mut padding).unwrap();
        assert_eq!(padding, 30, "Padding improperly decoded from test file.");
        assert_eq!(file_content, TEST_DATA, "Test data improperly read from test file.");
    }

    #[test]
    // Check that mismatched HMACs are properly detected
    fn check_hmac_mismatch_detection() {
        // Increase round count by one to cause invalid HMAC.
        let header = generate_cryt_header(TEST_NONCE, TEST_ROUNDS+1);
        let rslt = verify_hmac(&TEST_HMAC, &TEST_DATA.to_vec(), &TEST_KEY, &header);
        assert_eq!(rslt, Err("HMAC mismatch! Data corrupt or manipulated. Expected: 0x4035bdf7fbb37281932c01b364b06658538872fc9c6a04432688e2a634384b0d Calculated: 0xd9a96972f55e4e1d3999b62692e1cb15340d50f9d99e24554bf3b06d697fc84d".to_string()));
    }
}