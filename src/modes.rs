// Copyright 2024 N. Dornseif
//
// Dual-licensed under Apache 2.0 and MIT terms.

//! BIRCHAXE is a 256bit feistel block cipher using 512bit keys.
//! This module contains functions to implement encryption of lists of blocks.

// ------------------------TODO------------------------
// 
// ----------------------------------------------------

use crate::crypt;
use crate::utils;
use crate::filesystem;

/// ECB encrypt a vec of blocks
///
/// Simply encrypts as electronic code book.
/// THIS MODE IS CONSIDERED INSECURE. CONSIDER USING CTR MODE.
fn ecb_encrypt(data: &mut Vec<[u8; 32]>, subkeys: &[[u8; 16]; 36]) {
	    for block in data.iter_mut() {
        *block = crypt::encrypt_block(block, subkeys);
    }
}

/// ECB decrypt a vec of blocks
///
/// Simply decrypts as electronic code book.
/// THIS MODE IS CONSIDERED INSECURE. CONSIDER USING CTR MODE.
fn ecb_decrypt(data: &mut Vec<[u8; 32]>, subkeys: &[[u8; 16]; 36]) {
	    for block in data.iter_mut() {
        *block = crypt::decrypt_block(block, subkeys);
    }
}

/// CTR encrypt a vec of blocks
///
/// Adds the block number to the nonce and encrypts this value to generate keystream.
/// XORs data blocks with keystream.
/// Nonce needs to be random to resist chosen-plaintext attacks.
fn ctr_encrypt(data: &mut Vec<[u8; 32]>, subkeys: &[[u8; 16]; 36], nonce: &[u8; 32]) {
    for (i, block) in data.iter_mut().enumerate() {
        let crypt_block: [u8; 32] = crypt::encrypt_block(&utils::wrapping_add_256bit_u64(*nonce, i as u64), subkeys);
        *block = utils::xor_256bit(crypt_block, *block);
    }
}

/// CTR decrypt a vec of blocks
///
/// Adds the block number to the nonce and encrypts this value to generate keystream.
/// XORs data blocks with keystream.
/// Nonce needs to be random to resist chosen-plaintext attacks.
fn ctr_decrypt(data: &mut Vec<[u8; 32]>, subkeys: &[[u8; 16]; 36], nonce: &[u8; 32]) {
    for (i, block) in data.iter_mut().enumerate() {
        let crypt_block: [u8; 32] = crypt::encrypt_block(&utils::wrapping_add_256bit_u64(*nonce, i as u64), subkeys);
        *block = utils::xor_256bit(crypt_block, *block);
    }
}


#[cfg(test)]
mod unit_tests {
	static TEST_KEY: [u8; 64] = [0x64, 0x54, 0x82, 0x64, 0xb3, 0x10, 0x1e, 0x0, 0x8b, 0xd8, 0xc, 0xb9, 0xf2, 0x7b, 0x8a, 0x89, 0xaa, 0x3b, 0x6d, 0x36, 0x1d, 0x47, 0x1f, 0x4d, 0xa8, 0xa6, 0x1f, 0xc2, 0x12, 0x66, 0x67, 0x7b, 0xb6, 0xf6, 0x11, 0x98, 0xad, 0x77, 0x66, 0x67, 0xbe, 0x5a, 0xbb, 0x9b, 0xef, 0xaa, 0x2a, 0x71, 0xdc, 0xad, 0x2c, 0x6a, 0xe5, 0xc8, 0x2b, 0xcf, 0xea, 0x2c, 0x9d, 0xe7, 0x1a, 0x83, 0x4a, 0xe7];
    static TEST_DATA_BLOCK: [u8; 32] = [0x80, 0xf, 0x6a, 0x56, 0x87, 0xda, 0xa4, 0xda, 0xed, 0x44, 0x47, 0xd9, 0xd1, 0x24, 0x8b, 0xff, 0x93, 0x84, 0xd8, 0xd6, 0x20, 0x4a, 0x5e, 0x27, 0x8a, 0x7b, 0x17, 0x39, 0x31, 0xeb, 0x6a, 0x3c];
    const TEST_NONCE: [u8; 32] = [44, 7, 114, 184, 174, 250, 236, 1, 211, 183, 59, 179, 138, 241, 217, 132, 22, 138, 161, 0, 109, 159, 161, 210, 39, 239, 67, 99, 144, 233, 89, 12];

    use super::*;

	#[test]
    /// Checks if the plaintext is correctly returned when encrypting and decrypting in ECB mode.
    fn ecb_encrypt_decrypt_file() {
        const TEST_FILE_PATH: &str = "testfiles/unit_tests/ctr_encrypt_decrypt_file.bin";
        const PADDING: usize = 0;
        let mut data = Vec::new();
        data.push(TEST_DATA_BLOCK);
        let intial_data = data.clone();
        let subkeys = crypt::subkey_generation(&TEST_KEY);
        ecb_encrypt(&mut data, &subkeys);
        assert_ne!(intial_data, data, "Encryption did not modify data.");
        // Fill Nonce with zeros since its not neccesary for ECB mode.
        let writer_header = filesystem::generate_cryt_header([0u8; 32]);
        let hmac = crypt::generate_hmac(&data, &TEST_KEY, &writer_header);
        let _ = filesystem::write_cipherfile(TEST_FILE_PATH, &data, PADDING, &writer_header, &hmac);
        let mut read_padding: usize = 0;
        let mut read_header = [0u8; 64];
        let mut read_hmac = [0u8; 32];
        let mut file_content = filesystem::read_cipherfile(TEST_FILE_PATH, &mut read_padding, &mut read_header, &mut read_hmac).unwrap();
        ecb_decrypt(&mut file_content, &subkeys);
        assert_eq!(file_content, intial_data, "Test data improperly read from test file.");
        assert_eq!(read_padding, PADDING, "Padding improperly decoded from test file.");
        assert_eq!(read_header, writer_header, "Header improperly read from test file.");
        assert_eq!(read_hmac, hmac, "HMAC improperly read from test file.");
    }

    #[test]
    /// Checks if the plaintext is correctly returned when encrypting and decrypting a file in CTR mode.
    fn ctr_encrypt_decrypt_file() {
        const TEST_FILE_PATH: &str = "testfiles/unit_tests/ctr_encrypt_decrypt_file.bin";
        const PADDING: usize = 0;
        let mut data = Vec::new();
        data.push(TEST_DATA_BLOCK);
        let intial_data = data.clone();
        let subkeys = crypt::subkey_generation(&TEST_KEY);
        ctr_encrypt(&mut data, &subkeys, &TEST_NONCE);
        assert_ne!(intial_data, data, "Encryption did not modify data.");
        let writer_header = filesystem::generate_cryt_header(TEST_NONCE);
        let hmac = crypt::generate_hmac(&data, &TEST_KEY, &writer_header);
        let _ = filesystem::write_cipherfile(TEST_FILE_PATH, &data, PADDING, &writer_header, &hmac);
        let mut read_padding: usize = 0;
        let mut read_header = [0u8; 64];
        let mut read_hmac = [0u8; 32];
        let mut file_content = filesystem::read_cipherfile(TEST_FILE_PATH, &mut read_padding, &mut read_header, &mut read_hmac).unwrap();
        ctr_decrypt(&mut file_content, &subkeys, &TEST_NONCE);
        assert_eq!(file_content, intial_data, "Test data improperly read from test file.");
        assert_eq!(read_padding, PADDING, "Padding improperly decoded from test file.");
        assert_eq!(read_header, writer_header, "Header improperly read from test file.");
        assert_eq!(read_hmac, hmac, "HMAC improperly read from test file.");
    }
}