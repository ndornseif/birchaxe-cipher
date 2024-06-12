// Copyright 2024 N. Dornseif
//
// Dual-licensed under Apache 2.0 and MIT terms.
    
//! BIRCHAXE is a 256bit feistel block cipher using 512bit keys.
//! This module contains the basic cryptographic functions.

// ------------------------TODO------------------------
// USE BLOCK SIZE CONSTANT
// ----------------------------------------------------

use sha2::{Sha512, Sha512_256, Digest};
use crate::constants;
use crate::utils::{
    xor_128bit,
    wrapping_add_128bit,
    left_rotate_128bit
};

/// Apply the S-Boxes to byte array
///
/// Takes in sixteen bytes substitute for bytes from S-Boxes
fn apply_sboxes(data: &mut [u8; 16]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = constants::SBOXES[i % 4][*byte as usize];
    }
}

// Tanspose bytes 
//
// Take in eight bytes and reorder them
fn apply_transposition(data: &mut [u8; 16]) {
    let mut transposed: [u8; 16] = [0; 16];
    transposed[0] = data[10];
    transposed[1] = data[15];
    transposed[2] = data[12];
    transposed[3] = data[5];
    transposed[4] = data[8];
    transposed[5] = data[4];
    transposed[6] = data[7];
    transposed[7] = data[14];
    transposed[8] = data[9];
    transposed[9] = data[6];
    transposed[10] = data[2];
    transposed[11] = data[13];
    transposed[12] = data[11];
    transposed[13] = data[1];
    transposed[14] = data[0];
    transposed[15] = data[3];
    *data = transposed;
}



/// Feistel round function (F function)
///
/// Uses key dependent shifts and fixed S-Boxes to achieve good avalance effect.
/// The Feistel function might be vunerable to sidde channel attacks.
fn round_function(data: [u8; 16], subkey: [u8; 16], round: usize) -> [u8; 16] {
    let mut shifts = [0u32; 16];
    // Use subkey to generate shift amounts based on the SHIFT_TABLE
    // Add mod 64 last shift value to current value to prevent same shift value
    // getting picked multiple times in a row if subkey bytes repeat.
    for (i, byte) in subkey.iter().enumerate() { 
        shifts[i] = constants::SHIFT_TABLE[*byte as usize];
        if i > 0 {
            shifts[i] = (shifts[i-1] + shifts[i]) % 64;
        }
    }
    // Genrate two versions of the data with a key dependent shift
    let mut data0 = left_rotate_128bit(data, shifts[4]);
    let mut data1 = left_rotate_128bit(data, shifts[0]);
    // Mix in round constants
    let constant0 = left_rotate_128bit(constants::ROUND_CONSTANTS[round][0], shifts[7]);
    let constant1 = left_rotate_128bit(constants::ROUND_CONSTANTS[round][1], shifts[9]);
    data0 = xor_128bit(constant0, data0);
    data1 = xor_128bit(constant1, data1);
    // Substitute bytes.
    apply_sboxes(&mut data0);
    apply_sboxes(&mut data1);
    // Transpose bytes.
    apply_transposition(&mut data0);
    apply_transposition(&mut data1);
    // Mix in round constants the other way around
    let constant0 = left_rotate_128bit(constants::ROUND_CONSTANTS[round][1], shifts[10]);
    let constant1 = left_rotate_128bit(constants::ROUND_CONSTANTS[round][0], shifts[8]);
    data0 = xor_128bit(constant0, data0);
    data1 = xor_128bit(constant1, data1);
    // Mix in subkey
    let mut mykey = left_rotate_128bit(subkey, shifts[1]);
    data0 = wrapping_add_128bit(data0, mykey);
    mykey = left_rotate_128bit(subkey, shifts[3]);
    data1 = wrapping_add_128bit(data1, mykey);
    // Pseudo-Hadamard transform
    let mut data2 = wrapping_add_128bit(data0, data1);
    let mut data3 = wrapping_add_128bit(data0, wrapping_add_128bit(data1, data1));
    // Final combination
    data2 = left_rotate_128bit(data2, shifts[6]);
    data3 = left_rotate_128bit(data3, shifts[5]);
    let result = xor_128bit(data2, data3);
    left_rotate_128bit(result, shifts[2])
}

// Perform a full feistel round
//
// Apply round function before swapping left and right
fn feistel_round(left: &mut [u8; 16], right: &mut [u8; 16], round: usize, subkey: &[u8; 16]) {
    let old_right = *right;
    *right = xor_128bit(*left, round_function(*right, *subkey, round));
    *left = old_right;
}

// Encrpyt 256bit block
//
// Perform full cipher encryption on 256bit block using 36*16bit subkey-array.
pub fn encrypt_block(plaintext: &[u8; 32], subkeys: &[[u8; 16]; 36]) -> [u8; 32] {
    let mut left: [u8; 16] = (&plaintext[0..16]).try_into().unwrap();
    let mut right: [u8; 16] = (&plaintext[16..32]).try_into().unwrap();
    // Input whitening
    left = xor_128bit(left, subkeys[32]);
    right = xor_128bit(right, subkeys[33]);
    for i in 0..constants::ROUND_COUNT {
        feistel_round(&mut left, &mut right, i, &subkeys[i]);
    }
    // Output whitening
    left = xor_128bit(left, subkeys[34]);
    right = xor_128bit(right, subkeys[35]);
    let mut result = [0u8; 32];
    result[..16].copy_from_slice(&left);
    result[16..].copy_from_slice(&right);
    result
}

// Decrypt 128bit block
//
// Perform full cipher decryption on 128bit block using 4608bit subkey-array
pub fn decrypt_block(plaintext: &[u8; 32], subkeys: &[[u8; 16]; 36]) -> [u8; 32] {
    let mut left: [u8; 16] = (&plaintext[0..16]).try_into().unwrap();
    let mut right: [u8; 16] = (&plaintext[16..32]).try_into().unwrap();
    // Undo output whitening
    left = xor_128bit(left, subkeys[34]);
    right = xor_128bit(right, subkeys[35]);
    for i in 0..constants::ROUND_COUNT {
        // Apply round keys and round constants in reverse order.
        let reverse_i: usize = (constants::ROUND_COUNT-1)-i;
        feistel_round(&mut right, &mut left, reverse_i, &subkeys[reverse_i]);
    }
    // Undo input whitening
    left = xor_128bit(left, subkeys[32]);
    right = xor_128bit(right, subkeys[33]);
    let mut result = [0u8; 32];
    result[..16].copy_from_slice(&left);
    result[16..].copy_from_slice(&right);
    result
}

/// Generate Subkeys
///
/// Expands the 512bit key to 36*16bit subkey-array using SHA-512.
pub fn subkey_generation(key: &[u8; 64]) -> [[u8; 16]; 36] {
    // Start with constant initialization vector
    let mut last_digest: [u8; 64] = constants::KDF_IV;
    let mut subkeys = [[0u8; 16]; 36];
    for key_block in subkeys.iter_mut(){
        let mut hasher = Sha512::new();
        hasher.update(*key);
        hasher.update(last_digest);
        last_digest = hasher.finalize().into();
        *key_block = (&last_digest[..16]).try_into().unwrap();
    }
    subkeys
}

/// Generate HMAC
///
/// Generates a 256bit HMAC of a vec of 256bit data blocks, and a header using 512bit key and sha512.
pub fn generate_hmac(data: &Vec<[u8; 32]>, key: &[u8; 64], header: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(*key);
    hasher.update(*header);
    for block in data.iter() {
        hasher.update(block);
    }
    let hash1: [u8; 64] = hasher.finalize().into();
    let mut hasher = Sha512_256::new();
    hasher.update(*key);
    hasher.update(hash1);
    hasher.finalize().into()
}

#[cfg(test)]
mod unit_tests {
    static TEST_KEY: [u8; 64] = [0x64, 0x54, 0x82, 0x64, 0xb3, 0x10, 0x1e, 0x0, 0x8b, 0xd8, 0xc, 0xb9, 0xf2, 0x7b, 0x8a, 0x89, 0xaa, 0x3b, 0x6d, 0x36, 0x1d, 0x47, 0x1f, 0x4d, 0xa8, 0xa6, 0x1f, 0xc2, 0x12, 0x66, 0x67, 0x7b, 0xb6, 0xf6, 0x11, 0x98, 0xad, 0x77, 0x66, 0x67, 0xbe, 0x5a, 0xbb, 0x9b, 0xef, 0xaa, 0x2a, 0x71, 0xdc, 0xad, 0x2c, 0x6a, 0xe5, 0xc8, 0x2b, 0xcf, 0xea, 0x2c, 0x9d, 0xe7, 0x1a, 0x83, 0x4a, 0xe7];
    static TEST_DATA_BLOCK: [u8; 32] = [0x80, 0xf, 0x6a, 0x56, 0x87, 0xda, 0xa4, 0xda, 0xed, 0x44, 0x47, 0xd9, 0xd1, 0x24, 0x8b, 0xff, 0x93, 0x84, 0xd8, 0xd6, 0x20, 0x4a, 0x5e, 0x27, 0x8a, 0x7b, 0x17, 0x39, 0x31, 0xeb, 0x6a, 0x3c];
    use super::*;

    #[test]
    /// Checks if the plaintext is correctly returned when encrypting and decrypting.
    fn encrypt_decrypt_block() {
        let subkeys = subkey_generation(&TEST_KEY);
        let ciphertext = encrypt_block(&TEST_DATA_BLOCK, &subkeys);
        let plaintext = decrypt_block(&ciphertext, &subkeys);
        assert_eq!(TEST_DATA_BLOCK, plaintext, "Plaintext changed after encrypting and decrypting.");
    }
    #[test]
    /// Checks if the HMAC changes when changing key, header or data.
    fn check_hmac_invalidation() {
        let mut data = Vec::new();
        data.push(TEST_DATA_BLOCK);
        let mut key = TEST_KEY;
        let mut header = [0u8; 64];
        let base_hmac = generate_hmac(&data, &key, &header);
        println!("{:?}", data);
        // Flip first bit in first block
        data[0][0] ^= 1;
        let data_diff_hmac = generate_hmac(&data, &key, &header);
        // Flip back data bit
        data[0][0] ^= 1;
        key[0] ^= 1;
        let key_diff_hmac = generate_hmac(&data, &key, &header);
        key[0] ^= 1;
        header[0] ^= 1;
        let header_diff_hmac = generate_hmac(&data, &key, &header);
        assert_ne!(base_hmac, data_diff_hmac, "HMAC unchanged after flipping data bit.");
        assert_ne!(base_hmac, key_diff_hmac, "HMAC unchanged after flipping key bit.");
        assert_ne!(base_hmac, header_diff_hmac, "HMAC unchanged after flipping header bit.");
    }
}