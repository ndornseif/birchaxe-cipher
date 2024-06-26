// Copyright 2024 N. Dornseif
//
// Dual-licensed under Apache 2.0 and MIT terms.

//! BIRCHAXE is a 256bit feistel block cipher using 512bit keys.
//! This module utility functions

use std::fmt::Write;

/// Convert u8 array to hex string
///
/// Takes in a u8 array pointer and returns hex representaiton as String.
/// Example for four zero bytes: "0x00000000"
pub fn byte_array_to_hex(data: &[u8]) -> String{
	let mut return_string = String::new();
	return_string.push_str("0x");
	for byte in data.iter() {
        write!(return_string, "{:02x}", byte).unwrap();
    }
    return_string
}

/// Perform wrapping addition on two 128bit values
///
/// Takes two 16 byte arrays and performs wrapping addition. 
pub fn wrapping_add_128bit(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let a0 = u128::from_be_bytes(a);
    let b0 = u128::from_be_bytes(b);
    a0.wrapping_add(b0).to_be_bytes()
}

/// Perform XOR on two 128bit values
///
/// Takes two 16 byte arrays and performs bitwise XOR. 
pub fn xor_128bit(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let a0 = u128::from_be_bytes(a);
    let b0 = u128::from_be_bytes(b);
    (a0 ^ b0).to_be_bytes() 
}

/// Perform XOR on two 256bit values
///
/// Takes two 32 byte arrays and performs bitwise XOR. 
pub fn xor_256bit(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Perform bit rotaion on 128bit value
///
/// Takes in a 16 byte array and a shift amount.
/// Shifts the bits in the array left as a u128.
pub fn left_rotate_128bit(a: [u8; 16], amount: u32) -> [u8; 16] {
    let a0 = u128::from_be_bytes(a);
    a0.rotate_left(amount).to_be_bytes()
}

/// Perform bit rotaion on 128bit value
///
/// Takes in a 16 byte array and a shift amount.
/// Shifts the bits in the array right as a u128.
pub fn right_rotate_128bit(a: [u8; 16], amount: u32) -> [u8; 16] {
    let a0 = u128::from_be_bytes(a);
    a0.rotate_right(amount).to_be_bytes()
}

/// Wrapping addition of 256bit byte array and u64
///
/// Perform wrapping addition between a 256bit number supplied as 32 byte array and a u64.
pub fn wrapping_add_256bit_u64(a: [u8; 32], b: u64) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry = 0u16;

    let b_bytes = b.to_le_bytes();
    for i in 0..8 {
        let sum = a[i] as u16 + b_bytes[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    // Propagate the carry to the remaining bytes
    for i in 8..32 {
        let sum = a[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    result
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    /// Test if u8 array is encoded to hex string properly.
    fn byte_array_to_hex_encoder() {
        let test_data = [0x00, 0x01, 0x02, 0x03, 0x04, 0xFC, 0xFD, 0xFE, 0xFF];
        let hex_string = byte_array_to_hex(&test_data);
        assert_eq!(hex_string, "0x0001020304fcfdfeff");
    }

    #[test]
    /// Test if wrapping_add_128bit produces expected result.
    fn test_wrapping_add_128bit() {
        const INPUT_A: [u8; 16] = [0xff; 16];;
        const INPUT_B: [u8; 16] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xee];
        let rslt = wrapping_add_128bit(INPUT_A, INPUT_B);
        assert_eq!(rslt, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xed]);
    }

    #[test]
    /// Test if xor_128bit produces expected result.
    fn test_xor_128bit() {
        const INPUT_A: [u8; 16] = [0xb5, 0x7f, 0x43, 0xf4, 0xc9, 0x7d, 0x8d, 0xf1, 0x92, 0x67, 0xbd, 0x04, 0x2f, 0x6d, 0x07, 0x94];
        const INPUT_B: [u8; 16] = [0x39, 0x63, 0x7e, 0x8f, 0x0e, 0x26, 0x79, 0x5d, 0x9b, 0x88, 0xa3, 0x45, 0x23, 0xe6, 0xe5, 0x56];
        let rslt = xor_128bit(INPUT_A, INPUT_B);
        assert_eq!(rslt, [0x8c, 0x1c, 0x3d, 0x7b, 0xc7, 0x5b, 0xf4, 0xac, 0x9, 0xef, 0x1e, 0x41, 0xc, 0x8b, 0xe2, 0xc2]);
    }

    #[test]
    /// Test if xor_256bit produces expected result.
    fn test_xor_256bit() {
        const INPUT_A: [u8; 32] = [0xb5, 0x7f, 0x43, 0xf4, 0xc9, 0x7d, 0x8d, 0xf1, 0x92, 0x67, 0xbd, 0x04, 0x2f, 0x6d, 0x07, 0x94, 0x39, 0x63, 0x7e, 0x8f, 0x0e, 0x26, 0x79, 0x5d, 0x9b, 0x88, 0xa3, 0x45, 0x23, 0xe6, 0xe5, 0x56];
        const INPUT_B: [u8; 32] = [0xa7, 0x3b, 0x22, 0x4a, 0x12, 0x26, 0x0f, 0x37, 0x60, 0xf4, 0xe7, 0x74, 0xc4, 0xd0, 0xd8, 0xc0, 0x48, 0x49, 0x81, 0xc9, 0xb7, 0xaa, 0x08, 0xec, 0xaf, 0xcc, 0xdb, 0x17, 0xdd, 0x3f, 0x0d, 0x52];
        let rslt = xor_256bit(INPUT_A, INPUT_B);
        assert_eq!(rslt, [0x12, 0x44, 0x61, 0xbe, 0xdb, 0x5b, 0x82, 0xc6, 0xf2, 0x93, 0x5a, 0x70, 0xeb, 0xbd, 0xdf, 0x54, 0x71, 0x2a, 0xff, 0x46, 0xb9, 0x8c, 0x71, 0xb1, 0x34, 0x44, 0x78, 0x52, 0xfe, 0xd9, 0xe8, 0x04]);
    }

    #[test]
    /// Test if left_rotate_128bit produces expected result.
    fn test_left_rotate_128bit() {
        const INPUT_A: [u8; 16] = [0xb5, 0x7f, 0x43, 0xf4, 0xc9, 0x7d, 0x8d, 0xf1, 0x92, 0x67, 0xbd, 0x04, 0x2f, 0x6d, 0x07, 0x94];
        let rslt = left_rotate_128bit(INPUT_A, 5);
        assert_eq!(rslt, [0xaf, 0xe8, 0x7e, 0x99, 0x2f, 0xb1, 0xbe, 0x32, 0x4c, 0xf7, 0xa0, 0x85, 0xed, 0xa0, 0xf2, 0x96]);
    }

    #[test]
    /// Test if right_rotate_128bit produces expected result.
    fn test_right_rotate_128bit() {
        const INPUT_A: [u8; 16] = [0xb5, 0x7f, 0x43, 0xf4, 0xc9, 0x7d, 0x8d, 0xf1, 0x92, 0x67, 0xbd, 0x04, 0x2f, 0x6d, 0x07, 0x94];
        let rslt = right_rotate_128bit(INPUT_A, 5);
        assert_eq!(rslt, [0xa5, 0xab, 0xfa, 0x1f, 0xa6, 0x4b, 0xec, 0x6f, 0x8c, 0x93, 0x3d, 0xe8, 0x21, 0x7b, 0x68, 0x3c]);
    }

    #[test]
    /// Test if wrapping_add_256bit_u64 produces expected result.
    fn test_wrapping_add_256bit_u64() {
        const INPUT_A: [u8; 32] = [0xff; 32];
        let rslt = wrapping_add_256bit_u64(INPUT_A, 2u64);
        assert_eq!(rslt, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}