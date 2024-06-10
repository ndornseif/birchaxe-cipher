// Copyright 2024 N. Dornseif
//
// Dual-licensed under Apache 2.0 and MIT terms.

//! BIRCHAXE is a 256bit block cipher using 512bit keys.
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
}