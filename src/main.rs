// Copyright 2024 N. Dornseif
//
// Dual-licensed under Apache 2.0 and MIT terms.

pub mod crypt;
pub mod constants;
pub mod filesystem;
pub mod utils;

//use crate::filesystem;

pub mod birchaxe {
    //! BIRCHAXE is a 256bit block cipher using 512bit keys.
    //! It is constructed as a Feistel cipher using fixed S-Boxes.
    //! SHA-512 is used to generate the subkeys from the main key.
    //! DO NOT USE THIS FOR ANY APPLICATIONS THAT REQUIRE SECURE ENCRYPTION.
    //! THIS CIPHER AND IMPLEMENTATION HAVE NOT BEEN SUBJECT TO THOROUGH CRYPTOANALYSIS.
    //! THERE ARE NO PROTECTIONS AGAINST SIDE CHANNEL ATTACKS IN PLACE.
}

macro_rules! time_it {
    ($tip:literal, $func:stmt) => {
        let start = std::time::Instant::now();
        $func
        println!("{}: {:?}", $tip, start.elapsed());
    };
}


fn main() {
    let mut padding: usize = 0;
    let mut read_header = [0u8; 64];
    let mut read_hmac = [0u8; 32];
    time_it!("", let _file_content = filesystem::read_cipherfile(&String::from("testfiles/img4.ppm"), &mut padding, &mut read_header, &mut read_hmac).unwrap());
}
