// Copyright 2024 N. Dornseif
//
// Dual-licensed under Apache 2.0 and MIT terms.

//! BIRCHAXE is a 256bit feistel block cipher using 512bit keys.
//! This module contains constant values.

// S-Boxes choosen to ensure minimum hamming distance of two between input and ouput.
pub const SBOXES: [[u8; 256]; 4] = [[111, 61, 67, 163, 223, 205, 107, 170, 74, 209, 154, 52, 38, 94, 47, 50, 180, 18, 232, 68, 79, 64, 95, 240, 159, 168, 82, 120, 90, 97, 19, 140, 156, 66, 54, 148, 191, 201, 40, 65, 101, 26, 110, 151, 83, 230, 92, 246, 13, 78, 221, 58, 158, 236, 203, 238, 213, 32, 249, 182, 117, 30, 28, 247, 98, 253, 146, 72, 23, 33, 118, 16, 51, 199, 3, 143, 248, 228, 119, 194, 59, 24, 46, 207, 225, 231, 208, 233, 149, 178, 142, 128, 48, 210, 152, 169, 5, 220, 227, 196, 106, 214, 15, 254, 255, 85, 114, 22, 144, 241, 57, 202, 192, 175, 157, 193, 211, 186, 132, 80, 10, 37, 9, 239, 104, 133, 109, 70, 29, 251, 91, 88, 243, 139, 242, 215, 153, 164, 56, 49, 31, 131, 8, 39, 184, 222, 123, 226, 77, 166, 204, 63, 6, 235, 100, 195, 219, 162, 4, 167, 99, 55, 75, 127, 17, 113, 185, 81, 115, 43, 87, 165, 190, 250, 45, 234, 93, 76, 244, 125, 1, 137, 216, 174, 108, 160, 60, 145, 27, 20, 21, 229, 2, 134, 129, 121, 122, 147, 171, 62, 12, 0, 14, 103, 84, 71, 172, 183, 252, 237, 73, 177, 53, 218, 179, 206, 198, 35, 141, 25, 44, 102, 124, 161, 138, 173, 245, 11, 42, 189, 7, 89, 96, 187, 105, 188, 217, 86, 34, 41, 36, 176, 130, 200, 136, 126, 150, 135, 69, 112, 181, 197, 116, 212, 224, 155],
                                    [105, 247, 42, 158, 94, 165, 56, 204, 70, 49, 15, 187, 146, 140, 180, 35, 201, 254, 108, 195, 33, 185, 90, 169, 121, 48, 178, 116, 81, 135, 107, 209, 60, 83, 183, 10, 27, 229, 57, 98, 9, 130, 84, 23, 138, 68, 16, 65, 41, 248, 32, 6, 255, 164, 12, 194, 85, 227, 2, 251, 197, 170, 167, 208, 128, 243, 20, 235, 133, 111, 109, 13, 103, 88, 224, 0, 3, 30, 45, 18, 36, 87, 190, 149, 184, 239, 223, 5, 21, 151, 181, 196, 119, 64, 73, 242, 179, 137, 112, 69, 241, 199, 249, 211, 7, 221, 89, 191, 127, 52, 171, 22, 147, 218, 75, 29, 122, 203, 189, 155, 173, 25, 78, 125, 216, 38, 80, 159, 11, 28, 220, 175, 141, 198, 234, 72, 129, 79, 99, 19, 17, 104, 46, 62, 205, 226, 91, 1, 43, 200, 252, 168, 232, 134, 212, 66, 233, 76, 44, 150, 39, 153, 123, 244, 156, 174, 61, 215, 55, 110, 53, 225, 250, 161, 96, 37, 152, 50, 74, 40, 51, 160, 82, 95, 245, 117, 100, 97, 228, 230, 34, 136, 24, 14, 240, 176, 207, 182, 202, 114, 143, 92, 124, 8, 59, 132, 120, 231, 217, 93, 154, 253, 26, 144, 113, 102, 237, 186, 31, 236, 77, 86, 238, 148, 210, 188, 163, 142, 222, 115, 206, 126, 177, 162, 219, 157, 118, 214, 63, 67, 139, 246, 193, 101, 166, 54, 172, 131, 71, 47, 106, 58, 4, 145, 213, 192],
                                    [166, 189, 219, 231, 187, 32, 147, 12, 19, 249, 123, 116, 205, 55, 202, 85, 126, 91, 105, 35, 142, 254, 225, 29, 41, 163, 61, 133, 195, 200, 38, 203, 144, 16, 67, 228, 43, 191, 2, 140, 186, 162, 240, 181, 207, 161, 248, 72, 245, 25, 0, 176, 66, 132, 164, 56, 53, 234, 255, 93, 7, 175, 196, 174, 229, 87, 235, 36, 103, 47, 227, 52, 153, 15, 102, 201, 177, 192, 95, 17, 3, 141, 232, 194, 118, 122, 160, 170, 159, 4, 63, 68, 152, 209, 28, 222, 146, 217, 30, 113, 251, 112, 137, 167, 221, 206, 208, 154, 120, 158, 250, 94, 145, 45, 223, 179, 83, 70, 214, 13, 212, 78, 6, 178, 253, 69, 20, 204, 88, 96, 149, 84, 216, 97, 233, 74, 131, 98, 244, 77, 82, 18, 111, 22, 143, 34, 157, 242, 46, 101, 92, 50, 183, 128, 188, 51, 218, 109, 8, 86, 197, 10, 238, 252, 89, 130, 224, 54, 37, 21, 57, 119, 14, 64, 100, 125, 150, 139, 136, 241, 247, 246, 211, 155, 115, 44, 108, 90, 243, 190, 9, 215, 182, 99, 180, 172, 134, 79, 135, 76, 168, 121, 26, 236, 129, 1, 226, 110, 60, 75, 151, 220, 230, 199, 73, 62, 80, 127, 148, 24, 193, 23, 165, 210, 58, 65, 39, 31, 33, 107, 71, 106, 213, 40, 81, 117, 49, 5, 59, 156, 124, 173, 185, 114, 171, 48, 184, 104, 198, 42, 237, 138, 239, 11, 169, 27],
                                    [225, 62, 196, 137, 13, 144, 220, 27, 55, 241, 32, 41, 184, 14, 127, 161, 68, 92, 102, 135, 171, 46, 204, 12, 141, 254, 228, 134, 16, 4, 214, 188, 87, 158, 205, 128, 201, 243, 24, 180, 146, 212, 78, 152, 30, 232, 235, 248, 57, 208, 143, 145, 129, 82, 60, 90, 131, 104, 163, 199, 18, 22, 33, 70, 132, 202, 1, 190, 39, 120, 251, 122, 112, 198, 227, 77, 179, 200, 118, 217, 10, 97, 119, 197, 162, 49, 230, 61, 75, 11, 40, 63, 96, 35, 69, 185, 192, 28, 115, 105, 114, 181, 43, 255, 194, 150, 215, 17, 21, 234, 219, 140, 103, 154, 130, 153, 88, 38, 169, 226, 221, 80, 84, 151, 136, 83, 191, 50, 25, 121, 175, 85, 240, 26, 167, 79, 117, 244, 47, 34, 176, 216, 52, 110, 223, 94, 109, 81, 125, 59, 187, 15, 157, 147, 65, 246, 6, 0, 195, 142, 252, 44, 168, 93, 53, 98, 91, 177, 224, 238, 173, 107, 210, 2, 207, 237, 76, 203, 250, 73, 170, 231, 186, 7, 156, 89, 209, 242, 160, 174, 206, 193, 247, 64, 166, 229, 222, 67, 165, 23, 133, 56, 123, 239, 99, 74, 42, 100, 9, 236, 253, 58, 178, 3, 108, 5, 172, 155, 36, 249, 111, 183, 182, 8, 164, 213, 54, 29, 95, 66, 106, 37, 71, 189, 48, 31, 245, 149, 124, 86, 148, 159, 126, 51, 20, 138, 233, 45, 139, 211, 19, 116, 72, 218, 113, 101]];
    
// All cryptographic constants except the S-Boxes are derived from SHA-3 hashes of values from RANDs "A Million Random Digits with 100,000 Normal Deviates". 
// See python_utils/gen_round_constants.py for full procedure.

// Round contants are XORed into the block during the feistel function.
pub const ROUND_CONSTANTS: [[[u8; 16]; 2]; 32] = [[[0xb5, 0x7f, 0x43, 0xf4, 0xc9, 0x7d, 0x8d, 0xf1, 0x92, 0x67, 0xbd, 0x04, 0x2f, 0x6d, 0x07, 0x94], [0x39, 0x63, 0x7e, 0x8f, 0x0e, 0x26, 0x79, 0x5d, 0x9b, 0x88, 0xa3, 0x45, 0x23, 0xe6, 0xe5, 0x56]],
                                                [[0xa7, 0x3b, 0x22, 0x4a, 0x12, 0x26, 0x0f, 0x37, 0x60, 0xf4, 0xe7, 0x74, 0xc4, 0xd0, 0xd8, 0xc0], [0x48, 0x49, 0x81, 0xc9, 0xb7, 0xaa, 0x08, 0xec, 0xaf, 0xcc, 0xdb, 0x17, 0xdd, 0x3f, 0x0d, 0x52]],
                                                [[0x9d, 0xe4, 0x81, 0x0f, 0x26, 0xbc, 0xd2, 0x3b, 0x7e, 0x33, 0x19, 0x6d, 0x96, 0xb4, 0xbe, 0x73], [0x0f, 0xf2, 0x87, 0x90, 0x75, 0x47, 0x28, 0x38, 0xa9, 0xf9, 0x23, 0xa9, 0x8e, 0x21, 0x17, 0x05]],
                                                [[0x80, 0x22, 0x36, 0x94, 0x87, 0x8c, 0xd2, 0x1f, 0x87, 0x72, 0x84, 0x2d, 0xe1, 0x6f, 0x40, 0xea], [0xcf, 0x29, 0x49, 0x69, 0x8f, 0x6d, 0xbd, 0xd7, 0x95, 0xa6, 0x1a, 0x78, 0xd9, 0x5b, 0xcc, 0xd3]],
                                                [[0x1a, 0x37, 0x8a, 0x9e, 0x0b, 0x01, 0xeb, 0xdd, 0x0b, 0x6d, 0xb7, 0xb0, 0xe4, 0x79, 0x16, 0xaf], [0x36, 0x7b, 0xf0, 0xa1, 0xfb, 0x1b, 0xde, 0x72, 0x80, 0x5a, 0x13, 0x95, 0x08, 0xb9, 0x49, 0xde]],
                                                [[0x0b, 0xbb, 0xc8, 0x5a, 0xae, 0xd5, 0xcb, 0xf4, 0xbf, 0xb4, 0xb9, 0xcb, 0xac, 0x96, 0x48, 0x53], [0x8d, 0xdf, 0xa7, 0x64, 0xff, 0x7e, 0xcc, 0xc8, 0xd2, 0x37, 0x13, 0xb9, 0xfd, 0xd4, 0xca, 0x97]],
                                                [[0x52, 0xdd, 0x2c, 0x26, 0x5d, 0x63, 0xc0, 0x8e, 0x8a, 0x77, 0x0a, 0x94, 0xc0, 0xc8, 0xcd, 0x56], [0x58, 0x1c, 0x4b, 0xf0, 0x6d, 0x23, 0x88, 0x6c, 0xc4, 0xd2, 0xcf, 0xc8, 0xe9, 0x8f, 0x9a, 0x4e]],
                                                [[0x92, 0xec, 0xb4, 0x78, 0x65, 0x04, 0xea, 0xaa, 0xc2, 0x01, 0xe7, 0xff, 0x92, 0x70, 0x36, 0x7e], [0x1d, 0x3d, 0x47, 0x75, 0x3d, 0x54, 0xb9, 0xd5, 0x53, 0x30, 0x1b, 0x3b, 0x19, 0xc1, 0x75, 0x0a]],
                                                [[0xbc, 0x16, 0xbf, 0xf4, 0x43, 0x79, 0x38, 0xd0, 0x10, 0x17, 0x98, 0x6d, 0xdf, 0xd6, 0xbb, 0xa6], [0x30, 0x93, 0x52, 0xae, 0x2c, 0xd7, 0x27, 0x05, 0xab, 0x00, 0xb8, 0x0e, 0x2f, 0x95, 0x54, 0x86]],
                                                [[0xaa, 0xc5, 0x6b, 0x72, 0x19, 0x62, 0x2d, 0x00, 0x6f, 0x01, 0x3f, 0x51, 0x81, 0x2f, 0x65, 0x20], [0x05, 0x87, 0x37, 0xf1, 0x7c, 0xf5, 0xed, 0x72, 0x14, 0xfe, 0x24, 0xf3, 0x80, 0x84, 0x1c, 0xcb]],
                                                [[0x68, 0xd7, 0xd6, 0x6f, 0xec, 0xc2, 0xe7, 0xfe, 0x85, 0x8d, 0xa4, 0xd3, 0x8e, 0x65, 0xb8, 0x1f], [0xd2, 0xd7, 0xb4, 0x9e, 0x48, 0x2e, 0x18, 0x70, 0x48, 0x0e, 0xdf, 0x91, 0x07, 0xee, 0xf1, 0xfb]],
                                                [[0x07, 0xfd, 0x27, 0x5b, 0x27, 0x63, 0x84, 0xab, 0x8c, 0x28, 0x6f, 0xe4, 0x49, 0xef, 0x42, 0x42], [0x3c, 0xe4, 0xbe, 0x2e, 0x7e, 0xeb, 0x2f, 0x9b, 0x4a, 0x60, 0x21, 0xbf, 0x10, 0x9b, 0x49, 0x55]],
                                                [[0xd6, 0xa3, 0x71, 0xce, 0xdd, 0x6a, 0xa9, 0xd7, 0xf9, 0x9c, 0xe8, 0x2c, 0x64, 0x29, 0x11, 0x3e], [0xcf, 0xf0, 0xd6, 0x34, 0xcc, 0xdd, 0x41, 0xdb, 0x76, 0x2f, 0x16, 0xc9, 0x77, 0x19, 0xa7, 0xf7]],
                                                [[0xdc, 0x5c, 0xce, 0x5c, 0x1a, 0xb5, 0x6e, 0x68, 0x03, 0x0d, 0xe1, 0x82, 0x17, 0x15, 0xea, 0x07], [0x34, 0xab, 0x4c, 0x3a, 0xac, 0xd6, 0x3e, 0xe6, 0xfa, 0xd4, 0xad, 0x27, 0x30, 0x5c, 0xc4, 0x6b]],
                                                [[0xec, 0x61, 0xa1, 0x77, 0x6e, 0x81, 0x28, 0x72, 0xac, 0x1f, 0x88, 0x99, 0x5b, 0xf6, 0x45, 0x48], [0x79, 0x12, 0x24, 0x4c, 0xd7, 0x56, 0xac, 0x49, 0x16, 0xb9, 0x0d, 0xf8, 0xb8, 0x6a, 0xd4, 0x64]],
                                                [[0x15, 0x6e, 0xa3, 0xb1, 0xf5, 0x41, 0x48, 0x89, 0xe4, 0x17, 0xfb, 0x10, 0x7e, 0x1a, 0xa5, 0x76], [0x98, 0x8a, 0x39, 0x46, 0xc7, 0x96, 0xb0, 0xc7, 0x78, 0xf8, 0x9e, 0xe5, 0xd4, 0xc9, 0xb9, 0x12]],
                                                [[0x2c, 0xa1, 0x64, 0xcb, 0x89, 0x74, 0x56, 0x74, 0xa6, 0x81, 0xdf, 0xa4, 0x11, 0x34, 0x52, 0x4a], [0x80, 0xfa, 0xed, 0xc3, 0xb2, 0xac, 0xf4, 0x82, 0xa6, 0xbb, 0x95, 0x7f, 0xc5, 0xdc, 0xd5, 0xf6]],
                                                [[0xf1, 0x86, 0xd5, 0x51, 0x3a, 0x8d, 0x30, 0x91, 0xc8, 0x65, 0x4c, 0x69, 0xf1, 0x86, 0xbd, 0x5c], [0x13, 0x21, 0x19, 0xc0, 0x36, 0x2e, 0x70, 0xdc, 0xb9, 0xdf, 0x90, 0xea, 0x1e, 0x04, 0x02, 0x1d]],
                                                [[0x6f, 0x6c, 0xdd, 0xfe, 0xf8, 0x84, 0x8c, 0x64, 0x20, 0x27, 0x27, 0x14, 0xeb, 0x37, 0xff, 0xdf], [0xae, 0xff, 0xb5, 0x08, 0x64, 0xbd, 0x57, 0x8b, 0xe6, 0xfb, 0x0e, 0xb2, 0x0a, 0xb4, 0x0d, 0x98]],
                                                [[0x46, 0x97, 0x6f, 0x2d, 0x78, 0x65, 0xdd, 0x5d, 0xaf, 0xbf, 0xfc, 0x98, 0x07, 0x47, 0x35, 0xed], [0xac, 0xa1, 0xf2, 0x58, 0x2d, 0x12, 0xb8, 0x2c, 0x65, 0x7b, 0xd5, 0xf3, 0x66, 0xdc, 0x39, 0xd0]],
                                                [[0xc3, 0x6e, 0xb6, 0xf3, 0xf2, 0x1c, 0x14, 0xf0, 0x36, 0x1b, 0x33, 0x21, 0xff, 0x17, 0x9a, 0xbf], [0x64, 0x80, 0xc1, 0x61, 0x6d, 0x79, 0xcf, 0xe8, 0xb4, 0x41, 0xd5, 0xb7, 0x34, 0x8c, 0xf0, 0x5f]],
                                                [[0xd0, 0xdb, 0x2d, 0xfd, 0x1f, 0x24, 0xce, 0x3b, 0x95, 0xa1, 0x41, 0xbd, 0x2b, 0x46, 0x64, 0x15], [0x90, 0x89, 0xd2, 0x12, 0x91, 0xca, 0x80, 0x7e, 0x5c, 0x2b, 0x6d, 0x63, 0x5c, 0xc2, 0x6e, 0xbd]],
                                                [[0xbc, 0x46, 0x44, 0x83, 0x5c, 0x8f, 0xa9, 0x20, 0x09, 0x25, 0xae, 0x1a, 0x9e, 0xaf, 0xc0, 0x68], [0x8e, 0xe7, 0x78, 0x9b, 0xef, 0xf6, 0x40, 0xcd, 0x9f, 0x96, 0x54, 0xe4, 0xdd, 0x2d, 0x94, 0x4c]],
                                                [[0x2a, 0xcf, 0xfc, 0x3a, 0xa3, 0xe7, 0x09, 0xfd, 0x22, 0xcc, 0xc3, 0x69, 0x01, 0x13, 0x83, 0xbe], [0xbe, 0xbc, 0x60, 0x5d, 0x48, 0x8f, 0x2e, 0xa5, 0x36, 0x87, 0xa8, 0x97, 0x5b, 0x37, 0x55, 0xd3]],
                                                [[0x6b, 0x74, 0x44, 0x91, 0x02, 0x8e, 0x42, 0xf8, 0xbe, 0x40, 0x5a, 0xa3, 0x4b, 0x94, 0x69, 0x49], [0x06, 0x32, 0x72, 0xc5, 0x4a, 0x21, 0xcc, 0x05, 0x2c, 0x9b, 0x28, 0x0d, 0xed, 0xac, 0xf4, 0xe0]],
                                                [[0x8c, 0x7a, 0x88, 0x29, 0x36, 0xca, 0x2f, 0x8e, 0x1f, 0xdd, 0x20, 0xb8, 0x76, 0xa2, 0xd1, 0x44], [0x7c, 0x5f, 0x7c, 0x6e, 0x57, 0x8b, 0x48, 0x0e, 0xc7, 0xb7, 0x99, 0xa6, 0x7d, 0xdb, 0xf8, 0xc4]],
                                                [[0xd2, 0x65, 0xc8, 0xff, 0x06, 0x0e, 0x8d, 0xd0, 0xb5, 0x7f, 0xfc, 0xc2, 0x84, 0xf4, 0x1e, 0xb5], [0xa4, 0x2b, 0xb0, 0xc0, 0xe4, 0xc4, 0x8f, 0x70, 0x9a, 0x2f, 0xcd, 0x67, 0xe2, 0xb0, 0x4d, 0x98]],
                                                [[0xa2, 0x5f, 0xd5, 0xd2, 0x29, 0x87, 0x9e, 0xda, 0xf4, 0xce, 0xa3, 0xa3, 0x29, 0x29, 0x8e, 0xe5], [0x18, 0x08, 0x83, 0x0f, 0x07, 0x1c, 0x14, 0xcc, 0xc1, 0x18, 0x78, 0xe6, 0x74, 0xa1, 0x39, 0x00]],
                                                [[0x83, 0xba, 0xe4, 0xca, 0x2d, 0xd0, 0x41, 0x18, 0x01, 0xdd, 0x63, 0x1b, 0xa5, 0xa3, 0x39, 0xa4], [0xca, 0x09, 0x22, 0xf8, 0x30, 0xc6, 0x49, 0xee, 0x85, 0xc1, 0x6c, 0x09, 0xe2, 0xe1, 0x0a, 0x91]],
                                                [[0xf8, 0x3a, 0xaa, 0xa2, 0x6f, 0x8f, 0x6c, 0x4f, 0xa0, 0x6b, 0x38, 0x8d, 0x1c, 0x8f, 0x8a, 0xbd], [0x81, 0x9b, 0x32, 0xf7, 0x19, 0x66, 0x01, 0x17, 0xa1, 0xee, 0x62, 0x2c, 0x6b, 0x72, 0x87, 0x81]],
                                                [[0x88, 0xe4, 0xb7, 0x00, 0xaa, 0x6a, 0xaa, 0x08, 0x77, 0x05, 0x5c, 0xc0, 0x58, 0xa5, 0x59, 0x16], [0x8f, 0x31, 0x88, 0xf9, 0x0d, 0xca, 0x8e, 0x50, 0x60, 0xdf, 0x00, 0x82, 0x28, 0x8b, 0xae, 0x41]],
                                                [[0x4b, 0x16, 0x7b, 0x4f, 0x4f, 0x6c, 0x86, 0x64, 0x86, 0x7d, 0xbd, 0x48, 0x93, 0x0e, 0xa9, 0x23], [0x7b, 0xa7, 0x04, 0x9b, 0x13, 0x3f, 0x42, 0xaf, 0x7b, 0x3d, 0x9b, 0xc2, 0x5e, 0x7c, 0x98, 0x9e]]];

// Table used to generate key dependent shifts in feistel function.
pub const SHIFT_TABLE: [u32; 256] = [32, 14, 0, 46, 26, 23, 14, 26, 38, 20, 47, 13, 44, 58, 45, 30, 18, 20, 61, 20, 49, 8, 25, 16, 40, 35, 15, 19, 35, 31, 16, 5, 51, 47, 37, 15, 36, 22, 6, 48, 46, 38, 21, 1, 17, 4, 53, 55, 25, 29, 9, 19, 0, 57, 27, 48, 40, 4, 4, 0, 60, 43, 3, 40, 12, 37, 34, 56, 36, 16, 7, 23, 29, 25, 38, 28, 39, 30, 18, 18, 22, 21, 37, 41, 62, 59, 57, 18, 32, 37, 34, 19, 59, 2, 28, 18, 35, 14, 8, 50, 50, 54, 49, 61, 46, 2, 50, 45, 30, 28, 20, 5, 18, 42, 51, 52, 10, 63, 52, 43, 22, 13, 36, 27, 57, 26, 38, 3, 47, 32, 15, 48, 45, 31, 15, 2, 60, 29, 23, 62, 9, 25, 17, 41, 55, 42, 39, 63, 22, 32, 62, 17, 12, 14, 21, 9, 55, 18, 49, 13, 51, 34, 10, 49, 17, 14, 15, 45, 27, 1, 16, 50, 23, 21, 15, 55, 8, 11, 51, 21, 55, 18, 12, 53, 12, 52, 36, 39, 39, 47, 53, 38, 12, 55, 6, 30, 26, 62, 14, 19, 19, 26, 15, 24, 22, 21, 17, 46, 6, 2, 49, 2, 34, 60, 11, 27, 9, 14, 16, 43, 30, 29, 9, 53, 23, 30, 27, 25, 53, 38, 51, 45, 55, 57, 30, 6, 5, 43, 26, 53, 1, 1, 38, 53, 3, 55, 13, 35, 60, 23, 37, 38, 3, 26, 31, 23];

// Initialisation vector of the key derivation function.
pub const KDF_IV: [u8; 64] = [0x55, 0xa2, 0xfa, 0xa9, 0x69, 0xad, 0x87, 0xee, 0x27, 0x63, 0x7c, 0x26, 0x06, 0x0a, 0x41, 0x35, 0x81, 0x08, 0xe4, 0x5d, 0x32, 0xce, 0xa7, 0xa9, 0xba, 0x93, 0x60, 0x7f, 0xac, 0xba, 0xe5, 0x6c, 0x47, 0x8e, 0xdc, 0x9f, 0x0b, 0x63, 0x57, 0xd8, 0x73, 0x09, 0xf1, 0x9b, 0xc3, 0x23, 0x21, 0x7e, 0x3a, 0x2f, 0x6f, 0xf2, 0xb6, 0x65, 0x3e, 0x51, 0xc1, 0xca, 0xff, 0xe7, 0x4b, 0xc1, 0xff, 0x74];

// Cipher block size in bytes
// 32 bytes is the only possible value. This is only here to make clear where array lenghts ect. come from.
pub const BLOCK_SIZE: usize = 32;

// Number of feistel rounds used in the cipher
// 32 rounds is the only possible value. This is only here to make clear where array lenghts ect. come from.
pub static ROUND_COUNT: usize = 32;

