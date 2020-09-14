// Tea_js realization on rust
#![warn(clippy::pedantic)]
use rand::Rng;
use std::iter::FromIterator;
use std::str;
use std::vec::Vec;

static A2B: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn is_in_a2b(x: &char) -> bool {
    A2B.chars().any(|y| y == *x)
}

fn rand_byte() -> u8 {
    let random_number: u8 = rand::thread_rng().gen();
    random_number
}

pub fn xor_blocks(blk1: &[i32], blk2: &[i32]) -> [i32; 2] {
    // xor of two 8-byte blocks
    let blk: [i32; 2] = [blk1[0] ^ blk2[0], blk1[1] ^ blk2[1]];
    blk
}

pub fn binary2ascii(s: &[i32]) -> String {
    bytes2ascii(&blocks2bytes(s).as_slice())
}

#[allow(unused_variables)]
pub fn binarydigest(s: &str, keystr: &str) -> [i32; 4] {
    // returns 22-char ascii signature
    let key: [i32; 4] = [0x61626364, 0x62636465, 0x63646566, 0x64656667];

    // Initial Value for CBC mode = "abcdbcde". Retain for interoperability.
    let mut c0: Vec<i32> = vec![0x61626364, 0x62636465];
    let mut c1: Vec<i32> = vec![0x61626364, 0x62636465];

    let blocks = bytes2blocks(&digest_pad(&str2bytes(&s)));
    let nbl = blocks.len();

    for ibl in (0..blocks.len()).step_by(4) {
        let v0: [i32; 2] = [blocks[ibl], blocks[ibl + 1]];
        let v1: [i32; 2] = [blocks[ibl + 2], blocks[ibl + 3]];
        // cipher them XOR'd with previous stage ...
        c0 = tea_code(&xor_blocks(&v0, &c0.as_slice()), &key).to_vec();
        c1 = tea_code(&xor_blocks(&v1, &c1.as_slice()), &key).to_vec();
        // mix up the two cipher blocks with a 32-bit left rotation ...
        let swap = c0[0];
        c0[0] = c0[1];
        c0[1] = c1[0];
        c1[0] = c1[1];
        c1[1] = swap;
    }
    //vec![c0[0], c0[1], c1[0], c1[1]]
    [c0[0], c0[1], c1[0], c1[1]]
}

// Convert string to bytes string
pub fn str2bytes(normal_string: &str) -> &[u8] {
    normal_string.as_bytes() as &[u8]
}

// Convert bytes array to ascii string
pub fn bytes2str(byte_arr: &[u8]) -> &str {
    str::from_utf8(byte_arr).unwrap()
}

// converts pseudo-base64 to array of bytes
pub fn ascii2bytes(ascii_string: &str) -> Vec<u8> {
    let mut counter = 0;
    let ascii_len = ascii_string.len();
    let arr_index = 0;
    let mut arr: Vec<u8> = Vec::new();
    let mut carry;
    for ch in ascii_string.chars() {
        if is_in_a2b(&ch) {
            let ch_value: u8 = A2B.find(ch).unwrap() as u8;

            if (counter % 4) == 0 {
                let new_val: u8 = ch_value;
                arr.push(new_val << 2)
            }
            if (counter % 4) == 1 {
                carry = ch_value;
                let last_el = arr.len() - 1;
                arr[last_el] |= carry >> 4;
                carry = 0xF & carry;
                if (carry == 0) && (arr_index == (ascii_len - 1)) {
                    return arr;
                };
                arr.push(carry << 4);
            }
            if (counter % 4) == 2 {
                carry = ch_value;
                let last_el = arr.len() - 1;
                arr[last_el] |= carry >> 2;
                carry = 3 & carry;
                if (carry == 0) && (arr_index == (ascii_len - 1)) {
                    return arr;
                };
                arr.push(carry << 6);
            }
            if (counter % 4) == 3 {
                let new_val = ch_value;
                let last_el = arr.len() - 1;
                arr[last_el] |= new_val;
            }
            counter += 1;
        }
    }
    arr
}

// Converts array of bytes to pseudo-base64 ascii
pub fn bytes2ascii(bytes_list: &[u8]) -> String {
    let mut arr: Vec<char> = Vec::new();
    let mut carry: u8 = 0;

    // reads 3 bytes and produces 4 chars
    for index in 0..bytes_list.len() {
        let byte: u8 = bytes_list[index] & 0xFF;
        if (index % 3) == 0 {
            let a_ind = 63 & ((byte & 0xFF as u8) >> 2);
            arr.push(A2B.chars().nth(a_ind as usize).unwrap());
            carry = 3 & byte;
        }

        if (index % 3) == 1 {
            let a_ind = 0xF0 & (carry << 4) | (byte >> 4);
            arr.push(A2B.chars().nth(a_ind as usize).unwrap());
            carry = 0xF & bytes_list[index];
        }

        if (index % 3) == 2 {
            let a_ind = (60 & (carry << 2)) | (byte >> 6);
            let b_ind = 63 & byte;
            arr.push(A2B.chars().nth(a_ind as usize).unwrap());
            arr.push(A2B.chars().nth(b_ind as usize).unwrap());
        }

        if (index > 0) && (index % 36) == 0 {
            arr.push('\n');
        }
    }
    if (bytes_list.len() % 3) == 1 {
        let a_ind = carry << 4;
        arr.push(A2B.chars().nth(a_ind as usize).unwrap());
    }
    if (bytes_list.len() % 3) == 2 {
        let a_ind = carry << 2;
        arr.push(A2B.chars().nth(a_ind as usize).unwrap());
    }
    String::from_iter(&arr)
}

pub fn bytes2blocks(bytes_list: &[u8]) -> Vec<i32> {
    let mut blocks: Vec<i32> = Vec::new();
    let mut ibl = 0;
    let mut iby = 0;
    let nby = bytes_list.len();
    loop {
        blocks.push((0xFF & bytes_list[iby] as i32) << 24);
        iby += 1;
        if iby >= nby {
            break;
        }
        blocks[ibl] |= (0xFF & bytes_list[iby] as i32) << 16;
        iby += 1;
        if iby >= nby {
            break;
        }
        blocks[ibl] |= (0xFF & bytes_list[iby] as i32) << 8;
        iby += 1;
        if iby >= nby {
            break;
        }
        blocks[ibl] |= 0xFF & bytes_list[iby] as i32;
        iby += 1;
        if iby >= nby {
            break;
        }
        ibl += 1;
    }
    blocks
}

pub fn blocks2bytes(blocks: &[i32]) -> Vec<u8> {
    let mut bytes_list: Vec<u8> = Vec::new();

    for ibl in 0..blocks.len() {
        bytes_list.push(0xFF & (blocks[ibl] >> 24) as u8);
        bytes_list.push(0xFF & (blocks[ibl] >> 16) as u8);
        bytes_list.push(0xFF & (blocks[ibl] >> 8) as u8);
        bytes_list.push(0xFF & blocks[ibl] as u8);
    }
    bytes_list
}

pub fn digest_pad(bytearray: &[u8]) -> Vec<u8> {
    // add 1 char ('0'..'15') at front to specify no of \x00 pad chars at end
    let mut newarray: Vec<u8> = Vec::new();
    let nba = bytearray.len();
    let npads: u8 = 15 - (nba as u8 % 16);
    newarray.push(npads);

    for iba in 0..bytearray.len() {
        newarray.push(bytearray[iba]);
    }
    for _ in (0..npads).rev() {
        newarray.push(0);
    }
    newarray
}

pub fn pad(bytearray: &[u8]) -> Vec<u8> {
    // add 1 char ('0'..'7') at front to specify no of rand pad chars at end
    // unshift and push fail on Netscape 4.7 :-(
    let mut newarray: Vec<u8> = Vec::new();
    let nba = bytearray.len();
    let npads: u8 = 7 - (nba as u8 % 8);
    newarray.push((0xF8 & rand_byte()) | (7 & npads));

    for iba in 0..bytearray.len() {
        newarray.push(bytearray[iba]);
    }
    for _ in (0..npads).rev() {
        newarray.push(rand_byte());
    }
    newarray
}

pub fn unpad(bytearray: &[u8]) -> Vec<u8> {
    // remove no of pad chars at end specified by 1 char ('0'..'7') at front
    // unshift and push fail on Netscape 4.7 :-(
    let mut newarray: Vec<u8> = Vec::new();
    let npads: usize = (0x7 & bytearray[0]) as usize;
    let nba = bytearray.len() - npads;
    for val in bytearray[1..nba].iter() {
        newarray.push(*val);
    }
    newarray
}
// --- TEA stuff, translated from the Perl Tea_JS.pm see www.pjb.com.au/comp ---

pub fn asciidigest(s: &str) -> String {
    binary2ascii(&binarydigest(s, &String::from("")))
}

pub fn tea_code(v: &[i32; 2], k: &[i32; 4]) -> [i32; 2] {
    // NewTEA. 2-int (64-bit) cyphertext block in v. 4-int (128-bit) key in k.
    let mut v0: i32 = v[0];
    let mut v1: i32 = v[1];
    let mut sum: i32 = 0;
    for _ in 0..32 {
        v0 = v0.wrapping_add(
            (v1.wrapping_add((v1 << 4) ^ (0x07FFFFFF & (v1 >> 5))))
                ^ (sum.wrapping_add(k[(sum & 3) as usize])),
        );
        sum = sum.wrapping_sub(1640531527); // TEA magic number 0x9e3779b9
        v1 = v1.wrapping_add(
            (v0.wrapping_add((v0 << 4) ^ (0x07FFFFFF & (v0 >> 5))))
                ^ (sum.wrapping_add(k[((sum >> 11) & 3) as usize])),
        );
    }
    let w = [v0, v1];
    w
}

pub fn tea_decode(v: &[i32; 2], k: &[i32; 4]) -> [i32; 2] {
    // NewTEA. 2-int (64-bit) cyphertext block in v. 4-int (128-bit) key in k.
    let mut v0: i32 = v[0];
    let mut v1: i32 = v[1];
    let mut sum: i32 = -957401312; // TEA magic number 0x9e3779b9<<5
    for _ in 0..32 {
        v1 = v1.wrapping_sub(
            (v0.wrapping_add((v0 << 4) ^ (0x07FFFFFF & (v0 >> 5))))
                ^ (sum.wrapping_add(k[((sum >> 11) & 3) as usize])),
        );
        sum = sum.wrapping_add(1640531527);
        v0 = v0.wrapping_sub(
            (v1.wrapping_add((v1 << 4) ^ (0x07FFFFFF & (v1 >> 5))))
                ^ (sum.wrapping_add(k[(sum & 3) as usize])),
        );
    }
    let w = [v0, v1];
    w
}

pub fn ascii2binary(s: &str) -> Vec<i32> {
    bytes2blocks(&ascii2bytes(&s))
}

pub fn encrypt(s: &str, keystr: &str) -> String {
    // encodes with CBC (Cipher Block Chaining)
    if keystr.len() == 0 || s.len() == 0 {
        ()
    }
    let key: &[i32; 4] = &binarydigest(&keystr, &String::from(""));
    let blocks = bytes2blocks(&pad(&str2bytes(&s)));
    // Initial Value for CBC mode = "abcdbcde". Retain for interoperability.
    let mut c: Vec<i32> = vec![0x61626364, 0x62636465];
    let mut v: [i32; 2];
    let mut cblocks: Vec<i32> = vec![];
    for ibl in (0..blocks.len()).step_by(2) {
        v = [blocks[ibl], blocks[ibl + 1]];
        c = tea_code(&xor_blocks(&v, &c.as_slice()), key).to_vec();
        cblocks.push(c[0]);
        cblocks.push(c[1]);
    }
    binary2ascii(&cblocks)
}
pub fn decrypt(ascii: &str, keystr: &str) -> String {
    // decodes with CBC
    if keystr.len() == 0 || ascii.len() == 0 {
        ()
    }
    let key: &[i32; 4] = &binarydigest(&keystr, &String::from(""));
    let cblocks = ascii2binary(ascii);
    // Initial Value for CBC mode = "abcdbcde". Retain for interoperability.
    let mut lastc: [i32; 2] = [0x61626364, 0x62636465];
    let mut blocks: Vec<i32> = vec![];
    for icbl in (0..cblocks.len()).step_by(2) {
        let c: [i32; 2] = [cblocks[icbl], cblocks[icbl + 1]];
        let v: [i32; 2] = xor_blocks(&lastc, &tea_decode(&c, key));
        blocks.push(v[0]);
        blocks.push(v[1]);
        lastc = [c[0], c[1]];
    }
    bytes2str(&unpad(&blocks2bytes(&blocks))).to_string()
}
