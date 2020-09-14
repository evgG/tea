extern crate tea;

#[test]
fn test_bytes2str() {
    let arr: [u8; 6] = [88, 49, 118, 99, 115, 69];
    let s: &str = tea::bytes2str(&arr);
    assert_eq!("X1vcsE", s);
}

#[test]
fn test_str2bytes() {
    let array: &[u8] = tea::str2bytes("GUQEX19vG3csxE9");
    assert_eq!(
        [71, 85, 81, 69, 88, 49, 57, 118, 71, 51, 99, 115, 120, 69, 57],
        array
    );
}

#[test]
fn test_ascii2bytes() {
    let s: &str = "GUQEX19vG3csxE9v2";
    let v: &Vec<u8> = &vec![25, 68, 4, 95, 95, 111, 27, 119, 44, 196, 79, 111, 216];
    assert_eq!(v, &tea::ascii2bytes(s));
    //assert_eq!(s, tea::bytes2ascii(&tea::ascii2bytes(s)));
}

#[test]
fn test_bytes2blocks() {
    let bytes: &Vec<u8> = &vec![88, 49, 118, 99, 115, 69];
    let s = vec![1479636579, 1933901824];
    assert_eq!(s, tea::bytes2blocks(bytes));
}

#[test]
fn test_blocks2bytes() {
    let bytes: [u8; 6] = [88, 49, 118, 99, 115, 69];
    assert_eq!(
        &bytes,
        &tea::blocks2bytes(tea::bytes2blocks(&bytes).as_slice())[..bytes.len()]
    );
}

#[test]
fn test_digets_pad() {
    let bytes: &Vec<u8> = &vec![88, 49, 118, 99, 115, 69];
    assert_eq!(bytes.as_slice(), &tea::pad(bytes)[1..=bytes.len()]);
    assert_eq!(0, tea::pad(bytes).len() % 8);
}

#[test]
fn test_pad() {
    let bytes: &Vec<u8> = &vec![88, 49, 118, 99, 115, 69];
    assert_eq!(bytes.as_slice(), &tea::digest_pad(bytes)[1..=bytes.len()]);
    assert_eq!(0, tea::digest_pad(bytes).len() % 16);
}

#[test]
fn test_unpad() {
    let bytes: &Vec<u8> = &vec![121, 88, 49, 118, 99, 115, 69, 162];
    assert_eq!(
        &bytes[1..bytes.len() - 1],
        &tea::unpad(bytes)[..bytes.len() - 2]
    );
}

#[test]
fn test_xor_blocks() {
    let block1: &[i32; 2] = &[2048299521, 595110280];
    let block2: &[i32; 2] = &[-764348263, -554905533];
    assert_eq!([-1469683048, -40601141], tea::xor_blocks(block1, block2));
}

#[test]
fn test_tea_code() {
    let v: [i32; 2] = [2048299521, 595110280];
    let k: [i32; 4] = [-764348263, 554905533, 637549562, -283747546];
    assert_eq!([-1667003507, 826873245], tea::tea_code(&v, &k));
}

#[test]
fn test_binarydigest() {
    let v = String::from("Gloop gleep glorp glurp");
    let k = String::from("ksmZjyFSBRc3_cHLUag9zA");
    assert_eq!(
        [187179885, 2049096094, 1627188933, -792459524].to_vec(),
        tea::binarydigest(&v, &k)
    );
}

#[test]
fn test_asciidigest() {
    let s = String::from("Gloop gleep glorp glurp");
    assert_eq!(String::from("CygjbXoiuZ5g_O7F0MQG_A"), tea::asciidigest(&s));
}

#[test]
fn test_tea_decode() {
    let v: [i32; 2] = [2048299521, 595110280];
    let k: [i32; 4] = [-764348263, 554905533, 637549562, -283747546];
    assert_eq!([-1958983444, -475923215], tea::tea_decode(&v, &k));
}

#[test]
fn test_binary2ascii() {
    let v: [i32; 4] = [1234567, 7654321, 9182736, 8273645];
    let s = String::from("ABLWhwB0y7EAjB4QAH4-7Q");
    assert_eq!(s, tea::binary2ascii(&v));
}

#[test]
fn test_ascii2binary() {
    let s = String::from("GUQEX19vG3csxE9v2Vtwh");
    let v: [i32; 4] = [423887967, 1601117047, 751062895, -648318844];
    assert_eq!(v, tea::ascii2binary(&s).as_slice());
}

#[test]
fn test_encrypt_decrypt() {
    let s = String::from("GUQEX19vG3csxE9v2Vtwh");
    let key = String::from("PUFgob$*LKDF D)(F IDD&P?/");
    assert_eq!(s, tea::decrypt(&tea::encrypt(&s, &key), &key));
}
