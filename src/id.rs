use std::error::Error;
use std::sync::{Once, OnceLock};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::alphabet::Alphabet;
use base64::Engine;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use md5;
use rand::RngCore;
use rand::rngs::OsRng;
use regex::Regex;

static OBJECT_ID_COUNTER: AtomicU32 = AtomicU32::new(0);
static INIT: Once = Once::new();

fn initialize_idc_name() -> String {
    if let Ok(name) = std::env::var("OBJECT_ID_IDC") {
        validate_idc_name(&name);
        name
    } else {
        "00".to_string()
    }
}

fn get_idc_name() -> &'static String {
    static IDC_NAME: OnceLock<String> = OnceLock::new();
    IDC_NAME.get_or_init(|| initialize_idc_name())
}

fn get_process_unique() -> &'static [u8; 8] {
    static PROCESS_UNIQUE: OnceLock<[u8; 8]> = OnceLock::new();
    PROCESS_UNIQUE.get_or_init(|| initialize_process_unique())
}

fn initialize_process_unique() -> [u8; 8] {
    let hostname = hostname::get().expect("Cannot get hostname").to_string_lossy().into_owned();
    let hash = md5::compute(hostname.as_bytes());
    let mut b = [0u8; 8];
    b[0..3].copy_from_slice(&hash[0..3]);
    let mut rng = OsRng::default();
    rng.fill_bytes(&mut b[3..]);
    b
}

fn get_custom_engine() -> &'static GeneralPurpose {
    static CUSTOM_ENGINE: OnceLock<GeneralPurpose> = OnceLock::new();
    CUSTOM_ENGINE.get_or_init(|| initialize_custom_engine())
}

fn initialize_custom_engine() -> GeneralPurpose {
    let custom_alphabet = Alphabet::new("-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz").unwrap();
    GeneralPurpose::new(&custom_alphabet, GeneralPurposeConfig::new().with_encode_padding(false))
}


fn initialize() {
    INIT.call_once(|| {
        OBJECT_ID_COUNTER.store(read_random_u32(), Ordering::SeqCst);
    });
}

fn read_random_u32() -> u32 {
    let mut rng = OsRng::default();
    rng.next_u32()
}

fn validate_idc_name(name: &str) {
    let re = Regex::new(r"^[-_0-9A-Za-z]{2}$").unwrap();
    if !re.is_match(name) {
        panic!("Invalid IDC name: `{}`", name);
    }
}

fn encode(src: &[u8]) -> String {
    get_custom_engine().encode(src)
}

fn decode(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(get_custom_engine().decode(s.as_bytes())?)
}

fn set_timestamp(b: &mut [u8]) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let millis = now.as_millis() as u64;
    b[0] = ((millis >> 40) as u8) | 0x80;
    b[1] = (millis >> 32) as u8;
    b[2] = (millis >> 24) as u8;
    b[3] = (millis >> 16) as u8;
    b[4] = (millis >> 8) as u8;
    b[5] = millis as u8;
}

fn set_counter(b: &mut [u8]) {
    let i = OBJECT_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    b[0] = (i >> 24) as u8;
    b[1] = (i >> 16) as u8;
    b[2] = (i >> 8) as u8;
    b[3] = i as u8;
}

pub fn generate_id() -> String {
    initialize(); // Ensure initialization is called
    let mut b = [0u8; 18];
    set_timestamp(&mut b[0..6]);
    b[6..14].copy_from_slice(&*get_process_unique()); // 解引用 PROCESS_UNIQUE
    set_counter(&mut b[14..18]);
    format!("{}{}", encode(&b), &*get_idc_name())
}

pub fn parse_time(id: &str) -> Result<SystemTime, Box<dyn Error>> {
    let bs = to_bytes(id)?;
    let ms = ((bs[0] & 0x7F) as u64) << 40 |
        (bs[1] as u64) << 32 |
        (bs[2] as u64) << 24 |
        (bs[3] as u64) << 16 |
        (bs[4] as u64) << 8 |
        (bs[5] as u64);
    Ok(UNIX_EPOCH + std::time::Duration::from_millis(ms))
}

pub fn parse_idc(id: &str) -> String {
    if id.len() == 26 {
        return id[24..].to_string();
    }
    "".to_string()
}

fn to_bytes(id: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if id.len() != 26 {
        return Err("The provided id is not a valid objectID".into());
    }
    decode(&id[0..24])
}

pub fn is_object_id(id: &str) -> bool {
    parse_time(id).is_ok()
}
