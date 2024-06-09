use id::{generate_id, parse_idc, parse_time};

mod id;
mod id_test;

fn main() {
    let new_id = generate_id();
    println!("Generated ID: {}", new_id);
    if let Ok(time) = parse_time(&new_id) {
        println!("Parsed Time: {:?}", time);
    }
    println!("Parsed IDC: {}", parse_idc(&new_id));
}
