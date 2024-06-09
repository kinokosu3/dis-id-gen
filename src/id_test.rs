use std::collections::HashSet;
use std::sync::{Arc, mpsc, Mutex};
use std::thread;

use crate::id::generate_id;

#[test]
fn test_single_threaded_unique_ids() {
    const NUM_IDS: usize = 10_000;
    let mut ids = HashSet::with_capacity(NUM_IDS);

    for _ in 0..NUM_IDS {
        let id = generate_id();
        assert!(ids.insert(id), "Duplicate ID generated in single-threaded test");
    }
}

#[test]
fn test_multi_threaded_unique_ids() {
    const NUM_THREADS: usize = 10;
    const IDS_PER_THREAD: usize = 1_000;
    const NUM_IDS: usize = NUM_THREADS * IDS_PER_THREAD;

    let (tx, rx) = mpsc::channel();
    let ids = Arc::new(Mutex::new(HashSet::with_capacity(NUM_IDS)));

    for _ in 0..NUM_THREADS {
        let tx = tx.clone();
        thread::spawn(move || {
            for _ in 0..IDS_PER_THREAD {
                let id = generate_id();
                tx.send(id).expect("Unable to send ID through channel");
            }
        });
    }

    drop(tx); // Close the sending side of the channel

    for id in rx {
        let mut ids = ids.lock().unwrap();
        assert!(ids.insert(id), "Duplicate ID generated in multi-threaded test");
    }
}