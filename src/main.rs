#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

use std::borrow::Cow;

use openssl::{md::Md, md_ctx::MdCtx};
use rand::{distributions, thread_rng, Rng};

#[inline]
fn validate(str_digest: &str) -> bool {
    if let Some(sub) = str_digest.find("'||'").or_else(|| str_digest.find("'or'")) {
        if let Some(eval) = str_digest[sub..].chars().nth(4) {
            if eval > '0' && eval < '9' {
                return true;
            }
        }
    }
    false
}

// 87153179503375488964249572016766023268706569805029887102402011499288342510775092757977654940386142689199562616975803271832089582121260280598138107679172885818920928633840231384484533108096150415512236913966

fn main() {
    crack();
}

fn crack() {
    let mut i = 0;
    let mut buf = String::with_capacity(400);
    let mut digest = [0; 32];
    // Ascii codes for digits.
    let uniform_ascii_digits = distributions::Uniform::from(48..=57);
    // Distribution for selecting random
    let uniform_take_range = distributions::Uniform::from(1..=4);
    loop {
        if i % 10000 == 0 {
            #[cfg(debug_assertions)]
            println!("{buf}");
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
        // thread_rng()
        //     .sample_iter(uniform_ascii_digits)
        //     .take(thread_rng().sample(uniform_take_range))
        //     .filter_map(char::from_u32)
        //     .for_each(|ch| buf.push(ch));

        unsafe {
            buf.push(char::from_u32_unchecked(
                thread_rng().sample(uniform_ascii_digits),
            ));
        }

        // Calculate md5 hash
        let str_digest = openssl_str_digest(&buf, &mut digest);

        // Check if we can create the OR statement from it.
        if validate(&str_digest) {
            println!("Found! i = {i}");
            println!("Content = {buf}");
            println!("Raw md5 Hash = {str_digest}");
            return;
        }
    }
}

#[inline]
fn openssl_str_digest<'a>(buf: &str, digest: &'a mut [u8; 32]) -> Cow<'a, str> {
    let mut ctx = MdCtx::new().unwrap();
    ctx.digest_init(Md::md5()).unwrap();
    ctx.digest_update(buf.as_bytes()).unwrap();
    ctx.digest_final(digest).unwrap();

    String::from_utf8_lossy(digest)
}

#[test]
fn test_validation() {
    let buf = "129581926211651571912466741651878684928";

    let mut digest = [0; 32];
    let mut ctx = MdCtx::new().unwrap();
    ctx.digest_init(Md::md5()).unwrap();
    ctx.digest_update(buf.as_bytes()).unwrap();
    ctx.digest_final(&mut digest).unwrap();

    let str_digest = openssl_str_digest(buf, &mut digest);

    println!("{str_digest}");
    assert!(validate(&str_digest));
}
