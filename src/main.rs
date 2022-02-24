// hex to base64
use std::collections::HashMap;
use std::ops::BitXor;

fn chal1(string: &str) -> Option<String> {
    hex::decode(string).ok().map(base64::encode)
}

fn xor<T>(xs: &[T], ys: &[T]) -> Vec<T::Output>
where
    T: BitXor<T> + Copy,
{
    xs.iter()
        .cycle()
        .zip(ys.iter().cycle())
        .take(xs.len().max(ys.len()))
        .map(|(&x, &y)| x ^ y)
        .collect()
}

// xor same length inputs together, from hex to hex
fn chal2(a: &str, b: &str) -> Option<String> {
    if let Ok(xs) = hex::decode(a) {
        if let Ok(ys) = hex::decode(b) {
            let zip = xs.iter().zip(ys.iter());
            let xored = zip.map(|(x, y)| x ^ y).collect::<Vec<_>>();
            return Some(hex::encode(xored));
        }
    }
    None
}

fn freq(c: char) -> f32 {
    match c.to_ascii_lowercase() {
        'e' => 0.111607,
        'a' => 0.084966,
        'r' => 0.075809,
        'i' => 0.075448,
        'o' => 0.071635,
        't' => 0.069509,
        'n' => 0.066544,
        's' => 0.057351,
        'l' => 0.054893,
        'c' => 0.045388,
        _ => 0.0,
    }
}

// string looks like english
fn score(string: &str) -> f32 {
    let printable = |c: char| c.is_alphanumeric() || c.is_ascii_punctuation() || c.is_whitespace();
    if string.chars().all(printable) {
        let mut counts = HashMap::<char, usize>::new();
        for c in string.chars() {
            counts.entry(c).and_modify(|n| *n += 1).or_insert(1);
        }
        let mut freqs = HashMap::<char, f32>::new();
        for (c, n) in counts {
            freqs.insert(c, (n / string.len()) as f32);
        }
        string.chars().map(|c| (freqs[&c] + freq(c)) / 2.0).sum()
    } else {
        0.0
    }
}

/// Returns (key, score, plaintext)
fn crack_single_byte_xor(string: &str) -> Option<(u8, f32, String)> {
    if let Ok(bytes) = hex::decode(string) {
        return (0..=0xff)
            .filter_map(|i| {
                String::from_utf8(xor(&bytes, &[i]))
                    .ok()
                    .map(|p| (i, score(&p), p))
            })
            .max_by(|(_, a, _), (_, b, _)| a.partial_cmp(b).unwrap());
    }
    None
}

fn chal3(string: &str) -> Option<String> {
    crack_single_byte_xor(string).map(|(_, _, s)| s.clone())
}

/// tells whether a line has been encrypted with single-byte xor
fn chal4() -> Option<String> {
    let input = include_str!("../data/4.txt");
    for line in input.lines() {
        if let Some((_, s, line)) = crack_single_byte_xor(line) {
            // println!("{}: {} {}", key, s, line);
            if s > 0.5 {
                return Some(line.clone());
            }
        }
    }
    None
}

fn chal5(plaintext: &str, key: &str) -> String {
    let xored = xor(plaintext.as_bytes(), key.as_bytes());
    hex::encode(xored)
}

fn main() {
    // println!("Hello world");
    chal4();
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_chal1() {
        assert_eq!(
            Some(String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")),
            chal1("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
        );
    }

    #[test]
    fn test_chal2() {
        assert_eq!(
            Some(String::from("746865206b696420646f6e277420706c6179")),
            chal2(
                "1c0111001f010100061a024b53535009181c",
                "686974207468652062756c6c277320657965"
            ),
        )
    }

    #[test]
    fn test_chal3() {
        assert_eq!(
            Some(String::from("Cooking MC's like a pound of bacon")),
            chal3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        );
    }

    #[test]
    fn test_chal4() {
        assert_eq!(
            Some(String::from("Now that the party is jumping\n")),
            chal4()
        )
    }

    #[test]
    fn test_chal5() {
        let expected =
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let plaintext = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
        assert_eq!(expected, chal5(plaintext, "ICE"));
    }
}
