// hex to base64
use std::collections::HashMap;
use std::ops::BitXor;

fn uncurry<A, B, C>(f: fn(A, B) -> C) -> impl Fn((&A, &B)) -> C
where
    A: Copy,
    B: Copy,
{
    move |(&x, &y)| f(x, y)
}

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
        .map(uncurry(BitXor::bitxor))
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
        _ => 0.0,
    }
}

// string looks like english
fn score(string: &str) -> f32 {
    let printable = |c: char| c.is_alphanumeric() || c.is_ascii_punctuation() || c == ' ';
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

fn chal3(string: &str) {
    if let Ok(bytes) = hex::decode(string) {
        let s = (0..=0xff)
            .filter_map(|i| String::from_utf8(xor(&bytes, &[i])).ok())
            .max_by(|a, b| score(a).partial_cmp(&score(b)).unwrap())
            .unwrap();
        println!("{}: {}", score(&s), s);
    }
}

fn main() {
    chal3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
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
    fn test_chal3() {}
}
