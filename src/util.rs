use crypto::blowfish::Blowfish;
use crypto::blockmodes::CtrMode;
use crypto::symmetriccipher::SynchronousStreamCipher;


#[macro_export]
macro_rules! rand {
    ( _ ) => { ::rand::random() };
    ( $len:expr ) => {{
        use ::rand::Rng;
        ::rand::thread_rng().gen_iter().take($len).collect::<Vec<_>>()
    }};
    ( choose $range:expr, $num:expr ) => {
        ::rand::sample(&mut ::rand::thread_rng(), $range, $num)
    };
    ( choose $range:expr ) => {
        rand!(choose $range, 1)[0]
    };
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .map(|(x, y)| x ^ y)
        .collect()
}

pub fn oracle(message: &[u8], len: usize) -> Vec<u8> {
    let mut output = vec![0; message.len()];
    let mut key = rand!(len);
    let i = key.len() - 1;
    key[i] &= 128;
    let mut cipher = Blowfish::init_state();
    cipher.expand_key(&key);
    CtrMode::new(cipher, vec![0; 8])
        .process(&message, &mut output);
    output
}

#[derive(Debug, PartialEq)]
pub enum GuessFail {
    LenError
}

pub fn exhaustion(ciphertext: &[u8], plaintext: &[u8], len: usize) -> Result<Vec<u8>, GuessFail> {
    let try_pass = move |key: &[u8]| {
        let mut output = vec![0; ciphertext.len()];
        let mut cipher = Blowfish::init_state();
        cipher.expand_key(key);
        CtrMode::new(cipher, vec![0; 8])
            .process(&ciphertext, &mut output);
        if output.starts_with(plaintext) {
            Some(output)
        } else {
            None
        }
    };

    let mut key = vec![0; len];
    let i = key.len() - 1;
    let start = key.clone();
    loop {
        if key[i] <= 128 {
            if let Some(output) = try_pass(&key) {
                return Ok(output);
            } else {
                add_ctr(&mut key, 1);
            }
        } else {
            add_ctr(&mut key, 127);
        }
        if key == start { Err(GuessFail::LenError)? };
    }
}

// from rust-crypto
fn add_ctr(ctr: &mut [u8], mut ammount: u8) {
    for i in ctr.iter_mut() {
        let prev = *i;
        *i = i.wrapping_add(ammount);
        if *i >= prev {
            break;
        }
        ammount = 1;
    }
}


#[test]
fn test_exhaustion_oracle() {
    let plaintext = rand!(16);
    let ciphertext = oracle(&plaintext, 2);
    let guesstext = exhaustion(&ciphertext, &plaintext[0..8], 2);

    assert_eq!(guesstext, Ok(plaintext));
}
