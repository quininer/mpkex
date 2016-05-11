#![feature(question_mark)]

extern crate rand;
extern crate crypto;

#[macro_use] mod util;

use std::collections::HashMap;
use util::xor;
pub use util::GuessFail;


/// Config(Message Number, Key Len)
#[derive(Clone, Copy, Debug)]
pub struct Config(pub usize, pub usize);

pub const CONFIG: Config = Config(1048576, 4);
const HEAD: &'static [u8] = &[b'w' ;8];


/// ```
/// use mpkex::{ MpKex, Config };
/// let alice = MpKex::new(Config(100, 2));
/// let bob = MpKex::new_empty(Config(100, 2));
///
/// let (c, bob_secret) = bob.exchange(&alice.public().unwrap()).unwrap();
/// let alice_secret = alice.exchange_from(&c).unwrap();
/// assert_eq!(alice_secret, bob_secret);
/// ```
pub struct MpKex {
    map: Option<HashMap<Vec<u8>, Vec<u8>>>,
    len: usize
}

impl MpKex {
    pub fn new(Config(num, len): Config) -> MpKex {
        let map = (0..num)
            .map(|_| (rand!(8), rand!(16)))
            .collect();
        MpKex {
            map: Some(map),
            len: len
        }
    }

    pub fn new_empty(Config(_, len): Config) -> MpKex {
        MpKex {
            map: None,
            len: len
        }
    }

    pub fn public(&self) -> Option<Vec<Vec<u8>>> {
        self.map.clone().map(|m| m.iter()
            .map(|(n, k)| util::oracle(
                &[HEAD, n, k].concat(),
                self.len
            ))
            .collect()
        )
    }

    /// Key Exchange. returns (reconciliation data, secret).
    pub fn exchange(&self, data: &[Vec<u8>]) -> Result<(Vec<u8>, Vec<u8>), GuessFail> {
        let a_key = rand!(16);
        let sample = rand!(choose data);
        debug_assert_eq!(sample.len(), 32);
        let output = util::exhaustion(sample, HEAD, self.len)?;
        let (text, b_key) = output.split_at(16);

        Ok(([&text[8..], &a_key].concat(), xor(b_key, &a_key)))
    }

    /// Key Exchange. from (reconciliation, data), return secret.
    pub fn exchange_from(&self, data: &[u8]) -> Option<Vec<u8>> {
        let (c, k) = data.split_at(8);
        self.map.clone()
            .and_then(|m| m.get(c).cloned())
            .map(|r| xor(&r, k))
    }
}
