/*
ge25519_p3_tobytes(string, point);
ge25519_is_canonical(string);
ge25519_frombytes(point, string);
ge25519_from_uniform(H_string, r_string);

crypto_vrf_ietfdraft03_keypair_from_seed(pk, sk, seed);
ge25519_scalarmult_base(&A, sk);
ge25519_p3_tobytes(pk, &A);

ge25519_frombytes(&H_point, h_string);
ge25519_scalarmult(&Gamma_point, x_scalar, &H_point);
ge25519_scalarmult_base(&kB_point, k_scalar);
sc25519_muladd(pi+48, c_scalar, x_scalar, k_scalar);

ge25519_p3_to_cached(&tmp_point, point);
ge25519_add(&tmp2_point, point, &tmp_point);
ge25519_p1p1_to_p3(point, &tmp2_point);

ge25519_has_small_order(pk_string)

ge25519_p3
ge25519_p1p1
ge25519_cached

ge25519_sub(&tmp_p1p1_point, &tmp_p3_point, &tmp_cached_point);

void _vrf_ietfdraft03_point_to_string(unsigned char string[32],
				      const ge25519_p3 *point);

int _vrf_ietfdraft03_string_to_point(ge25519_p3 *point,
				     const unsigned char string[32]);

int _vrf_ietfdraft03_decode_proof(ge25519_p3 *Gamma, unsigned char c[16],
				  unsigned char s[32],
				  const unsigned char pi[80]);

void _vrf_ietfdraft03_hash_to_curve_elligator2_25519(unsigned char H_string[32],
						     const ge25519_p3 *Y_point,
						     const unsigned char *alpha,
						     const unsigned long long alphalen);

void _vrf_ietfdraft03_hash_points(unsigned char c[16], const ge25519_p3 *P1,
				  const ge25519_p3 *P2, const ge25519_p3 *P3,
				  const ge25519_p3 *P4);

*/

use std::fmt;
use std::error;

use rand;
use bincode;

// Borrowed from Andrew Poelstra's rust-bitcoin library
/// An iterator that returns pairs of elements
pub struct Pair<I>
    where I: Iterator
{
    iter: I,
    last_elem: Option<I::Item>
}

impl<I: Iterator> Iterator for Pair<I> {
    type Item = (I::Item, I::Item);

    #[inline]
    fn next(&mut self) -> Option<(I::Item, I::Item)> {
        let elem1 = self.iter.next();
        if elem1.is_none() {
            None
        } else {
            let elem2 = self.iter.next();
            if elem2.is_none() {
                self.last_elem = elem1;
                None
            } else {
                Some((elem1.unwrap(), elem2.unwrap()))
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.iter.size_hint() {
            (n, None) => (n/2, None),
            (n, Some(m)) => (n/2, Some(m/2))
        }
    }
}

impl<I: Iterator> Pair<I> {
    /// Returns the last element of the iterator if there were an odd
    /// number of elements remaining before it was Pair-ified.
    #[inline]
    pub fn remainder(self) -> Option<I::Item> {
        self.last_elem
    }
}

/// Returns an iterator that returns elements of the original iterator 2 at a time
pub trait Pairable : Sized + Iterator {
    /// Returns an iterator that returns elements of the original iterator 2 at a time
    fn pair(self) -> Pair<Self>;
}

impl<I: Iterator> Pairable for I {
    /// Creates an iterator that yields pairs of elements from the underlying
    /// iterator, yielding `None` when there are fewer than two elements to
    /// return.
    #[inline]
    fn pair(self) -> Pair<I> {
        Pair {iter: self, last_elem: None }
    }
}

pub fn hex_bytes(s: &str) -> Result<Vec<u8>, &'static str> {
    let mut v = vec![];
    let mut iter = s.chars().pair();
    // Do the parsing
    iter.by_ref().fold(Ok(()), |e, (f, s)| 
        if e.is_err() { e }
        else {
            match (f.to_digit(16), s.to_digit(16)) {
                (None, _) => Err("unexpected hex digit"),
                (_, None) => Err("unexpected hex digit"),
                (Some(f), Some(s)) => { v.push((f * 0x10 + s) as u8); Ok(()) }
            }
        }
    )?;
    // Check that there was no remainder
    match iter.remainder() {
        Some(_) => Err("hexstring of odd length"),
        None => Ok(v)
    }
}

/// Convert a slice of u8 to a hex string
pub fn to_hex(s: &[u8]) -> String {
    let r : Vec<String> = s.to_vec().iter().map(|b| format!("{:02x}", b)).collect();
    return r.connect("");
}

#[derive(Debug)]
pub enum Error {
    InvalidPublicKey,
    SerializationError(bincode::Error),
    DeserializationError(bincode::Error),
    InvalidDataError,
    OSRNGError(rand::Error)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidPublicKey => f.write_str(error::Error::description(self)),
            Error::SerializationError(ref e) => fmt::Display::fmt(e, f),
            Error::DeserializationError(ref e) => fmt::Display::fmt(e, f),
            Error::InvalidDataError => f.write_str(error::Error::description(self)),
            Error::OSRNGError(ref e) => fmt::Display::fmt(e, f)
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::InvalidPublicKey => None,
            Error::SerializationError(ref e) => Some(e),
            Error::DeserializationError(ref e) => Some(e),
            Error::InvalidDataError => None,
            Error::OSRNGError(ref e) => Some(e)
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::InvalidPublicKey => "Invalid public key",
            Error::SerializationError(ref e) => e.description(),
            Error::DeserializationError(ref e) => e.description(),
            Error::InvalidDataError => "No data could be found",
            Error::OSRNGError(ref e) => e.description()
        }
    }
}

// print debug statements while testing
macro_rules! test_debug {
    ($($arg:tt)*) => ({
        use std::env;
        if env::var("BLOCKSTACK_DEBUG") == Ok("1".to_string()) {
            debug!($($arg)*);
        }
    })
}

