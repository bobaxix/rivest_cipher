use crate::cast;
use std::{cmp, convert, mem};

// Implementation of RC5 word
pub trait Rc5Word:
    cast::NarrowedCast
    + num_traits::PrimInt
    + num_traits::WrappingAdd
    + num_traits::WrappingSub
    + convert::From<u8>
{
    /// Build word from u8 slice in BigEndian order
    fn collect_word(slice: &[u8]) -> Option<Self>
    where
        Self: Sized;

    /// Unpack word into vector in BigEndian order
    fn unpack(&self) -> Vec<u8>;

    ///Returns value of first magic number
    fn pw() -> Self;

    /// Returns value of second magic number
    fn qw() -> Self;
}

impl Rc5Word for u8 {
    fn collect_word(slice: &[u8]) -> Option<Self> {
        Some(slice[0])
    }

    fn unpack(&self) -> Vec<u8> {
        vec![*self; 1]
    }

    fn pw() -> Self {
        0xB7_u8
    }

    fn qw() -> Self {
        0x9E_u8
    }
}

impl Rc5Word for u16 {
    /// ```
    /// use crate::rivest_cipher::schemes::rc5::{Rc5Word};
    /// assert_eq!(u16::collect_word([1,2].as_slice()).unwrap(), 0x0102_u16);
    /// ```
    fn collect_word(slice: &[u8]) -> Option<Self> {
        match slice.len() {
            x if x >= 2 => Some((slice[0] as u16) << 8 | slice[1] as u16),
            _ => None,
        }
    }

    /// ```
    /// use crate::rivest_cipher::schemes::rc5::{Rc5Word};
    /// assert_eq!(0x0102_u16.unpack(), vec![0x01_u8, 0x02_u8]);
    /// ```
    fn unpack(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn pw() -> Self {
        0xB7E1u16
    }

    fn qw() -> Self {
        0x9337u16
    }
}

impl Rc5Word for u32 {
    /// ```
    /// use crate::rivest_cipher::schemes::rc5::{Rc5Word};
    /// assert_eq!(u32::collect_word([1,2,3,4].as_slice()).unwrap(), 0x01020304_u32);
    /// ```
    fn collect_word(slice: &[u8]) -> Option<Self> {
        Some((u16::collect_word(slice)? as u32) << 16 | (u16::collect_word(&slice[2..4])? as u32))
    }

    /// ```
    /// use crate::rivest_cipher::schemes::rc5::{Rc5Word};
    /// assert_eq!(0x01020304_u32.unpack(), vec![0x01_u8, 0x02_u8, 0x03_u8, 0x04_u8]);
    /// ```
    fn unpack(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn pw() -> Self {
        0xB7E15163u32
    }

    fn qw() -> Self {
        0x9E3779B9u32
    }
}

impl Rc5Word for u64 {
    /// ```
    /// use crate::rivest_cipher::schemes::rc5::{Rc5Word};
    /// assert_eq!(u64::collect_word([1,2,3,4,5,6,7,8].as_slice()).unwrap(), 0x0102030405060708_u64);
    /// ```
    fn collect_word(slice: &[u8]) -> Option<Self> {
        Some((u32::collect_word(slice)? as u64) << 32 | (u32::collect_word(&slice[4..8])? as u64))
    }

    /// ```
    /// use crate::rivest_cipher::schemes::rc5::{Rc5Word};
    /// assert_eq!(0x0102030405060708_u64.unpack(), vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    /// ```
    fn unpack(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn pw() -> Self {
        0xB7E151628AED2A6Bu64
    }

    fn qw() -> Self {
        0x9E3779B97F4A7C15u64
    }
}

pub struct Rc5<T> {
    /// Number of encryption rounds
    rounds: u8,

    /// Used word size in bytes
    word_size: usize,

    /// The round subkey words
    s: Vec<T>,
}

impl<T: Rc5Word> Rc5<T> {
    /// Returns block size in bytes
    pub fn block_size(&self) -> usize {
        self.word_size * 2
    }

    /// Returns word size in bits
    pub fn word_bits(&self) -> usize {
        self.word_size * 8
    }

    pub fn is_correct_padding(&self, block: &[u8]) -> bool {
        (block.len() % self.block_size()) == 0
    }

    fn s_init(t: usize) -> Vec<T> {
        let mut s = Vec::new();

        s.push(T::pw());

        for _ in 1..t {
            s.push(s.last().unwrap().wrapping_add(&T::qw()));
        }

        s
    }

    fn l_init(word_size: usize, vector_size: usize, key: &[u8]) -> Vec<T> {
        let mut l: Vec<T> = vec![T::zero(); vector_size];
        let mut i = (key.len() - 1) as isize;

        while i >= 0 {
            let index = (i as usize) / word_size;

            l[index] = match word_size {
                1 => key[i as usize].into(),
                _ => l[index].shl(8) + key[i as usize].into(),
            };

            i = i - 1;
        }

        return l;
    }

    /// Creates new instance of encryptor
    pub fn setup(key: &[u8], rounds: u8) -> Rc5<T> {
        let word_size = mem::size_of::<T>();

        let key_size_as_words = match key.len() {
            i if i > 0 => ((cmp::max(1, i) as f64) / (word_size as f64)).ceil() as usize,
            _ => 1,
        };

        let t = 2 * (rounds as usize + 1);

        let mut l: Vec<T> = Rc5::l_init(word_size, key_size_as_words as usize, key);
        let mut s: Vec<T> = Rc5::s_init(t);

        let mut a: T = T::zero();
        let mut b: T = T::zero();

        let loops = 3 * cmp::max(t, key_size_as_words);

        let mut i = 0;
        let mut j = 0;

        for _ in 0..loops {
            a = s[i].wrapping_add(&a).wrapping_add(&b).rotate_left(3);

            let ab = a.wrapping_add(&b);
            b = l[j].wrapping_add(&ab).rotate_left(ab.to_u32().unwrap());

            s[i] = a;
            l[j] = b;

            i = (i + 1) % t;
            j = (j + 1) % key_size_as_words;
        }

        Rc5 {
            rounds,
            word_size,
            s,
        }
    }

    fn block_encrypt(&self, block: &[u8]) -> Option<(T, T)> {
        if block.len() < self.block_size() {
            return None;
        }

        let mut a = T::collect_word(block)
            .unwrap()
            .wrapping_add(self.s.first().unwrap());

        let mut b = T::collect_word(&block[self.word_size..self.block_size()])
            .unwrap()
            .wrapping_add(&self.s[1]);

        for i in 1..self.rounds + 1 {
            let index = 2 * i as usize;

            a = (a ^ b)
                .rotate_left(b.to_u32().unwrap())
                .wrapping_add(&self.s[index]);

            b = (b ^ a)
                .rotate_left(a.to_u32().unwrap())
                .wrapping_add(&self.s[index + 1]);
        }

        Some((a, b))
    }

    /// Encrypt input data.
    /// * `plaintext` - data to encrypt. His len must be multiplication of [`Rc5::block_size`], otherwise [`None`] is returned
    pub fn encrypt(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        if !self.is_correct_padding(plaintext) {
            return None;
        }

        let iter = plaintext.chunks(self.block_size());

        let mut result = Vec::<T>::with_capacity(iter.len() * 2);

        for chunk in iter {
            let (a, b) = self.block_encrypt(chunk)?;

            result.push(a);
            result.push(b);
        }

        let z = result.iter_mut().flat_map(|e| e.unpack());
        Some(z.collect())
    }

    fn block_decrypt(&self, block: &[u8]) -> Option<(T, T)> {
        if block.len() < self.block_size() {
            return None;
        }

        let mut a = T::collect_word(block)?;
        let mut b = T::collect_word(&block[self.word_size..self.block_size()])?;

        for i in (1..=(self.rounds as usize)).rev() {
            let bshift = (a % T::from_usize_narrowed(&self.word_bits())).to_u32()?;
            b = b.wrapping_sub(&self.s[2 * i + 1]).rotate_right(bshift) ^ a;

            let ashift = (b % T::from_usize_narrowed(&self.word_bits())).to_u32()?;
            a = a.wrapping_sub(&self.s[2 * i]).rotate_right(ashift) ^ b;
        }

        a = a.wrapping_sub(&self.s[0]);
        b = b.wrapping_sub(&self.s[1]);

        Some((a, b))
    }

    /// Decrypt input data.
    /// * `ciphertext` - text to decrypt. His len must be multiplication of [`Rc5::block_size`], otherwise [`None`] is returned
    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if !self.is_correct_padding(ciphertext) {
            return None;
        }

        let chunks = ciphertext.chunks(self.block_size());
        let mut result = Vec::<T>::with_capacity(chunks.len() * 2);

        for chunk in chunks.into_iter() {
            let (a, b) = self.block_decrypt(chunk)?;

            result.push(a);
            result.push(b);
        }

        let plaintext = result.into_iter().flat_map(|x| x.unpack()).collect();

        Some(plaintext)
    }
}

/// Wrapper for [Rc5::setup()]
pub fn setup<T: Rc5Word>(key: &[u8], rounds: u8) -> Rc5<T> {
    Rc5::<T>::setup(key, rounds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_encrypt_decrypt() {
        let key = (0..16).map(|_| "0").collect::<String>();
        let text = (0..16).map(|_| "0").collect::<String>();

        let cipher = Rc5::<u32>::setup(key.as_bytes(), 12);
        let ciphertext = cipher.encrypt(text.as_bytes()).unwrap();
        let plaintext = cipher.decrypt(ciphertext.as_slice()).unwrap();

        assert_eq!(text, std::str::from_utf8(plaintext.as_slice()).unwrap());
    }

    #[test]
    fn setup_test() {
        let key = [0; 16];
        let cipher = Rc5::<u32>::setup(&key, 12);

        assert_eq!(
            cipher.s,
            [
                2612779208, 439875579, 1190717637, 1175216261, 1895316362, 676037379, 1363022932,
                4129418530, 824510045, 296237661, 3559352427, 1899681837, 1266233241, 664380637,
                2811239497, 3739125530, 918565270, 2817507913, 1638370232, 990518571, 1304414838,
                2920685927, 819424010, 1125720836, 4140569649, 1694786432,
            ]
        )
    }
}
