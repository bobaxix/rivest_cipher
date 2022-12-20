use std::fmt::Display;
use std::ops::BitAnd;
use std::{cmp, convert, mem};

static FIRST_MAGIC_NUMBER: u64 = 0xB7E151628AED2A6B;
static SECOND_MAGIC_NUMBER: u64 = 0x9E3779B97F4A7C15;

use num::integer::Integer;

pub mod utils {

    pub fn get_u32_be(slice: &[u8]) -> u32 {
        (slice[0] as u32) << 24 | (slice[1] as u32) << 16 | (slice[2] as u32) << 8 | slice[3] as u32
    }
}

trait Rc5Word {
    fn collect_word(slice: &[u8]) -> Option<Self>
    where
        Self: Sized;
    fn unpack(&self) -> Vec<u8>;

    /// Returns value of first magic number
    fn pw() -> Self;

    /// Returns value of second magic number
    fn qw() -> Self;
}

impl Rc5Word for u16 {
    fn collect_word(slice: &[u8]) -> Option<Self> {
        match slice.len() {
            x if x >= 2 => Some((slice[0] as u16) << 8 | slice[1] as u16),
            _ => None,
        }
    }

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
    fn collect_word(slice: &[u8]) -> Option<Self> {
        Some((u16::collect_word(slice)? as u32) << 16 | (u16::collect_word(&slice[2..4])? as u32))
    }

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
    fn collect_word(slice: &[u8]) -> Option<Self> {
        Some((u32::collect_word(slice)? as u64) << 32 | (u32::collect_word(&slice[4..8])? as u64))
    }

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

trait Rc5Padding {
    fn add_padding_zeros(&self, word_size: &usize) -> Option<Vec<u8>>;
}

impl Rc5Padding for [u8] {
    fn add_padding_zeros(&self, block_size: &usize) -> Option<Vec<u8>> {
        let padding_zeros = (*block_size as isize) - (self.len() as isize);

        match padding_zeros {
            x if x < 0 => None,
            0 => Some(self.to_vec()),
            _ => Some([self.to_vec(), vec![0; padding_zeros as usize]].concat()),
        }
    }
}

struct Rc5<T> {
    rounds: u8,

    /// The round subkey words
    s: Vec<T>,
}

trait Convert {
    fn from_u64(val: u64) -> Self;
}

impl Convert for u16 {
    fn from_u64(val: u64) -> Self {
        u16::try_from(val.bitand(u16::MAX as u64)).unwrap()
    }
}

impl Convert for u32 {
    fn from_u64(val: u64) -> Self {
        u32::try_from(val.bitand(u32::MAX as u64)).unwrap()
    }
}

impl<
        T: Rc5Word
            + convert::From<u8>
            + Convert
            + Display
            + num_traits::WrappingShl
            + num_traits::WrappingAdd
            + num_traits::Zero
            + num_traits::PrimInt
            + num_traits::Unsigned
            + num_traits::Bounded,
    > Rc5<T>
{
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
            let value = (l[index] << 8) + key[i as usize].into();
            l[index] = value;

            i = i - 1;
        }

        return l;
    }

    fn setup(key: &[u8], rounds: u8) -> Rc5<T> {
        let word_size = mem::size_of::<T>();

        let key_size_as_words = match key.len() {
            i if i > 0 => ((cmp::max(1, i) as f64) / (word_size as f64)).ceil() as usize,
            _ => 1,
        };

        let t = 2 * (rounds as usize + 1);

        let mut l: Vec<T> = Rc5::l_init(word_size, key_size_as_words as usize, key);
        let mut s: Vec<T> = Rc5::s_init(t);

        let mut A: T = T::zero();
        let mut B: T = T::zero();

        let loops = 3 * cmp::max(t, key_size_as_words);

        let mut i = 0;
        let mut j = 0;

        for _ in 0..loops {
            A = s[i].wrapping_add(&A).wrapping_add(&B).rotate_left(3);

            let ab = A.wrapping_add(&B);
            B = l[j].wrapping_add(&ab).rotate_left(ab.to_u32().unwrap());

            s[i] = A;
            l[j] = B;

            i = (i + 1) % t;
            j = (j + 1) % key_size_as_words;
        }

        Rc5 { rounds, s }
    }

    fn encrypt(self, plaintext: &[u8]) -> Vec<u8> {
        let size_of = mem::size_of::<T>();
        let chunk_size = size_of * 2;

        let iter = plaintext.chunks(2 * size_of);

        let mut result = Vec::<T>::with_capacity(iter.len() * 2);

        for chunk in iter {
            let bytesx = match chunk.len() {
                x if x == chunk_size => chunk.to_vec(),
                _ => chunk.add_padding_zeros(&chunk_size).unwrap(),
            };

            let bytes = bytesx.as_slice();

            let mut A = T::collect_word(bytes)
                .unwrap()
                .wrapping_add(self.s.first().unwrap());

            let mut B = T::collect_word(&bytes[size_of..2 * size_of])
                .unwrap()
                .wrapping_add(&self.s[1]);

            for i in 1..self.rounds + 1 {
                let index = 2 * i as usize;
                A = (A ^ B)
                    .rotate_left(B.to_u32().unwrap())
                    .wrapping_add(&self.s[index]);
                B = (B ^ A)
                    .rotate_left(A.to_u32().unwrap())
                    .wrapping_add(&self.s[index + 1]);
            }

            result.push(A);
            result.push(B);
        }

        let z = result.iter_mut().flat_map(|e| e.unpack());
        z.collect()

        // return vec![0; 2];
    }
    // fn rotate_left(&self)
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;

    #[test]
    fn valid_word_size() {
        let key = [0; 16];
        let text = [0; 8];

        let cipher = Rc5::<u32>::setup(&key, 12);
        let ciphertext = cipher.encrypt(&text);

        assert_eq!(
            ciphertext.as_slice(),
            [0xEE, 0xDB, 0xA5, 0x21, 0x6D, 0x8F, 0x4B, 0x15 /*21*/]
        )
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

    // #[test]
    // fn casting_Test() {
    //     assert_eq!(u16::from(MagicNumber{value: 0x10000 as u64}), 0)
    // }
    // #[test]
    // fn dummy() {
    //     let x = Rc5::new(16).unwrap();
    //     x.setup(vec![1, 2, 3, 4])
    // }
}
