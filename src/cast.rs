pub trait NarrowedCast {
    fn from_usize_narrowed(value: &usize) -> Self;
}

impl NarrowedCast for u8 {
    fn from_usize_narrowed(value: &usize) -> Self {
        let mask = match 1_usize.overflowing_shl(Self::BITS) {
            (_, ovflw) if ovflw == true => usize::MAX,
            (value, _) => value - 1_usize,
        };

        (value & mask) as Self
    }
}

impl NarrowedCast for u16 {
    fn from_usize_narrowed(value: &usize) -> Self {
        let mask = match 1_usize.overflowing_shl(Self::BITS) {
            (_, ovflw) if ovflw == true => usize::MAX,
            (value, _) => value - 1_usize,
        };

        (value & mask) as Self
    }
}

impl NarrowedCast for u32 {
    fn from_usize_narrowed(value: &usize) -> Self {
        let mask = match 1_usize.overflowing_shl(Self::BITS) {
            (_, ovflw) if ovflw == true => usize::MAX,
            (value, _) => value - 1_usize,
        };

        (value & mask) as Self
    }
}

impl NarrowedCast for u64 {
    fn from_usize_narrowed(value: &usize) -> Self {
        let mask = match 1_usize.overflowing_shl(Self::BITS) {
            (_, ovflw) if ovflw == true => usize::MAX,
            (value, _) => value - 1_usize,
        };

        (value & mask) as Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u8_narrowed_cast() {
        assert_eq!(u8::MAX, u8::from_usize_narrowed(&usize::MAX));
    }

    #[test]
    fn u16_narrowed_cast() {
        assert_eq!(u16::MAX, u16::from_usize_narrowed(&usize::MAX));
    }

    #[test]
    fn u32_narrowed_cast() {
        assert_eq!(u32::MAX, u32::from_usize_narrowed(&usize::MAX));
    }

    #[test]
    fn u64_narrowed_cast() {
        assert_eq!(u64::MAX, u64::from_usize_narrowed(&usize::MAX));
    }
}
