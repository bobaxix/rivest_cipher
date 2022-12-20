# Rivest cipher

Simple Rust module with Rivest Cipher implementation.

## Implemented schemes
- [ ] RC2
- [X] RC5 (RC5/8 RC5/16 RC5/32 RC5/64)
- [ ] RC6

## Usage
### Installation 
`cargo add rivest_cipher`

### Example
```rust
use rivest_cipher::schemes::rc5;

let key: [u8; 64] = { ... };
let plaintext: [u8; 16] = { ... };

let encryptor: Rc5<u32> = rc5::setup::<u32>(&key, 12);
let ciphertext: Vec<u8> = encryptor.encrypt(&plaintext).unwrap();

assert_eq!(plaintext.as_slice(), encryptor.decrypt(&ciphertext).unwrap().as_slice());
```



