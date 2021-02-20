type ChaChaBlock = [u32; 16];

fn quaterround(x: &mut ChaChaBlock, a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

pub struct ChaChaState {
    keystream: ChaChaBlock,
    nonce_first_word: u32,
}

impl ChaChaState {
    pub fn new(key_u8: &[u8; 32], nce_u8: &[u8; 12]) -> ChaChaState {
        let constant = [
            u32::from_le_bytes(*b"expa"),
            u32::from_le_bytes(*b"nd 3"),
            u32::from_le_bytes(*b"2-by"),
            u32::from_le_bytes(*b"te k"),
        ];
        let counter = 0;

        let key = |n| u32::from_le_bytes([key_u8[n], key_u8[n + 1], key_u8[n + 2], key_u8[n + 3]]);

        let nonce =
            |n| u32::from_le_bytes([nce_u8[n], nce_u8[n + 1], nce_u8[n + 2], nce_u8[n + 3]]);

        ChaChaState {
            keystream: [
                constant[0],
                constant[1],
                constant[2],
                constant[3],
                //
                key(0 * 4),
                key(1 * 4),
                key(2 * 4),
                key(3 * 4),
                //
                key(4 * 4),
                key(5 * 4),
                key(6 * 4),
                key(7 * 4),
                //
                counter,
                nonce(0 * 4),
                nonce(1 * 4),
                nonce(2 * 4),
            ],
            nonce_first_word: nonce(0 * 4),
        }
    }

    pub fn set_counter(&mut self, counter: u64) {
        let counter = counter.to_le_bytes();
        let lower = [counter[0], counter[1], counter[2], counter[3]];
        let upper = [counter[4], counter[5], counter[6], counter[7]];
        let counter = [u32::from_le_bytes(lower), u32::from_le_bytes(upper)];

        self.keystream[12] = counter[0];
        self.keystream[13] = self.nonce_first_word + counter[1];
    }

    fn chacha_core(&self) -> ChaChaBlock {
        let mut rounded_key = (0..10).fold(self.keystream.clone(), |mut key, _| {
            // Even round
            quaterround(&mut key, 0, 4, 8, 12);
            quaterround(&mut key, 1, 5, 9, 13);
            quaterround(&mut key, 2, 6, 10, 14);
            quaterround(&mut key, 3, 7, 11, 15);
            // Odd round
            quaterround(&mut key, 0, 5, 10, 15);
            quaterround(&mut key, 1, 6, 11, 12);
            quaterround(&mut key, 2, 7, 8, 13);
            quaterround(&mut key, 3, 4, 9, 14);
            key
        });

        (0..16).for_each(|i| rounded_key[i] = rounded_key[i].wrapping_add(self.keystream[i]));

        rounded_key
    }

    fn incr_counter(&mut self) {
        self.keystream[12] = self.keystream[12].wrapping_add(1);
        if self.keystream[12] == 0 {
            self.keystream[13] = self.keystream[13].wrapping_add(1);
        }
    }

    pub fn encrypt_decrypt(&mut self, buf: &[u8], out: &mut [u8]) {
        // copy buf to out.
        assert_eq!(buf.len(), out.len());
        out.copy_from_slice(&buf);
        self.encrypt_decrypt_inplace(out);
    }

    pub fn encrypt_decrypt_inplace(&mut self, buf: &mut [u8]) {
        // do thing
        let remaining = buf;
        for chunk in remaining.chunks_mut(64) {
            let keystream = self.chacha_core();
            self.incr_counter();

            let mut chunkbytes = chunk.iter_mut();

            for keyword in &keystream {
                for keybyte in keyword.to_le_bytes().iter() {
                    let chunkbyte = chunkbytes.next();
                    if let Some(chunkbyte) = chunkbyte {
                        *chunkbyte ^= keybyte;
                    } else {
                        // no more bytes in this chunk.
                        break;
                    }
                }
            }
        }
    }
}



#[test]
fn test_core() {
    let chacha = ChaChaState::new(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        b"\0\0\0\0\0\0\0\0\0\0\0\0",
    );

    let stream_block = chacha.chacha_core();

    assert_eq!(stream_block[0], 0xade0b876);
    assert_eq!(stream_block[1], 0x903df1a0);
    assert_eq!(stream_block[2], 0xe56a5d40);
}

#[test]
fn test_encrypt() {
    let input: Vec<_> = (0..1234).map(|i| (i % 255) as u8).collect();
    let key = b"this is a key ---- this is a key";
    let nonce = b"nonce--nonce";

    println!("before:    {:?}", input);

    let mut buf = input.clone();

    {
        let mut encode_chacha = ChaChaState::new(key, nonce);
        encode_chacha.set_counter(1023);
        encode_chacha.encrypt_decrypt_inplace(&mut buf);
    }
    
    println!("encrypted: {:?}", buf);

    {
        let mut decode_chacha = ChaChaState::new(key, nonce);
        decode_chacha.set_counter(1023);
        decode_chacha.encrypt_decrypt_inplace(&mut buf);
    }

    println!("decrypted: {:?}", buf);

    for (left, right) in input.iter().zip(buf.iter()) {
        assert_eq!(left, right);
    }
}
