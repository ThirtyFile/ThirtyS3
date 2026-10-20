#![no_main]

use libfuzzer_sys::fuzz_target;
use thirtys3_server::chunked::Decoder;

// The framing of an `aws-chunked` body: the first two bytes choose the kind of body and the size of the pieces it arrives in, the rest is the body.
fuzz_target!(|data: &[u8]| {
    let [flags, piece, wire @ ..] = data else { return };
    let mut decoder = Decoder::new(flags & 1 == 1, flags & 2 == 2, 4096);
    for bytes in wire.chunks(usize::from(*piece).max(1)) {
        decoder.push(bytes);
        loop {
            match decoder.next_event() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return,
            }
        }
        // Nothing is held that is not a line or a chunk of the sizes allowed
        assert!(decoder.buffered() <= 4096 + 64 * 1024 + bytes.len());
    }
    let _ = decoder.finish();
});
