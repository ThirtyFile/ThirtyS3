//! The checksum algorithms, against values worked out with other implementations and the sample in AWS's documentation.

use thirtys3_core::checksum::{ChecksumAlgorithm, Hashers, base64_encode, combine_crc, composite_checksum_value, composite_digest};

use ChecksumAlgorithm::*;

#[test]
fn known_values_of_abc_and_the_check_string() {
    // "123456789" is the check string of the CRC catalogue: 0xCBF43926, 0xE3069283 and 0xAE8B14860A799888.
    assert_eq!(Crc32.checksum_base64(b"123456789"), "y/Q5Jg==");
    assert_eq!(Crc32c.checksum_base64(b"123456789"), "4waSgw==");
    assert_eq!(Crc64Nvme.checksum_base64(b"123456789"), "rosUhgp5mIg=");
    assert_eq!(Sha1.checksum_base64(b"abc"), "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=");
    assert_eq!(Sha256.checksum_base64(b"abc"), "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
    assert_eq!(Sha512.checksum_base64(b"abc"), "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw==");
    assert_eq!(Md5.checksum_base64(b"abc"), "kAFQmDzST7DWlj99KOF/cg==");
}

#[test]
fn the_xxhash_values_of_nothing_are_the_published_ones() {
    // The reference values of the xxHash project for empty input, with seed 0.
    let hex = |algorithm: ChecksumAlgorithm| {
        let mut hasher = algorithm.hasher();
        hasher.update(b"");
        hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect::<String>()
    };
    assert_eq!(hex(Xxhash64), "ef46db3751d8e999");
    assert_eq!(hex(Xxhash3), "2d06800538d394c2");
    assert_eq!(hex(Xxhash128), "99aa06d3014798d86001c324468d497f");
}

#[test]
fn the_documentation_sample_trailing_checksum() {
    // In the trailing-checksum example the object is 66,560 bytes of 'a' and its CRC32C is given as sOO8/Q==.
    assert_eq!(Crc32c.checksum_base64(&vec![b'a'; 66560]), "sOO8/Q==");
}

#[test]
fn streaming_in_pieces_gives_the_same_as_all_at_once() {
    let data: Vec<u8> = (0..100_000_u32).map(|i| (i * 31 + i / 7) as u8).collect();
    for algorithm in ChecksumAlgorithm::ALL {
        let whole = algorithm.checksum_base64(&data);
        for piece in [1, 7, 4096, 65_537] {
            let mut hasher = algorithm.hasher();
            for chunk in data.chunks(piece) {
                hasher.update(chunk);
            }
            assert_eq!(hasher.finalize_base64(), whole, "{algorithm:?} in pieces of {piece}");
        }
    }
}

#[test]
fn reading_the_digest_does_not_end_the_hash() {
    for algorithm in ChecksumAlgorithm::ALL {
        let mut hasher = algorithm.hasher();
        hasher.update(b"abc");
        let first = hasher.finalize_base64();
        assert_eq!(hasher.finalize_base64(), first);
        hasher.update(b"def");
        assert_eq!(hasher.finalize_base64(), algorithm.checksum_base64(b"abcdef"), "{algorithm:?}");
    }
}

#[test]
fn every_digest_has_the_length_of_its_algorithm() {
    for algorithm in ChecksumAlgorithm::ALL {
        assert_eq!(algorithm.hasher().finalize().len(), algorithm.digest_len(), "{algorithm:?}");
        let value = algorithm.checksum_base64(b"x");
        assert_eq!(algorithm.decode_value(&value).map(|digest| digest.len()), Some(algorithm.digest_len()));
        assert_eq!(algorithm.hasher().algorithm(), algorithm);
    }
}

#[test]
fn a_value_of_the_wrong_length_or_not_base64_is_refused() {
    assert!(Crc32.decode_value("y/Q5Jg==").is_some());
    assert!(Crc32.decode_value("rosUhgp5mIg=").is_none()); // that is a CRC64
    assert!(Sha256.decode_value("y/Q5Jg==").is_none());
    assert!(Crc32.decode_value("y/Q5Jg").is_none()); // padding missing
    assert!(Crc32.decode_value("not base64!").is_none());
    assert!(Crc32.decode_value("").is_none());
}

#[test]
fn names_headers_and_elements_map_both_ways() {
    for algorithm in ChecksumAlgorithm::ALL {
        assert_eq!(ChecksumAlgorithm::from_name(algorithm.name()), Some(algorithm));
        assert_eq!(ChecksumAlgorithm::from_name(&algorithm.name().to_lowercase()), Some(algorithm));
        assert_eq!(ChecksumAlgorithm::from_header_name(algorithm.header_name()), Some(algorithm));
        assert_eq!(ChecksumAlgorithm::from_header_name(&algorithm.header_name().to_uppercase()), Some(algorithm));
        assert_eq!(ChecksumAlgorithm::from_xml_element(algorithm.xml_element()), Some(algorithm));
        assert_eq!(algorithm.header_name(), format!("x-amz-checksum-{}", algorithm.name().to_lowercase()));
        assert_eq!(algorithm.xml_element(), format!("Checksum{}", algorithm.name()));
    }
    assert_eq!(ChecksumAlgorithm::ALL.len(), 10);
    assert_eq!(ChecksumAlgorithm::from_name("CRC16"), None);
    assert_eq!(ChecksumAlgorithm::from_header_name("x-amz-checksum-algorithm"), None);
    assert_eq!(ChecksumAlgorithm::from_xml_element("ChecksumType"), None);
}

#[test]
fn only_the_crcs_have_full_object_checksums() {
    let full: Vec<_> = ChecksumAlgorithm::ALL.into_iter().filter(|algorithm| algorithm.supports_full_object()).collect();
    assert_eq!(full, [Crc32, Crc32c, Crc64Nvme]);
}

#[test]
fn several_hashers_share_one_pass_and_a_repeated_algorithm_counts_once() {
    let mut hashers = Hashers::new([Sha256, Crc32, Sha256, Md5]);
    hashers.update(b"ab");
    hashers.update(b"c");
    let sums = hashers.finalize_base64();
    assert_eq!(sums.len(), 3);
    for (algorithm, value) in sums {
        assert_eq!(value, algorithm.checksum_base64(b"abc"));
    }
    assert!(Hashers::new([]).finalize_base64().is_empty());
}

#[test]
fn a_composite_checksum_is_the_checksum_of_the_part_checksums() {
    let parts = [b"aaaaa".as_slice(), b"bbbbb", b"c"];
    let digests: Vec<Vec<u8>> = parts
        .iter()
        .map(|part| {
            let mut hasher = Sha256.hasher();
            hasher.update(part);
            hasher.finalize()
        })
        .collect();
    // Worked out with another implementation.
    assert_eq!(base64_encode(&digests[0]), "7ZaOhA0Q0tMTqHC8ExpOLDEdetCb3zKzQYFHIh9RpuI=");
    assert_eq!(base64_encode(&composite_digest(Sha256, &digests)), "0W2c7p+6tw5AoTujakVNsyvPh5crkL2ks8MamfEouu0=");
    assert_eq!(composite_checksum_value(Sha256, &digests), "0W2c7p+6tw5AoTujakVNsyvPh5crkL2ks8MamfEouu0=-3");
    // Another order is another checksum.
    let swapped = [digests[1].clone(), digests[0].clone(), digests[2].clone()];
    assert_ne!(composite_digest(Sha256, &swapped), composite_digest(Sha256, &digests));
}

#[test]
fn the_full_object_crc_is_worked_out_from_the_crcs_of_the_parts() {
    let object = [b"aaaaa".as_slice(), b"bbbbb", b"c"].concat();
    for algorithm in [Crc32, Crc32c, Crc64Nvme] {
        let mut parts = Vec::new();
        for part in [b"aaaaa".as_slice(), b"bbbbb", b"c"] {
            let mut hasher = algorithm.hasher();
            hasher.update(part);
            parts.push((hasher.finalize(), part.len() as u64));
        }
        let combined = combine_crc(algorithm, &parts).unwrap();
        assert_eq!(base64_encode(&combined), algorithm.checksum_base64(&object), "{algorithm:?}");
    }
    // The value worked out with zlib for CRC32.
    assert_eq!(Crc32.checksum_base64(&object), "QaJ2tA==");
}

#[test]
fn combining_refuses_what_is_not_a_crc_or_not_the_right_size() {
    assert_eq!(combine_crc(Sha256, &[(vec![0; 32], 1)]), None);
    assert_eq!(combine_crc(Crc32, &[(vec![0; 8], 1)]), None);
    assert_eq!(combine_crc(Crc32, &[]), None);
    let one = Crc32.hasher().finalize();
    assert_eq!(combine_crc(Crc32, &[(one.clone(), 0)]), Some(one));
}
