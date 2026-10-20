//! The XML reader and writer, including documents made to hurt.

use thirtys3_core::xml::{Limits, XmlError, XmlWriter, parse, parse_root};

fn read(xml: &str) -> Result<thirtys3_core::xml::Element, XmlError> {
    parse(xml.as_bytes(), &Limits::default())
}

#[test]
fn a_document_becomes_a_tree() {
    let root =
        read("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<A xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><B>one</B><B>two</B><C><D>deep</D></C><E/></A>")
            .unwrap();
    assert_eq!(root.name, "A");
    assert_eq!(root.children_named("B").map(|b| b.text.as_str()).collect::<Vec<_>>(), ["one", "two"]);
    assert_eq!(root.child("C").and_then(|c| c.child_text("D")), Some("deep"));
    assert_eq!(root.child_text("E"), Some(""));
    assert_eq!(root.child_text("F"), None);
}

#[test]
fn text_is_kept_exactly() {
    let root = read("<A><Key>  spaces  and\ttabs </Key></A>").unwrap();
    assert_eq!(root.child_text("Key"), Some("  spaces  and\ttabs "));
}

#[test]
fn predefined_entities_and_character_references_are_resolved() {
    let root = read("<A>&lt;&gt;&amp;&quot;&apos; &#65;&#x42;&#x1F600;</A>").unwrap();
    assert_eq!(root.text, "<>&\"' AB😀");
}

#[test]
fn cdata_is_text() {
    let root = read("<A><![CDATA[<not> & markup]]></A>").unwrap();
    assert_eq!(root.text, "<not> & markup");
}

#[test]
fn namespaces_prefixes_and_attributes_are_ignored() {
    let root = read("<s3:A xmlns:s3=\"x\" a=\"1\"><s3:B b=\"2\">v</s3:B></s3:A>").unwrap();
    assert_eq!(root.name, "A");
    assert_eq!(root.child_text("B"), Some("v"));
}

#[test]
fn comments_declarations_and_processing_instructions_are_skipped() {
    let root = read("<?xml version=\"1.0\"?><!-- c --><?pi data?><A><!-- inside -->t</A><!-- after -->").unwrap();
    assert_eq!(root.text, "t");
}

#[test]
fn a_byte_order_mark_is_skipped() {
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend_from_slice(b"<A>x</A>");
    assert_eq!(parse(&bytes, &Limits::default()).unwrap().text, "x");
}

#[test]
fn a_document_type_declaration_is_refused() {
    let billion_laughs =
        "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><lolz>&lol2;</lolz>";
    assert_eq!(read(billion_laughs).unwrap_err(), XmlError::DocType);
    assert_eq!(read("<!DOCTYPE A SYSTEM \"file:///etc/passwd\"><A/>").unwrap_err(), XmlError::DocType);
}

#[test]
fn an_entity_that_is_not_predefined_is_refused() {
    assert!(matches!(read("<A>&lol;</A>").unwrap_err(), XmlError::UnknownEntity(name) if name == "lol"));
    assert!(matches!(read("<A>&#0;</A>").unwrap_err(), XmlError::Malformed { .. }));
    assert!(matches!(read("<A>&#xFFFFFFFF;</A>").unwrap_err(), XmlError::Malformed { .. }));
    assert!(matches!(read("<A>& dangling</A>").unwrap_err(), XmlError::Malformed { .. }));
}

#[test]
fn malformed_documents_are_refused() {
    for xml in ["", "   ", "text", "<A>", "<A></B>", "<A><B></A></B>", "<A/><B/>", "<A></A><B></B>", "</A>", "<A attr=1/>", "<A>x</A> trailing", "<A><</A>", "<A"] {
        assert!(read(xml).is_err(), "{xml:?} was accepted");
    }
}

#[test]
fn a_document_that_is_not_utf8_is_refused() {
    assert!(matches!(parse(b"<A>\xFF\xFE</A>", &Limits::default()).unwrap_err(), XmlError::Malformed { .. }));
}

#[test]
fn the_size_limit() {
    let limits = Limits { max_bytes: 20, ..Limits::default() };
    assert!(parse(b"<A>0123456789</A>", &limits).is_ok());
    assert_eq!(parse(b"<A>0123456789012345</A>", &limits).unwrap_err(), XmlError::TooLarge(20));
}

#[test]
fn the_depth_limit_holds_for_documents_far_deeper_than_the_stack() {
    let limits = Limits::default();
    let deep = format!("{}x{}", "<a>".repeat(limits.max_depth), "</a>".repeat(limits.max_depth));
    assert!(parse(deep.as_bytes(), &limits).is_ok());
    let deeper = format!("{}x{}", "<a>".repeat(limits.max_depth + 1), "</a>".repeat(limits.max_depth + 1));
    assert_eq!(parse(deeper.as_bytes(), &limits).unwrap_err(), XmlError::TooDeep(limits.max_depth));
    let huge = format!("{}{}", "<a>".repeat(2_000_000), "</a>".repeat(2_000_000));
    assert_eq!(parse(huge.as_bytes(), &Limits { max_bytes: usize::MAX, ..limits }).unwrap_err(), XmlError::TooDeep(limits.max_depth));
}

#[test]
fn the_element_limit() {
    let limits = Limits { max_elements: 10, ..Limits::default() };
    assert!(parse(format!("<A>{}</A>", "<B/>".repeat(9)).as_bytes(), &limits).is_ok());
    assert_eq!(parse(format!("<A>{}</A>", "<B/>".repeat(10)).as_bytes(), &limits).unwrap_err(), XmlError::TooManyElements(10));
    assert_eq!(parse(format!("<A>{}</A>", "<B></B>".repeat(10)).as_bytes(), &limits).unwrap_err(), XmlError::TooManyElements(10));
}

#[test]
fn the_default_limits_take_the_largest_requests_s3_takes() {
    // 10,000 parts, each with every checksum.
    let mut part = String::from("<Part><PartNumber>1</PartNumber><ETag>\"0123456789abcdef0123456789abcdef\"</ETag>");
    for name in ["CRC32", "CRC32C", "CRC64NVME", "MD5", "SHA1", "SHA256", "SHA512", "XXHASH128", "XXHASH3", "XXHASH64"] {
        part.push_str(&format!("<Checksum{name}>{}</Checksum{name}>", "A".repeat(44)));
    }
    part.push_str("</Part>");
    let big = format!("<CompleteMultipartUpload>{}</CompleteMultipartUpload>", part.repeat(10_000));
    assert!(big.len() < Limits::default().max_bytes, "{} bytes", big.len());
    assert_eq!(parse(big.as_bytes(), &Limits::default()).unwrap().children.len(), 10_000);
    // 1,000 keys of 1,024 bytes.
    let delete = format!("<Delete>{}</Delete>", format!("<Object><Key>{}</Key></Object>", "k".repeat(1024)).repeat(1000));
    assert_eq!(parse(delete.as_bytes(), &Limits::default()).unwrap().children.len(), 1000);
}

#[test]
fn the_document_element_is_checked_by_name() {
    assert!(parse_root(b"<Delete/>", "Delete", &Limits::default()).is_ok());
    assert!(matches!(parse_root(b"<Other/>", "Delete", &Limits::default()).unwrap_err(), XmlError::WrongRoot { expected: "Delete", found } if found == "Other"));
}

#[test]
fn the_writer_writes_the_compact_form_of_s3() {
    let mut writer = XmlWriter::new("ListBucketResult", true);
    writer.leaf("Name", "bucket").start("Contents").leaf("Key", "a").end().empty("Marker");
    assert_eq!(
        writer.finish(),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>bucket</Name><Contents><Key>a</Key></Contents><Marker/></ListBucketResult>"
    );
    assert_eq!(XmlWriter::new("Error", false).finish(), "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error></Error>");
}

#[test]
fn the_writer_closes_what_is_left_open() {
    let mut writer = XmlWriter::new("A", false);
    writer.start("B").start("C");
    assert!(writer.finish().ends_with("<A><B><C></C></B></A>"));
}

#[test]
fn text_is_escaped() {
    let mut writer = XmlWriter::new("A", false);
    writer.leaf("K", "a<b>&c\"d'e\r").leaf_opt("N", None).leaf_opt("O", Some("x"));
    assert!(writer.finish().ends_with("<A><K>a&lt;b&gt;&amp;c\"d'e&#13;</K><O>x</O></A>"));
}

#[test]
fn characters_xml_does_not_allow_are_written_as_numeric_references() {
    let mut writer = XmlWriter::new("A", false);
    writer.leaf("K", "a\u{1}b\u{FFFE}c\t\n");
    let xml = writer.finish();
    assert!(xml.ends_with("<A><K>a&#x1;b&#xFFFE;c\t\n</K></A>"), "{xml}");
}

#[test]
fn what_the_writer_writes_the_reader_reads_back() {
    let awkward = [
        "plain",
        "",
        "a & b < c > d \" e ' f",
        "line1\r\nline2\rline3\nline4",
        "tabs\tand  spaces ",
        "unicode 中文 😀 é",
        "]]> and <![CDATA[ and &amp; literal",
        "control \u{1} \u{8} \u{1f}",
        "&#65; and &lt;",
    ];
    for text in awkward {
        let mut writer = XmlWriter::new("A", true);
        writer.leaf("K", text);
        let xml = writer.finish();
        let root = parse(xml.as_bytes(), &Limits::default()).unwrap();
        assert_eq!(root.child_text("K"), Some(text), "{text:?} written as {xml}");
    }
}

#[test]
fn only_plain_names_are_valid_element_names() {
    for name in ["Key", "x-amz-meta", "A.b", "_x", "a1"] {
        assert!(XmlWriter::is_valid_name(name), "{name}");
    }
    for name in ["", "1a", "-a", ".a", "a b", "a<b", "a>b", "a/b", "a:b", "é", "a\"b"] {
        assert!(!XmlWriter::is_valid_name(name), "{name:?}");
    }
}
