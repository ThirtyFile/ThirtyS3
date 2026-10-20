//! A small XML reader and writer for the documents S3 sends and receives.
//!
//! The reader builds a tree of [`Element`]s with limits on size, depth and element count. It takes no document type declaration and no entity
//! other than the five predefined ones and numeric character references, so a hostile document cannot expand into more than it is long. Names
//! are read without their namespace prefix and attributes (such as `xmlns`) are ignored, as S3 does for requests with or without a namespace.
//! The attributes have to be well formed, but the characters of names are not checked: a name is only compared with the ones expected.
//! The writer produces the compact form S3 uses, with `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"` on the root of most documents.

use quick_xml::Reader;
use quick_xml::events::Event;

/// The namespace of the documents of the S3 API.
pub const S3_NAMESPACE: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// What can be wrong with an XML document, or with what a document says.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum XmlError {
    /// The document is not well-formed XML.
    #[error("the XML is not well formed (byte {position}): {message}")]
    Malformed {
        /// Where in the document the reader gave up.
        position: usize,
        /// What the reader found wrong.
        message: String,
    },
    /// The document is longer than the limit.
    #[error("the XML is longer than {0} bytes")]
    TooLarge(usize),
    /// The elements are nested deeper than the limit.
    #[error("the XML is nested deeper than {0} levels")]
    TooDeep(usize),
    /// The document has more elements than the limit.
    #[error("the XML has more than {0} elements")]
    TooManyElements(usize),
    /// The document has a `<!DOCTYPE …>`, which is not accepted.
    #[error("the XML has a document type declaration, which is not accepted")]
    DocType,
    /// The document uses an entity that is not one of the five predefined ones.
    #[error("the XML uses the entity &{0}; which is not defined")]
    UnknownEntity(String),
    /// The document element is not the one expected.
    #[error("expected <{expected}> as the document element, found <{found}>")]
    WrongRoot {
        /// The name that was expected.
        expected: &'static str,
        /// The name that was found.
        found: String,
    },
    /// A required element is missing.
    #[error("<{parent}> has no <{name}>")]
    Missing {
        /// The element that should have had it.
        parent: String,
        /// The name of the missing element.
        name: &'static str,
    },
    /// An element has a value that is not valid for it.
    #[error("<{name}> has an invalid value {value:?}")]
    Invalid {
        /// The element.
        name: String,
        /// The value, cut to a reasonable length.
        value: String,
    },
}

impl XmlError {
    pub(crate) fn invalid(name: &str, value: &str) -> Self {
        Self::Invalid { name: name.to_owned(), value: value.chars().take(80).collect() }
    }
}

/// How large a document the reader accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes in a document.
    pub max_bytes: usize,
    /// The most levels of elements inside one another.
    pub max_depth: usize,
    /// The most elements in a document.
    pub max_elements: usize,
}

impl Default for Limits {
    /// 16 MiB, 16 levels and 300,000 elements: room for the largest request S3 takes (a `CompleteMultipartUpload` of 10,000 parts with every
    /// checksum, which is 8.6 MB, or a `Delete` of 1,000 keys of 1,024 bytes) with room to spare.
    fn default() -> Self {
        Self { max_bytes: 16 * 1024 * 1024, max_depth: 16, max_elements: 300_000 }
    }
}

/// An element: its name without namespace prefix, the text directly inside it and its child elements.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Element {
    /// The local name.
    pub name: String,
    /// The text inside the element, outside its children, with entities resolved and nothing trimmed.
    pub text: String,
    /// The child elements in the order of the document.
    pub children: Vec<Element>,
}

impl Element {
    /// The first child with this name.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|child| child.name == name)
    }

    /// The children with this name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |child| child.name == name)
    }

    /// The text of the first child with this name.
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|child| child.text.as_str())
    }

    /// The text of a child that must be there.
    pub fn required_text(&self, name: &'static str) -> Result<&str, XmlError> {
        self.child_text(name).ok_or_else(|| XmlError::Missing { parent: self.name.clone(), name })
    }

    /// The child with this name read as `T` with `parse`, or `None` when there is no such child. `Err` when it has a value `parse` does not take.
    pub fn parsed_child<T>(&self, name: &str, parse: impl Fn(&str) -> Option<T>) -> Result<Option<T>, XmlError> {
        match self.child_text(name) {
            None => Ok(None),
            Some(text) => parse(text.trim()).map(Some).ok_or_else(|| XmlError::invalid(name, text)),
        }
    }
}

fn malformed(reader: &Reader<&[u8]>, message: impl ToString) -> XmlError {
    XmlError::Malformed { position: reader.buffer_position() as usize, message: message.to_string() }
}

/// The attributes are not used, but a start tag whose attributes are not well formed makes the document not well formed.
fn check_attributes(reader: &Reader<&[u8]>, start: &quick_xml::events::BytesStart<'_>) -> Result<(), XmlError> {
    for attribute in start.attributes() {
        attribute.map_err(|error| malformed(reader, error))?;
    }
    Ok(())
}

/// Reads a document and returns its document element.
pub fn parse(xml: &[u8], limits: &Limits) -> Result<Element, XmlError> {
    if xml.len() > limits.max_bytes {
        return Err(XmlError::TooLarge(limits.max_bytes));
    }
    let xml = xml.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(xml);
    let text = std::str::from_utf8(xml).map_err(|error| XmlError::Malformed { position: error.valid_up_to(), message: "the document is not UTF-8".to_owned() })?;
    let mut reader = Reader::from_str(text);
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut elements = 0_usize;

    // Puts a finished element in its parent, or makes it the document element.
    let attach = |stack: &mut Vec<Element>, root: &mut Option<Element>, element: Element, reader: &Reader<&[u8]>| -> Result<(), XmlError> {
        match stack.last_mut() {
            Some(parent) => parent.children.push(element),
            None if root.is_none() => *root = Some(element),
            None => return Err(malformed(reader, "more than one document element")),
        }
        Ok(())
    };

    loop {
        let event = reader.read_event().map_err(|error| malformed(&reader, error))?;
        match event {
            Event::Start(start) => {
                check_attributes(&reader, &start)?;
                elements += 1;
                if elements > limits.max_elements {
                    return Err(XmlError::TooManyElements(limits.max_elements));
                }
                if stack.len() >= limits.max_depth {
                    return Err(XmlError::TooDeep(limits.max_depth));
                }
                if root.is_some() && stack.is_empty() {
                    return Err(malformed(&reader, "more than one document element"));
                }
                stack.push(Element { name: start.local_name().as_ref().to_owned(), ..Element::default() });
            }
            Event::Empty(start) => {
                check_attributes(&reader, &start)?;
                elements += 1;
                if elements > limits.max_elements {
                    return Err(XmlError::TooManyElements(limits.max_elements));
                }
                if stack.len() >= limits.max_depth {
                    return Err(XmlError::TooDeep(limits.max_depth));
                }
                let element = Element { name: start.local_name().as_ref().to_owned(), ..Element::default() };
                attach(&mut stack, &mut root, element, &reader)?;
            }
            Event::End(_) => {
                let element = stack.pop().ok_or_else(|| malformed(&reader, "an end tag without a start tag"))?;
                attach(&mut stack, &mut root, element, &reader)?;
            }
            Event::Text(content) => {
                let content = content.xml10_content();
                match stack.last_mut() {
                    Some(top) => top.text.push_str(&content),
                    None if content.trim().is_empty() => {}
                    None => return Err(malformed(&reader, "text outside the document element")),
                }
            }
            Event::CData(content) => match stack.last_mut() {
                Some(top) => top.text.push_str(&content.xml10_content()),
                None => return Err(malformed(&reader, "text outside the document element")),
            },
            Event::GeneralRef(reference) => {
                let resolved = match reference.resolve_char_ref().map_err(|error| malformed(&reader, error))? {
                    Some(character) => character,
                    None => match &*reference {
                        "lt" => '<',
                        "gt" => '>',
                        "amp" => '&',
                        "quot" => '"',
                        "apos" => '\'',
                        other => return Err(XmlError::UnknownEntity(other.chars().take(40).collect())),
                    },
                };
                match stack.last_mut() {
                    Some(top) => top.text.push(resolved),
                    None => return Err(malformed(&reader, "a reference outside the document element")),
                }
            }
            Event::DocType(_) => return Err(XmlError::DocType),
            Event::Comment(_) | Event::PI(_) | Event::Decl(_) => {}
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(malformed(&reader, "the document ends inside an element"));
    }
    root.ok_or_else(|| malformed(&reader, "the document has no element"))
}

/// Reads a document and checks the name of its document element.
pub fn parse_root(xml: &[u8], expected: &'static str, limits: &Limits) -> Result<Element, XmlError> {
    let root = parse(xml, limits)?;
    if root.name == expected { Ok(root) } else { Err(XmlError::WrongRoot { expected, found: root.name.chars().take(80).collect() }) }
}

/// Whether `character` may appear in an XML 1.0 document.
fn is_xml_char(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

/// Writes a document in the compact form S3 uses.
///
/// A character that XML 1.0 does not allow (a control character in a key, for one) is written as a character reference, such as `&#x1;`, as S3
/// does. That is not well-formed XML 1.0, and the reader of this crate takes it back as the character; a strict parser will not. A service whose keys
/// can hold such characters should have its clients ask for `encoding-type=url`.
#[derive(Debug)]
pub struct XmlWriter {
    out: String,
    open: Vec<String>,
}

impl XmlWriter {
    /// Starts a document with the XML declaration and the document element `root`, with the S3 namespace when `namespaced`.
    pub fn new(root: &str, namespaced: bool) -> Self {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push('<');
        out.push_str(root);
        if namespaced {
            out.push_str(" xmlns=\"");
            out.push_str(S3_NAMESPACE);
            out.push('"');
        }
        out.push('>');
        Self { out, open: vec![root.to_owned()] }
    }

    /// Opens an element.
    pub fn start(&mut self, name: &str) -> &mut Self {
        self.out.push('<');
        self.out.push_str(name);
        self.out.push('>');
        self.open.push(name.to_owned());
        self
    }

    /// Closes the element opened last.
    pub fn end(&mut self) -> &mut Self {
        if let Some(name) = self.open.pop() {
            self.out.push_str("</");
            self.out.push_str(&name);
            self.out.push('>');
        }
        self
    }

    /// Writes text inside the element that is open. `&`, `<` and `>` become entities, a carriage return and the characters XML 1.0 does not
    /// allow become numeric references.
    pub fn text(&mut self, text: &str) -> &mut Self {
        for character in text.chars() {
            match character {
                '&' => self.out.push_str("&amp;"),
                '<' => self.out.push_str("&lt;"),
                '>' => self.out.push_str("&gt;"),
                '\r' => self.out.push_str("&#13;"),
                other if is_xml_char(other) => self.out.push(other),
                other => self.out.push_str(&format!("&#x{:X};", other as u32)),
            }
        }
        self
    }

    /// Writes `<name>text</name>`, with the text escaped as [`text`](Self::text) does.
    pub fn leaf(&mut self, name: &str, text: &str) -> &mut Self {
        self.out.push('<');
        self.out.push_str(name);
        self.out.push('>');
        self.text(text);
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push('>');
        self
    }

    /// Writes the leaf when there is a value.
    pub fn leaf_opt(&mut self, name: &str, text: Option<&str>) -> &mut Self {
        if let Some(text) = text {
            self.leaf(name, text);
        }
        self
    }

    /// Whether `name` can be an element name: ASCII letters, digits, `-`, `_` and `.`, not starting with a digit, `-` or `.`.
    pub fn is_valid_name(name: &str) -> bool {
        let mut characters = name.chars();
        characters.next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    }

    /// Writes an element without content, `<name/>`.
    pub fn empty(&mut self, name: &str) -> &mut Self {
        self.out.push('<');
        self.out.push_str(name);
        self.out.push_str("/>");
        self
    }

    /// Closes every element still open and returns the document.
    pub fn finish(mut self) -> String {
        while !self.open.is_empty() {
            self.end();
        }
        self.out
    }
}
