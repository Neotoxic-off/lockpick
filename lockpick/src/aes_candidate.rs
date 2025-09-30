#[derive(Debug, Clone)]
pub struct AesKeyCandidate {
    pub offset: usize,
    pub key: Vec<u8>,
    pub key_type: KeyType,
    pub entropy: f64,
    pub hex_string: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    Type1,
    Type2,
    Type3,
    Type4,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Type1 => write!(f, "Type1"),
            KeyType::Type2 => write!(f, "Type2"),
            KeyType::Type3 => write!(f, "Type3"),
            KeyType::Type4 => write!(f, "Type4"),
        }
    }
}
