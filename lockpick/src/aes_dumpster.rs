use log::{info, debug};
use std::collections::HashSet;

use crate::aes_candidate::{AesKeyCandidate, KeyType};

pub struct AesDumpster {
    buffer: Vec<u8>,
    min_entropy: f64,
    known_false_positives: Vec<Vec<u8>>,
}
pub struct ScanRule<'a> {
    key_type: KeyType,
    alignment: usize,
    pattern_fn: Box<dyn Fn(&AesDumpster, usize, &[u8]) -> bool + 'a>,
}

impl AesDumpster {
    pub fn new(buffer: Vec<u8>, min_entropy: f64) -> Self {
        let known_false_positives: Vec<Vec<u8>> = Self::initialize_false_positives();
        info!("Initialized AESDumpster with {} bytes buffer", buffer.len());
        debug!("Minimum entropy: {}", min_entropy);
        debug!("Known false positives: {}", known_false_positives.len());

        Self { buffer, min_entropy, known_false_positives }
    }

    fn initialize_false_positives() -> Vec<Vec<u8>> {
        vec![
            vec![0x00; 32],
            vec![0xFF; 32],
            vec![0xCC; 32],
            vec![0xCD; 32],
        ]
    }

    pub fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }

        let mut freq = [0u32; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    fn is_false_positive(&self, key: &[u8]) -> bool {
        self.known_false_positives.iter().any(|fp| fp == key)
    }

    pub fn scan(&self) -> Vec<AesKeyCandidate> {
        let rules: Vec<ScanRule> = vec![
            ScanRule {
                key_type: KeyType::Type1,
                alignment: 16,
                pattern_fn: Box::new(|_, _, _| true),
            },
            ScanRule {
                key_type: KeyType::Type2,
                alignment: 4,
                pattern_fn: Box::new(|_, _, key| {
                    let unique_bytes: HashSet<_> = key.iter().collect();
                    unique_bytes.len() >= 8
                }),
            },
            ScanRule {
                key_type: KeyType::Type3,
                alignment: 1,
                pattern_fn: Box::new(|s, offset, _| s.has_ue_signature(offset)),
            },
            ScanRule {
                key_type: KeyType::Type4,
                alignment: 1,
                pattern_fn: Box::new(|s, _, key| s.has_type4_pattern(key)),
            }
        ];

        let mut candidates: Vec<AesKeyCandidate> = Vec::new();

        for i in 0..self.buffer.len().saturating_sub(32) {
            let key_bytes = &self.buffer[i..i + 32];

            for rule in &rules {
                if i % rule.alignment != 0 {
                    continue;
                }

                if !(rule.pattern_fn)(self, i, key_bytes) {
                    continue;
                }

                let entropy = self.calculate_entropy(key_bytes);
                if entropy < self.min_entropy || self.is_false_positive(key_bytes) {
                    continue;
                }

                let hex_string: String = key_bytes.iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<String>();

                info!("[{:?}](0x{:08X})|{:.2}|: {}", rule.key_type, i, entropy, hex_string);

                candidates.push(AesKeyCandidate {
                    offset: i,
                    key: key_bytes.to_vec(),
                    key_type: rule.key_type.clone(),
                    entropy,
                    hex_string,
                });
            }
        }

        candidates.sort_by(|a, b| b.entropy.partial_cmp(&a.entropy).unwrap());
        candidates.dedup_by(|a, b| a.key == b.key);

        info!("Scan complete: {} unique candidates", candidates.len());
        candidates
    }

    fn has_ue_signature(&self, offset: usize) -> bool {
        if offset < 256 {
            return false;
        }

        let check_range = &self.buffer[offset.saturating_sub(256)..offset.min(self.buffer.len())];

        check_range.windows(4).any(|w| {
            w == b"FPak" || w == b"AES\x00" || w == b"UE4\x00"
        })
    }

    fn has_type4_pattern(&self, key: &[u8]) -> bool {
        let mut consecutive_same: i32 = 0;
        let mut max_consecutive: i32 = 0;

        for i in 0..key.len() {
            if i > 0 && key[i] == key[i - 1] {
                consecutive_same += 1;
                max_consecutive = max_consecutive.max(consecutive_same);
            } else {
                consecutive_same = 1;
            }
        }

        let unique_bytes: HashSet<_> = key.iter().collect();
        let byte_diversity = unique_bytes.len();

        byte_diversity >= 16 && max_consecutive <= 4
    }
}
