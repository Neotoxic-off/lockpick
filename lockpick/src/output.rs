use crate::aes_candidate::AesKeyCandidate;
use log::info;

pub fn print_results(candidates: &[AesKeyCandidate]) {
    info!("\n{}", "=".repeat(80));
    info!("AES Key Candidates Found: {}", candidates.len());
    info!("{}", "=".repeat(80));

    for (idx, candidate) in candidates.iter().enumerate() {
        info!("\n[{}] Key Type: {} | Entropy: {:.4}", idx + 1, candidate.key_type, candidate.entropy);
        info!("    Offset: 0x{:08X}", candidate.offset);
        info!("    Key: 0x{}", candidate.hex_string);
    }

    info!("\n{}", "=".repeat(80));
}
