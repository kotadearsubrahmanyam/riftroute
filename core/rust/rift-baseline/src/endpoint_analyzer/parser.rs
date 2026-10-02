use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::models::RawPacketRecord;

pub struct ParseResult {
    pub records: Vec<RawPacketRecord>,
    pub total_lines_read: usize,
    pub malformed_lines: usize,
    pub error_samples: Vec<String>,
}

pub struct CaptureParser;

impl CaptureParser {
    /// Read and parse a TShark packet metadata capture file from disk.
    /// Transparently handles UTF-8, UTF-16 LE (Windows PowerShell standard), and UTF-16 BE with BOM.
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<ParseResult, String> {
        let mut file = File::open(path.as_ref())
            .map_err(|e| format!("Failed to open capture file '{}': {}", path.as_ref().display(), e))?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| format!("Failed to read capture file: {}", e))?;

        let text = Self::decode_bytes_to_string(&buffer)?;
        Ok(Self::parse_str(&text))
    }

    /// Decode raw file bytes into a Rust String, handling UTF-8 and UTF-16 BOMs.
    pub fn decode_bytes_to_string(bytes: &[u8]) -> Result<String, String> {
        if bytes.is_empty() {
            return Ok(String::new());
        }

        // UTF-16 Little Endian BOM (\xFF\xFE)
        if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
            let u16_slice: Vec<u16> = bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            return String::from_utf16(&u16_slice)
                .map_err(|e| format!("Failed to decode UTF-16LE text: {}", e));
        }

        // UTF-16 Big Endian BOM (\xFE\xFF)
        if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
            let u16_slice: Vec<u16> = bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect();
            return String::from_utf16(&u16_slice)
                .map_err(|e| format!("Failed to decode UTF-16BE text: {}", e));
        }

        // UTF-8 BOM (\xEF\xBB\xBF)
        let utf8_slice = if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
            &bytes[3..]
        } else {
            bytes
        };

        String::from_utf8(utf8_slice.to_vec())
            .or_else(|_| {
                // If invalid UTF-8 and has null bytes every other byte, try UTF-16LE without BOM
                if bytes.len() >= 4 && (bytes[1] == 0 || bytes[3] == 0) {
                    let u16_slice: Vec<u16> = bytes
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();
                    String::from_utf16(&u16_slice)
                        .map_err(|e| format!("Failed to decode non-BOM UTF-16 text: {}", e))
                } else {
                    Err("File is not valid UTF-8 or UTF-16".to_string())
                }
            })
    }

    /// Parse in-memory text containing TShark lines into RawPacketRecords.
    pub fn parse_str(text: &str) -> ParseResult {
        let mut records = Vec::new();
        let mut total_lines_read = 0;
        let mut malformed_lines = 0;
        let mut error_samples = Vec::new();

        for (line_idx, line) in text.lines().enumerate() {
            total_lines_read += 1;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                // Blank lines are skipped safely and not considered malformed records
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() != 6 {
                malformed_lines += 1;
                if error_samples.len() < 5 {
                    error_samples.push(format!(
                        "Line {}: Expected 6 columns, found {} ('{}')",
                        line_idx + 1,
                        parts.len(),
                        trimmed
                    ));
                }
                continue;
            }

            let timestamp = match parts[0].parse::<f64>() {
                Ok(ts) if ts >= 0.0 => ts,
                _ => {
                    malformed_lines += 1;
                    if error_samples.len() < 5 {
                        error_samples.push(format!("Line {}: Invalid timestamp '{}'", line_idx + 1, parts[0]));
                    }
                    continue;
                }
            };

            let src_ip = parts[1].to_string();
            let dst_ip = parts[2].to_string();

            let src_port = match parts[3].parse::<u16>() {
                Ok(p) => p,
                _ => {
                    malformed_lines += 1;
                    if error_samples.len() < 5 {
                        error_samples.push(format!("Line {}: Invalid src port '{}'", line_idx + 1, parts[3]));
                    }
                    continue;
                }
            };

            let dst_port = match parts[4].parse::<u16>() {
                Ok(p) => p,
                _ => {
                    malformed_lines += 1;
                    if error_samples.len() < 5 {
                        error_samples.push(format!("Line {}: Invalid dst port '{}'", line_idx + 1, parts[4]));
                    }
                    continue;
                }
            };

            let frame_length = match parts[5].parse::<u32>() {
                Ok(l) => l,
                _ => {
                    malformed_lines += 1;
                    if error_samples.len() < 5 {
                        error_samples.push(format!("Line {}: Invalid frame length '{}'", line_idx + 1, parts[5]));
                    }
                    continue;
                }
            };

            records.push(RawPacketRecord {
                timestamp,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                frame_length,
            });
        }

        ParseResult {
            records,
            total_lines_read,
            malformed_lines,
            error_samples,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_records() {
        let sample = "
0.000000000\t20.205.179.128\t192.168.1.14\t27528\t50837\t73
0.002602700  192.168.1.14   20.205.179.128  50837   27528   67
";
        let res = CaptureParser::parse_str(sample);
        assert_eq!(res.records.len(), 2);
        assert_eq!(res.malformed_lines, 0);

        assert_eq!(res.records[0].timestamp, 0.0);
        assert_eq!(res.records[0].src_ip, "20.205.179.128");
        assert_eq!(res.records[0].dst_ip, "192.168.1.14");
        assert_eq!(res.records[0].src_port, 27528);
        assert_eq!(res.records[0].dst_port, 50837);
        assert_eq!(res.records[0].frame_length, 73);

        assert_eq!(res.records[1].timestamp, 0.002602700);
        assert_eq!(res.records[1].frame_length, 67);
    }

    #[test]
    fn test_parse_whitespace_and_blank_lines() {
        let sample = "\n\n   \t  \n0.100  10.0.0.1  10.0.0.2  1111  2222  100\n\n";
        let res = CaptureParser::parse_str(sample);
        assert_eq!(res.records.len(), 1);
        assert_eq!(res.malformed_lines, 0);
    }

    #[test]
    fn test_parse_malformed_records() {
        let sample = "
0.100 1.1.1.1 2.2.2.2 10 20 50
NOT_A_RECORD
0.200 1.1.1.1 2.2.2.2 NOT_PORT 20 50
0.300 1.1.1.1 2.2.2.2 10 20 NOT_LEN
";
        let res = CaptureParser::parse_str(sample);
        assert_eq!(res.records.len(), 1);
        assert_eq!(res.malformed_lines, 3);
        assert_eq!(res.error_samples.len(), 3);
    }

    #[test]
    fn test_utf16le_decoding() {
        // Construct UTF-16LE bytes with BOM
        let test_str = "0.001 1.1.1.1 2.2.2.2 10 20 60\n";
        let mut bytes = vec![0xFF, 0xFE]; // BOM
        for c in test_str.encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }

        let decoded = CaptureParser::decode_bytes_to_string(&bytes).unwrap();
        assert_eq!(decoded, test_str);

        let parsed = CaptureParser::parse_str(&decoded);
        assert_eq!(parsed.records.len(), 1);
    }
}
