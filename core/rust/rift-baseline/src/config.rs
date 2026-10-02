use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Destination {
    pub name: String,
    pub target: String,
    pub purpose: String,
    pub protocol: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineConfig {
    pub destinations: Vec<Destination>,
    pub probe_count: usize,
    pub timeout_ms: u64,
    pub interval_ms: u64,
    pub max_hops: u8,
    pub data_dir: String,
    pub reports_dir: String,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            destinations: vec![
                Destination {
                    name: "Cloudflare Anycast DNS".to_string(),
                    target: "1.1.1.1".to_string(),
                    purpose: "Public Anycast Internet benchmark (Cloudflare)".to_string(),
                    protocol: "ICMP".to_string(),
                    port: None,
                },
                Destination {
                    name: "Google Anycast DNS".to_string(),
                    target: "8.8.8.8".to_string(),
                    purpose: "Public Anycast Internet benchmark (Google)".to_string(),
                    protocol: "ICMP".to_string(),
                    port: None,
                },
            ],
            probe_count: 30,
            timeout_ms: 1000,
            interval_ms: 100, // Safe rate limiting: 100ms interval between probes
            max_hops: 30,
            data_dir: "data/baseline".to_string(),
            reports_dir: "reports/phase0".to_string(),
        }
    }
}

impl BaselineConfig {
    /// Validates configuration parameters to guarantee network safety and prevent abuse.
    pub fn validate(&self) -> Result<(), String> {
        if self.destinations.is_empty() {
            return Err("At least one destination must be configured.".to_string());
        }
        if self.probe_count == 0 {
            return Err("Probe count must be greater than 0.".to_string());
        }
        if self.probe_count > 100 {
            return Err("Probe count exceeds safe maximum (100 probes per batch).".to_string());
        }
        if self.interval_ms < 20 {
            return Err("Interval between probes is too aggressive (minimum 20ms).".to_string());
        }
        if self.timeout_ms < 100 || self.timeout_ms > 10_000 {
            return Err("Timeout must be between 100ms and 10000ms.".to_string());
        }
        if self.max_hops == 0 || self.max_hops > 64 {
            return Err("Max hops must be between 1 and 64.".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_valid() {
        let config = BaselineConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.probe_count, 30);
        assert_eq!(config.destinations.len(), 2);
    }

    #[test]
    fn test_validation_probe_bounds() {
        let mut config = BaselineConfig::default();
        config.probe_count = 0;
        assert!(config.validate().is_err());

        config.probe_count = 500;
        assert!(config.validate().is_err());

        config.probe_count = 30;
        config.interval_ms = 5; // too aggressive
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let config = BaselineConfig::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let deserialized: BaselineConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }
}
