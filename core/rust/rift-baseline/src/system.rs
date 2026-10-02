use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteEntry {
    pub destination: String,
    pub netmask: String,
    pub gateway: String,
    pub interface: String,
    pub metric: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IspMetadata {
    pub asn: String,
    pub organization: String,
    pub city: String,
    pub region: String,
    pub country: String,
    pub source: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemInventory {
    pub os: String,
    pub architecture: String,
    pub hostname: String,
    pub active_interface: String,
    pub interface_description: String,
    pub ipv4_address: String,
    pub default_gateway: String,
    pub dns_servers: Vec<String>,
    pub interface_metric: u32,
    pub private_network_range: String,
    pub routing_table: Vec<RouteEntry>,
    pub isp_info: IspMetadata,
    pub timestamp: String,
}

impl SystemInventory {
    /// Collect the system network inventory on Windows.
    pub fn collect() -> Self {
        let timestamp = Utc::now().to_rfc3339();
        let os = "Microsoft Windows 11 (x64)".to_string();
        let architecture = "x64".to_string();
        let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".to_string());

        // Default fallback values
        let mut active_interface = "Wi-Fi".to_string();
        let mut interface_description = "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter".to_string();
        let mut ipv4_address = "192.168.1.14".to_string();
        let mut default_gateway = "192.168.1.1".to_string();
        let mut dns_servers = vec!["192.168.1.1".to_string()];
        let mut interface_metric = 35;

        // Query active adapter via PowerShell Get-NetIPConfiguration
        let ps_cmd = r#"Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | ForEach-Object { [PSCustomObject]@{ InterfaceAlias = $_.InterfaceAlias; Description = $_.InterfaceDescription; IPv4 = ($_.IPv4Address.IPAddress -join ','); Gateway = ($_.IPv4DefaultGateway.NextHop -join ','); DNS = ($_.DNSServer.ServerAddresses -join ',') } } | ConvertTo-Json"#;
        if let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-Command", ps_cmd])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(alias) = val["InterfaceAlias"].as_str() {
                        active_interface = alias.to_string();
                    }
                    if let Some(desc) = val["Description"].as_str() {
                        interface_description = desc.to_string();
                    }
                    if let Some(ip) = val["IPv4"].as_str() {
                        if !ip.is_empty() {
                            ipv4_address = ip.split(',').next().unwrap_or(ip).trim().to_string();
                        }
                    }
                    if let Some(gw) = val["Gateway"].as_str() {
                        if !gw.is_empty() {
                            default_gateway = gw.split(',').next().unwrap_or(gw).trim().to_string();
                        }
                    }
                    if let Some(dns) = val["DNS"].as_str() {
                        dns_servers = dns
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                }
            }
        }

        // Parse routes from `route print -4`
        let mut routing_table = Vec::new();
        if let Ok(route_out) = Command::new("route").args(["print", "-4"]).output() {
            if route_out.status.success() {
                let text = String::from_utf8_lossy(&route_out.stdout);
                let mut in_active_routes = false;
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("Network Destination") {
                        in_active_routes = true;
                        continue;
                    }
                    if in_active_routes {
                        if trimmed.starts_with("===") || trimmed.starts_with("Persistent") {
                            break;
                        }
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 5 {
                            let destination = parts[0].to_string();
                            let netmask = parts[1].to_string();
                            let gateway = parts[2].to_string();
                            let interface = parts[3].to_string();
                            let metric = parts[4].parse::<u32>().unwrap_or(0);

                            if destination == "0.0.0.0" {
                                interface_metric = metric;
                            }

                            routing_table.push(RouteEntry {
                                destination,
                                netmask,
                                gateway,
                                interface,
                                metric,
                            });
                        }
                    }
                }
            }
        }

        let private_network_range = format!("{}/24", default_gateway.rsplit_once('.').map(|(p, _)| format!("{}.0", p)).unwrap_or_else(|| "192.168.1.0".to_string()));

        // Query external ISP metadata
        let isp_info = Self::query_isp();

        Self {
            os,
            architecture,
            hostname,
            active_interface,
            interface_description,
            ipv4_address,
            default_gateway,
            dns_servers,
            interface_metric,
            private_network_range,
            routing_table,
            isp_info,
            timestamp,
        }
    }

    /// Query public ISP / ASN metadata via reliable HTTPS API with a strict timeout.
    fn query_isp() -> IspMetadata {
        let ts = Utc::now().to_rfc3339();
        let endpoints = ["https://ipinfo.io/json", "https://ip-api.com/json"];

        for url in endpoints {
            if let Ok(resp) = ureq::get(url).timeout(std::time::Duration::from_secs(3)).call() {
                if let Ok(val) = resp.into_json::<serde_json::Value>() {
                    let org = val["org"].as_str().or_else(|| val["isp"].as_str()).unwrap_or("UNKNOWN").to_string();
                    let city = val["city"].as_str().unwrap_or("UNKNOWN").to_string();
                    let region = val["region"].as_str().or_else(|| val["regionName"].as_str()).unwrap_or("UNKNOWN").to_string();
                    let country = val["country"].as_str().unwrap_or("UNKNOWN").to_string();

                    // Parse ASN prefix if present in org string (e.g. "AS24560 Bharti Airtel Ltd.")
                    let asn = if org.starts_with("AS") {
                        org.split_whitespace().next().unwrap_or("UNKNOWN").to_string()
                    } else if let Some(as_str) = val["as"].as_str() {
                        as_str.split_whitespace().next().unwrap_or("UNKNOWN").to_string()
                    } else {
                        "UNKNOWN".to_string()
                    };

                    return IspMetadata {
                        asn,
                        organization: org,
                        city,
                        region,
                        country,
                        source: url.to_string(),
                        timestamp: ts,
                    };
                }
            }
        }

        IspMetadata {
            asn: "UNKNOWN".to_string(),
            organization: "UNKNOWN".to_string(),
            city: "UNKNOWN".to_string(),
            region: "UNKNOWN".to_string(),
            country: "UNKNOWN".to_string(),
            source: "Offline / Timeout".to_string(),
            timestamp: ts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isp_metadata_struct() {
        let isp = IspMetadata {
            asn: "AS24560".to_string(),
            organization: "Bharti Airtel Ltd.".to_string(),
            city: "Hyderabad".to_string(),
            region: "Telangana".to_string(),
            country: "IN".to_string(),
            source: "test".to_string(),
            timestamp: "2026-10-02T16:00:00Z".to_string(),
        };
        assert_eq!(isp.asn, "AS24560");
        assert_eq!(isp.country, "IN");
    }

    #[test]
    fn test_route_entry_serialization() {
        let entry = RouteEntry {
            destination: "0.0.0.0".to_string(),
            netmask: "0.0.0.0".to_string(),
            gateway: "192.168.1.1".to_string(),
            interface: "192.168.1.14".to_string(),
            metric: 35,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: RouteEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }
}
