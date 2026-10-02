use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EndpointClassification {
    Observed,
    VerifiedGameServer,
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActiveConnection {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: String,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
    pub game_name: Option<String>,
    pub classification: EndpointClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GameProcess {
    pub pid: u32,
    pub name: String,
    pub game: String,
    pub verified: bool,
    pub connections: Vec<ActiveConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessInventory {
    pub detected_games: Vec<GameProcess>,
    pub total_active_connections: usize,
    pub timestamp: String,
}

pub struct ProcessManager;

impl ProcessManager {
    /// Return the known signature map: process executable name -> Game Title
    pub fn known_games() -> HashMap<&'static str, &'static str> {
        let mut map = HashMap::new();
        map.insert("TslGame.exe", "PUBG PC");
        map.insert("cs2.exe", "Counter-Strike 2");
        map.insert("VALORANT.exe", "VALORANT");
        map.insert("VALORANT-Win64-Shipping.exe", "VALORANT");
        map.insert("Discovery.exe", "THE FINALS");
        map
    }

    /// Non-invasively inventory running processes on Windows using tasklist.
    pub fn list_running_processes() -> HashMap<u32, String> {
        let mut map = HashMap::new();
        if let Ok(output) = Command::new("tasklist").args(["/FO", "CSV", "/NH"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 2 {
                        let name = parts[0].trim().trim_matches('"').to_string();
                        let pid_str = parts[1].trim().trim_matches('"');
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            map.insert(pid, name);
                        }
                    }
                }
            }
        }
        map
    }

    /// Enumerate all active network connections using netstat -ano.
    pub fn list_active_connections() -> Vec<ActiveConnection> {
        let process_map = Self::list_running_processes();
        let known_games = Self::known_games();
        let mut connections = Vec::new();

        if let Ok(output) = Command::new("netstat").args(["-ano"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                connections = Self::parse_netstat_output(&text, &process_map, &known_games);
            }
        }

        connections
    }

    /// Parse netstat -ano text output.
    pub fn parse_netstat_output(
        text: &str,
        process_map: &HashMap<u32, String>,
        known_games: &HashMap<&str, &str>,
    ) -> Vec<ActiveConnection> {
        let mut connections = Vec::new();

        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let proto = parts[0].to_uppercase();
            if proto == "TCP" && parts.len() >= 5 {
                let local_address = parts[1].to_string();
                let remote_address = parts[2].to_string();
                let state = parts[3].to_string();
                let pid: u32 = parts[4].parse().unwrap_or(0);

                let process_name = process_map
                    .get(&pid)
                    .cloned()
                    .unwrap_or_else(|| "UNKNOWN".to_string());

                let game_name = known_games.get(process_name.as_str()).map(|&s| s.to_string());
                let classification = if game_name.is_some() {
                    EndpointClassification::Observed
                } else {
                    EndpointClassification::Unverified
                };

                connections.push(ActiveConnection {
                    protocol: proto,
                    local_address,
                    remote_address,
                    state,
                    pid,
                    process_name,
                    game_name,
                    classification,
                });
            } else if proto == "UDP" && parts.len() >= 4 {
                let local_address = parts[1].to_string();
                let remote_address = parts[2].to_string();
                let state = "NONE".to_string();
                let pid: u32 = parts[3].parse().unwrap_or(0);

                let process_name = process_map
                    .get(&pid)
                    .cloned()
                    .unwrap_or_else(|| "UNKNOWN".to_string());

                let game_name = known_games.get(process_name.as_str()).map(|&s| s.to_string());
                let classification = if game_name.is_some() {
                    EndpointClassification::Observed
                } else {
                    EndpointClassification::Unverified
                };

                connections.push(ActiveConnection {
                    protocol: proto,
                    local_address,
                    remote_address,
                    state,
                    pid,
                    process_name,
                    game_name,
                    classification,
                });
            }
        }

        connections
    }

    /// Discover running game processes and their active network connections.
    pub fn scan_game_activity() -> ProcessInventory {
        let timestamp = Utc::now().to_rfc3339();
        let running_processes = Self::list_running_processes();
        let known_games = Self::known_games();
        let all_connections = Self::list_active_connections();

        let mut detected_games = Vec::new();

        for (&pid, proc_name) in &running_processes {
            if let Some(&game_title) = known_games.get(proc_name.as_str()) {
                let proc_connections: Vec<ActiveConnection> = all_connections
                    .iter()
                    .filter(|c| c.pid == pid)
                    .cloned()
                    .collect();

                detected_games.push(GameProcess {
                    pid,
                    name: proc_name.clone(),
                    game: game_title.to_string(),
                    verified: true,
                    connections: proc_connections,
                });
            }
        }

        ProcessInventory {
            total_active_connections: all_connections.len(),
            detected_games,
            timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_games_signatures() {
        let map = ProcessManager::known_games();
        assert_eq!(map.get("TslGame.exe"), Some(&"PUBG PC"));
        assert_eq!(map.get("cs2.exe"), Some(&"Counter-Strike 2"));
        assert_eq!(map.get("VALORANT.exe"), Some(&"VALORANT"));
        assert_eq!(map.get("Discovery.exe"), Some(&"THE FINALS"));
    }

    #[test]
    fn test_parse_netstat_sample() {
        let sample = r#"
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    192.168.1.14:50000     54.254.12.34:7777      ESTABLISHED     1234
  UDP    192.168.1.14:60000     *:*                                    1234
  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       5678
"#;
        let mut proc_map = HashMap::new();
        proc_map.insert(1234, "TslGame.exe".to_string());
        proc_map.insert(5678, "node.exe".to_string());

        let known = ProcessManager::known_games();
        let conns = ProcessManager::parse_netstat_output(sample, &proc_map, &known);

        assert_eq!(conns.len(), 3);
        assert_eq!(conns[0].process_name, "TslGame.exe");
        assert_eq!(conns[0].game_name, Some("PUBG PC".to_string()));
        assert_eq!(conns[0].classification, EndpointClassification::Observed);
        assert_eq!(conns[0].remote_address, "54.254.12.34:7777");

        assert_eq!(conns[1].protocol, "UDP");
        assert_eq!(conns[1].pid, 1234);

        assert_eq!(conns[2].process_name, "node.exe");
        assert_eq!(conns[2].game_name, None);
        assert_eq!(conns[2].classification, EndpointClassification::Unverified);
    }
}
