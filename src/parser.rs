use csv::Writer;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

#[derive(Debug, Serialize)]
struct LogEntry {
    timestamp: String,
    source_ip: String,
    protocol: String,
    src_port: Option<String>,
    dest_port: Option<String>,
}

pub struct SysLogParser {
    log_file: String,
    csv_file: String,
}

impl SysLogParser {
    pub fn new(log_file: &str, csv_file: &str) -> Self {
        log::info!("Initializing parser...");
        Self {
            log_file: log_file.to_string(),
            csv_file: csv_file.to_string(),
        }
    }

    pub fn parse(self) {
        let mut writer = Writer::from_path(self.csv_file).unwrap();
        log::info!("hmm: {}", self.log_file);
        if let Ok(lines) = Self::read_lines(self.log_file) {
            for line in lines {
                let Ok(log_entry) = line else {panic!("Couldn't read logline")};
                Self::extract_malicious_traffic(log_entry, &mut writer);
            }
        }
    }

    fn extract_malicious_traffic(log_entry: String, writer: &mut Writer<File>) {
        lazy_static! {
                static ref FIREWALL_ENTRY : Regex = Regex::new(
                    r"\[UFW BLOCK\]"
            ).unwrap();
                // TODO: Add server identifier in from config file
        static ref LOGS_DATA : Regex = Regex::new(
            r"(?<timestamp>.+) srv[0-9]+.+SRC=(?<src_ip>[0-9\.]+).+PROTO=(?<protocol>[A-Z0-9]+).+SPT=(?<src_port>[0-9]+).+DPT=(?<dst_port>[0-9]+)"
            ).unwrap();
                static ref LOGS_DATA_NO_PORTS : Regex = Regex::new(
                    r"(?<timestamp>.+) srv[0-9]+.+SRC=(?<src_ip>[0-9\.]+).+PROTO=(?<protocol>[A-Z0-9]+)"
            ).unwrap();
            }
        let result = FIREWALL_ENTRY.is_match(&log_entry);
        if result {
            log::info!("Found log line with firewall entry, attemtping to parse...");
            if let Some(captures) = LOGS_DATA.captures(&log_entry) {
                let record = LogEntry {
                    timestamp: captures["timestamp"].to_string(),
                    src_port: Some(captures["src_port"].to_string()),
                    dest_port: Some(captures["dst_port"].to_string()),
                    source_ip: captures["src_ip"].to_string(),
                    protocol: captures["protocol"].to_string(),
                };
                Self::write_csv(writer, record).unwrap();
                log::info!("Parsed line successfully!");
            } else {
                log::info!("Line didn't include src or dst ports, retrying with another regex...");
                let captures = LOGS_DATA_NO_PORTS.captures(&log_entry).unwrap();
                let record = LogEntry {
                    timestamp: captures["timestamp"].to_string(),
                    src_port: None,
                    dest_port: None,
                    source_ip: captures["src_ip"].to_string(),
                    protocol: captures["protocol"].to_string(),
                };
                Self::write_csv(writer, record).unwrap();
                log::info!("Parsed line successfully!");
            };
        }
    }

    fn write_csv(writer: &mut Writer<File>, record: LogEntry) -> Result<(), Box<dyn Error>> {
        writer.serialize(record)?;
        Ok(())
    }

    fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where
        P: AsRef<Path>,
    {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }
}
