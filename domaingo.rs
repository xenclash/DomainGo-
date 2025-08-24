use whois_rust::{WhoIs, WhoIsLookupOptions};
use chrono::{NaiveDate, Utc};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn get_expiration_date(whois_data: &str) -> Option<NaiveDate> {
    for line in whois_data.lines() {
        if line.to_lowercase().contains("expiry date") || line.to_lowercase().contains("expiration date") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 1 {
                let date_str = parts[1].trim();
                if let Ok(date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                    return Some(date);
                }
                // Try other formats if needed
            }
        }
    }
    None
}

fn main() {
    let path = "domains.txt";
    let whois = WhoIs::from_path("/usr/share/whois/servers.json").unwrap_or_default();

    if let Ok(lines) = read_lines(path) {
        for domain in lines.flatten() {
            let lookup = WhoIsLookupOptions::from_string(domain.clone());
            match whois.lookup(lookup) {
                Ok(response) => {
                    if let Some(expiry) = get_expiration_date(&response) {
                        let days_left = (expiry - Utc::today().naive_utc()).num_days();
                        println!("{} expires on {} (in {} days)", domain, expiry, days_left);
                    } else {
                        println!("Could not find expiration date for {}", domain);
                    }
                }
                Err(e) => println!("WHOIS lookup failed for {}: {}", domain, e),
            }
        }
    }
}

// Helper to read lines from a file
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}