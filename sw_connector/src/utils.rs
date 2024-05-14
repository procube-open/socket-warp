use base64::{engine::general_purpose, Engine as _};
use std::error::Error;

// Function to convert PEM data to DER
pub fn pem_to_der(pem_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
  let pem_str = String::from_utf8_lossy(pem_data);
  let base64_str = pem_str.lines().filter(|line| !line.starts_with("-----")).collect::<String>();
  let der_data = general_purpose::STANDARD.decode(&base64_str)?;
  Ok(der_data)
}

// Function to load private key from file and convert to DER
pub fn key_to_der(key_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
  let key_str = String::from_utf8_lossy(&key_data);
  let key_lines: Vec<&str> = key_str.lines().collect();
  let key_base64: String = key_lines.into_iter().filter(|line| !line.starts_with("-----")).collect();
  let der_data = general_purpose::STANDARD.decode(&key_base64)?;
  Ok(der_data)
}
