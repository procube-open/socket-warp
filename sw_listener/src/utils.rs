use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::x509::X509;

pub fn der_to_pem(der_data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let x509 = X509::from_der(der_data).expect("Failed to parse DER");
  x509.to_pem()
}

pub fn pem_to_der(pem_data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let cert = X509::from_pem(&pem_data).expect("Failed to parse PEM");
  cert.to_der()
}

pub fn key_to_der(key_data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let private_key = PKey::private_key_from_pem(&key_data).expect("Failed to load private key");
  private_key.private_key_to_der()
}

pub fn get_env(key: &str, default: &str) -> String {
  let env = match std::env::var(key) {
    Ok(val) => val,
    Err(_) => default.to_string(),
  };
  return env;
}
