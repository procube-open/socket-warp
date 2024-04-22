use openssl::error::ErrorStack;
use openssl::x509::X509;

pub fn der_to_pem(der_data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let x509 = X509::from_der(der_data)?;
  let pem = x509.to_pem()?;
  Ok(pem)
}

pub fn get_env(key: &str, default: &str) -> String {
  let env = match std::env::var(key) {
    Ok(val) => val,
    Err(_) => default.to_string(),
  };
  return env;
}
