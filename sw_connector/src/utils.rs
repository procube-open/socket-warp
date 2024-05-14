use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::x509::X509;

pub fn pem_to_der(pem_data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let cert = X509::from_pem(&pem_data).expect("Failed to parse PEM");
  cert.to_der()
}

pub fn key_to_der(key_data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
  let private_key = PKey::private_key_from_pem(&key_data).expect("Failed to load private key");
  private_key.private_key_to_der()
}
