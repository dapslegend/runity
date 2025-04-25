use secp256k1::Secp256k1;
use tiny_keccak::{Keccak, Hasher};
use rayon::prelude::*;
use regex::Regex;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use rand::rngs::OsRng;

#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    pub address: [u8; 20],
    pub secret: [u8; 32],
}

pub struct VanityGenerator {
    prefix: Option<String>,
    suffix: Option<String>,
    address_pattern: Regex,
}

impl VanityGenerator {
    pub fn new(prefix: Option<String>, suffix: Option<String>) -> anyhow::Result<Self> {
        let prefix = prefix.map(|p| p.to_lowercase());
        let suffix = suffix.map(|s| s.to_lowercase());

        let address_pattern = Regex::new(r"^[0-9a-f]{1,40}$")?;
        if let Some(ref p) = prefix {
            if !address_pattern.is_match(p) {
                return Err(anyhow::anyhow!("Invalid prefix: {}", p));
            }
        }
        if let Some(ref s) = suffix {
            if !address_pattern.is_match(s) {
                return Err(anyhow::anyhow!("Invalid suffix: {}", s));
            }
        }

        Ok(VanityGenerator {
            prefix,
            suffix,
            address_pattern,
        })
    }

    pub fn generate(&self) -> anyhow::Result<KeyPair> {
        if self.prefix.is_none() && self.suffix.is_none() {
            return Err(anyhow::anyhow!("Either prefix or suffix must be provided"));
        }

        let result: Arc<Mutex<Option<KeyPair>>> = Arc::new(Mutex::new(None));
        let thread_count = num_cpus::get();
        let secp = Secp256k1::new();

        (0..thread_count).into_par_iter().for_each(|_| {
            let mut rng = OsRng;
            loop {
                if result.lock().unwrap().is_some() {
                    break;
                }

                let (secret_key, public_key) = secp.generate_keypair(&mut rng);
                let public_key = public_key.serialize_uncompressed();
                let public_key = &public_key[1..];

                let mut keccak = Keccak::v256();
                keccak.update(public_key);
                let mut output = [0u8; 32];
                keccak.finalize(&mut output);
                let address_bytes = &output[12..32];
                let address_hex = hex::encode(address_bytes);

                let matches = match (&self.prefix, &self.suffix) {
                    (Some(p), Some(s)) => address_hex.starts_with(p) && address_hex.ends_with(s),
                    (Some(p), None) => address_hex.starts_with(p),
                    (None, Some(s)) => address_hex.ends_with(s),
                    (None, None) => false,
                };

                if matches {
                    let keypair = KeyPair {
                        address: address_bytes.try_into().unwrap(),
                        secret: secret_key.secret_bytes(),
                    };
                    *result.lock().unwrap() = Some(keypair);
                    break;
                }
            }
        });

        let result = result.lock().unwrap().take().ok_or_else(|| anyhow::anyhow!("No matching address found"))?;
        Ok(result)
    }
}