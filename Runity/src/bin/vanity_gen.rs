use structopt::StructOpt;
use serde::{Deserialize, Serialize};
use vanity_project::generator::VanityGenerator;
use hex;

#[derive(Serialize, Deserialize)]
struct KeyPair {
    address: [u8; 20],
    secret: [u8; 32],
}

#[derive(Serialize)]
struct KeyPairOutput {
    address: String,
    secret: String,
}

#[derive(StructOpt)]
struct Opts {
    #[structopt(long, default_value = "")]
    prefix: String,
    #[structopt(long, default_value = "")]
    suffix: String,
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::from_args();
    let prefix = if opts.prefix.is_empty() { None } else { Some(opts.prefix) };
    let suffix = if opts.suffix.is_empty() { None } else { Some(opts.suffix) };

    let generator = VanityGenerator::new(prefix, suffix)?;
    let keypair = generator.generate()?;

    let output = KeyPairOutput {
        address: format!("0x{}", hex::encode(keypair.address)),
        secret: format!("0x{}", hex::encode(keypair.secret)),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}