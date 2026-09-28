use structopt::StructOpt;
use runity::generator::VanityGenerator;
use hex;

#[derive(StructOpt)]
struct Opts {
    /// Hex prefix without 0x
    #[structopt(long, default_value = "")]
    prefix: String,
    /// Hex suffix without 0x
    #[structopt(long, default_value = "")]
    suffix: String,
    /// Print private key. Off by default.
    #[structopt(long)]
    show_secret: bool,
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::from_args();
    let prefix = if opts.prefix.is_empty() { None } else { Some(opts.prefix) };
    let suffix = if opts.suffix.is_empty() { None } else { Some(opts.suffix) };
    let gen = VanityGenerator::new(prefix, suffix)?;
    let kp = gen.generate()?;
    let address = format!("0x{}", hex::encode(kp.address));
    if opts.show_secret {
        println!(
            "{{\"address\":\"{}\",\"secret\":\"0x{}\"}}",
            address,
            hex::encode(kp.secret)
        );
    } else {
        println!("{{\"address\":\"{}"}}", address);
    }
    Ok(())
}
