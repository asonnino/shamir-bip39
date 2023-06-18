mod bip39;
mod gf256;
mod shamir;
mod utils;

use std::str::FromStr;

use bip39::{Bip39Dictionary, Bip39Secret};
use clap::{command, Parser};
use eyre::Result;
use shamir::ShamirSecretSharing;

use crate::bip39::Bip39Share;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(
        long,
        value_name = "FILE",
        default_value = "assets/bip39-en.txt",
        global = true
    )]
    dictionary_path: String,

    #[clap(subcommand)]
    operation: Operation,
}

#[derive(Parser)]
enum Operation {
    Split {
        #[clap(short, long, value_name = "STR")]
        secret: String,
        #[clap(short, long, value_name = "INT")]
        n: u8,
        #[clap(short, long, value_name = "INT")]
        t: u8,
    },

    Reconstruct {
        /// Shares are provided in the following format:
        /// "INDEX_I WORD_1 .. WORD_2, INDEX_K WORD_1 .. WORD_2, ..."
        #[clap(short, long, value_name = "[STR]", value_delimiter = ',', num_args(2..))]
        shares: Vec<ShareString>,
    },
}

#[derive(Clone)]
struct ShareString {
    index: u8,
    secret: String,
}

impl FromStr for ShareString {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(' ');
        let index = parts.next().unwrap().parse()?;
        let secret = parts.into_iter().collect::<Vec<_>>().join(" ");
        Ok(Self { index, secret })
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    let dictionary = Bip39Dictionary::load(&args.dictionary_path)?;

    match args.operation {
        Operation::Split { secret, n, t } => {
            let secret = Bip39Secret::from_mnemonic(&secret, &dictionary)?;
            secret.is_valid()?;
            let shares = secret.split(n, t, &mut rand::thread_rng());
            for share in shares {
                println!("{}", share.to_mnemonic(&dictionary));
            }
        }
        Operation::Reconstruct { shares } => {
            let shares = shares
                .into_iter()
                .map(|share| Bip39Share::from_mnemonic(share.index, &share.secret, &dictionary))
                .collect::<Result<Vec<_>>>()?;

            for share in &shares {
                share.is_valid()?;
            }

            let secret = Bip39Secret::reconstruct(&shares);
            println!("{}", secret.to_mnemonic(&dictionary));
        }
    }

    Ok(())
}
