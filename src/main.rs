mod bip39;
mod gf256;
mod shamir;
mod utils;

use std::str::FromStr;

use bip39::{Bip39Dictionary, Bip39Secret};
use clap::{command, Parser};
use color_eyre::owo_colors::OwoColorize;
use eyre::{ensure, Result};
use itertools::Itertools;
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
    /// Split a bip-39 secret into shares.
    Split {
        /// The bip-39 secret to split.
        #[clap(short, long, value_name = "STR")]
        secret: String,
        /// The number of shares to generate.
        #[clap(short, long, value_name = "INT")]
        n: u8,
        /// The threshold number of shares required to reconstruct the secret.
        #[clap(short, long, value_name = "INT")]
        t: u8,
        /// Double-check that the secret can be reconstructed from the shares.
        #[clap(short, long, value_name = "FLAG", default_value = "true")]
        check: bool,
    },
    /// Reconstruct a bip-39 secret from shares.
    Reconstruct {
        /// Shares are provided in the following format:
        /// "INDEX_I WORD_1 .. WORD_2,INDEX_K WORD_1 .. WORD_2, ..."
        #[clap(short, long, value_name = "[STR]", value_delimiter = ',', num_args(1..))]
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
        let secret = parts.collect::<Vec<_>>().join(" ");
        Ok(Self { index, secret })
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    // Load the bip-39 dictionary.
    let dictionary = Bip39Dictionary::load(&args.dictionary_path)?;

    match args.operation {
        Operation::Split {
            secret,
            n,
            t,
            check,
        } => {
            ensure!(n > 0, "There must be at least one share");
            ensure!(t > 0, "The threshold must be at least one");
            ensure!(t <= n, "The threshold must be lower than the total shares");

            // Generate a bip-39 secret from the input mnemonic.
            let secret = Bip39Secret::from_mnemonic(&secret, &dictionary)?;

            // Ensure the secret is valid with respect to the bip-39 standard.
            secret.is_valid()?;
            // Split the secret into the specified number of shares.
            let shares = secret.split(n, t, &mut rand::thread_rng());

            // Print the shares to stdout.
            for (i, share) in shares.iter().enumerate() {
                let heading = format!("Share {}/{}", i + 1, n);
                let mnemonic = share.to_mnemonic(&dictionary);

                println!("\n{}", heading.bold().green(),);
                for (j, word) in mnemonic.split_whitespace().enumerate() {
                    println!("{:2} {}", (j + 1).to_string().bold(), word);
                }
                println!();
            }
            let s = format!("The secret can be reconstructed from any {t} out of {n} shares");
            println!("{}", s.bold());

            // Double-check that the secret can be reconstructed from the shares.
            if check {
                print!("\nDouble-checking that the secret can be reconstructed from the shares...");
                for share in &shares {
                    assert!(share.is_valid().is_ok(), "The share is invalid");
                }

                for combination in (0..n).combinations(t as usize) {
                    let shares = combination
                        .into_iter()
                        .map(|i| &shares[i as usize])
                        .collect::<Vec<_>>();
                    let reconstructed = Bip39Secret::reconstruct(&shares);
                    assert!(
                        secret == reconstructed,
                        "The secret could not be reconstructed from the shares"
                    );
                }
                println!(" [{}]\n", "ok".green().bold());
            }
        }
        Operation::Reconstruct { shares } => {
            // Generate a bip-39 share from each input mnemonic.
            let shares = shares
                .into_iter()
                .map(|share| Bip39Share::from_mnemonic(share.index, &share.secret, &dictionary))
                .collect::<Result<Vec<_>>>()?;

            // Ensure each share is valid with respect to the bip-39 standard.
            for share in &shares {
                share.is_valid()?;
            }

            // Reconstruct the master secret from the shares.
            let secret = Bip39Secret::reconstruct(&shares);
            let mnemonic = secret.to_mnemonic(&dictionary);

            // Print the master secret to stdout.
            println!("\n{}", "Master secret:".green().bold());
            for (j, word) in mnemonic.split_whitespace().enumerate() {
                println!("{:2} {}", (j + 1).to_string().bold(), word);
            }
            println!();
        }
    }

    Ok(())
}
