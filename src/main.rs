// Copyright (c) Alberto Sonnino
// SPDX-License-Identifier: Apache-2.0

mod bip39;
mod gf256;
mod shamir;
mod utils;

use std::str::FromStr;

use clap::{command, Parser};
use color_eyre::owo_colors::OwoColorize;
use eyre::{ensure, Result};
use prettytable::{
    format::{FormatBuilder, LinePosition, LineSeparator},
    Cell,
    Row,
    Table,
};

use crate::{
    bip39::{Bip39Dictionary, Bip39Secret, Bip39Share},
    shamir::ShamirSecretSharing,
};

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
    },
    /// Reconstruct a bip-39 secret from shares.
    Reconstruct {
        /// Shares are provided in the following format:
        /// "INDEX_I WORD_1 .. WORD_2,INDEX_K WORD_1 .. WORD_2, ..."
        #[clap(short, long, value_name = "[STR]", value_delimiter = ',', num_args(1..))]
        shares: Vec<ShareString>,
    },
    /// Ensure a string is a valid bip-39 mnemonic.
    Check {
        /// The bip-39 mnemonic to check.
        #[clap(short, long, value_name = "STR")]
        mnemonic: String,
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
        Operation::Split { secret, n, t } => {
            ensure!(n > 0, "There must be at least one share");
            ensure!(t > 0, "The threshold must be at least one");
            ensure!(t <= n, "The threshold must be lower than the total shares");

            // Generate a bip-39 secret from the input mnemonic.
            let secret = Bip39Secret::from_mnemonic(&secret, &dictionary)?;

            // Ensure the secret is valid with respect to the bip-39 standard.
            secret.is_valid()?;
            // Split the secret into the specified number of shares.
            let shares = secret.split(n, t, &mut rand::rng());

            // Print the shares to stdout.
            for (i, share) in shares.iter().enumerate() {
                let heading = format!("Share {}/{}", i + 1, n);
                pretty_print_mnemonic(&heading, &share.to_mnemonic(&dictionary));
            }
            println!("The secret can be reconstructed from any {t} out of {n} shares");

            // Double-check that the secret can be reconstructed from the shares.
            #[cfg(feature = "double-check")]
            double_check_shares(&secret, &shares, t as usize, &dictionary)?;
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

            // Print the master secret to stdout.
            pretty_print_mnemonic("Master Secret", &secret.to_mnemonic(&dictionary));
        }
        Operation::Check { mnemonic } => {
            // Ensure the mnemonic is valid with respect to the bip-39 standard.
            match Bip39Secret::from_mnemonic(&mnemonic, &dictionary)?.is_valid() {
                Ok(()) => println!("\n{}\n", "The mnemonic is valid".green()),
                Err(e) => println!("\n{} {e}\n", "Invalid mnemonic:".red().bold()),
            }
        }
    }

    Ok(())
}

/// Pretty-print a bip-39 mnemonic.
fn pretty_print_mnemonic(heading: &str, mnemonic: &str) {
    let words = mnemonic
        .split_whitespace()
        .enumerate()
        .map(|(j, word)| format!("{:2} {}", (j + 1).to_string().bold(), word))
        .collect::<Vec<_>>();

    let chunks = words
        .chunks(4)
        .map(|chunk| Cell::new(&chunk.join("\n")))
        .collect::<Vec<_>>();

    let mut table = Table::new();
    let format = FormatBuilder::new()
        .separators(
            &[LinePosition::Top, LinePosition::Bottom, LinePosition::Title],
            LineSeparator::new('-', '-', '-', '-'),
        )
        .padding(1, 1)
        .build();
    table.set_format(format);
    table.add_row(Row::new(chunks));

    println!("\n{}", heading.bold().green());
    table.printstd();
    println!();
}

/// Double-check that the secret can be reconstructed from any `t` shares.
/// Panic if the secret cannot be reconstructed.
#[cfg(feature = "double-check")]
fn double_check_shares(
    secret: &Bip39Secret,
    shares: &[Bip39Share],
    t: usize,
    dictionary: &Bip39Dictionary,
) -> std::io::Result<()> {
    use std::{fs::File, io::Write};

    use itertools::Itertools;

    // Open a file for writing the output
    let mut file = File::create("reconstructed_seed_phrases.txt")?;

    println!("\nDouble-checking secret can be reconstructed from any {t} shares...\n");

    // Write the original seed phrase to the file
    let original_seed_phrase = secret.to_mnemonic(dictionary);
    writeln!(
        file,
        "Original seed phrase:\n\"{}\"\n",
        original_seed_phrase
    )?;

    for share in shares {
        assert!(share.is_valid().is_ok(), "The share is invalid");
    }

    for (index, combination) in (0..shares.len()).combinations(t).enumerate() {
        // Adjust share indices to start from 1 instead of 0
        let adjusted_combination: Vec<_> = combination.iter().map(|&i| i + 1).collect();

        // Print the combination index
        println!(
            "Testing combination {}: {:?}",
            index + 1,
            adjusted_combination
        );

        let shares_subset = combination
            .into_iter()
            .map(|i| &shares[i])
            .collect::<Vec<_>>();

        let reconstructed = Bip39Secret::reconstruct(&shares_subset);
        assert!(
            secret == &reconstructed,
            "The secret could not be reconstructed from the shares"
        );

        // Write the reconstructed seed phrase to the file
        let reconstructed_seed_phrase = reconstructed.to_mnemonic(dictionary);
        writeln!(
            file,
            "Reconstructed seed phrase from combination {}:",
            index + 1
        )?;
        for &i in &adjusted_combination {
            writeln!(
                file,
                "  Share {}: \"{}\"",
                i,
                shares[i - 1].to_mnemonic(dictionary)
            )?; // Adjust index back for accessing shares
        }
        writeln!(
            file,
            "  Reconstructed seed phrase:\n    \"{}\"\n",
            reconstructed_seed_phrase
        )?;
    }

    println!("\nWriting results to file: reconstructed_seed_phrases.txt\n");
    println!("[{}]\n", "ok".green().bold());

    Ok(())
}
