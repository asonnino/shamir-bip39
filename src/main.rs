pub mod bip39;
pub mod shamir;

use ::gf256::gf;

// The default gf256 type available in the gf256 crate defaults to a table-based implementation
// which risks leaking timing information due to caching. Instead we use a Barret implementation
// which provide constant-time operations (but is slower).
#[gf(polynomial = 0x11d, generator = 0x02, barret)]
pub type gf256;

fn main() {
    println!("Hello, world!");
}
