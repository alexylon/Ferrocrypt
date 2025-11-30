mod cli;

use ferrocrypt::CryptoError;

fn main() -> Result<(), CryptoError> {
    cli::run()
}
