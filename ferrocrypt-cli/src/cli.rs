use clap::{Parser, Subcommand};
use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    generate_asymmetric_key_pair, hybrid_encryption, symmetric_encryption, CryptoError,
};

use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

/// - If run with a subcommand (e.g. `fcr symmetric ...`), executes that directly.
/// - If run with no subcommand (just `./fcr`), enters an interactive REPL mode.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Subcommand to run. If omitted, the CLI starts in interactive mode.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Hybrid: Generate a private/public key pair
    Keygen {
        #[arg(short, long)]
        outpath: String,

        #[arg(short, long)]
        passphrase: String,

        /// Length of the key in bits for the key pair generation
        #[arg(short = 'b', long, default_value_t = 4096)]
        bit_size: u32,
    },

    /// Hybrid: Encrypt/decrypt using public/private key
    Hybrid {
        #[arg(short, long)]
        inpath: String,

        #[arg(short, long)]
        outpath: String,

        /// Path to the public key (encrypt) or private key (decrypt)
        #[arg(short, long)]
        key: String,

        /// Passphrase to decrypt the private key (if needed)
        #[arg(short, long, default_value = "")]
        passphrase: String,
    },

    /// Symmetric: Encrypt/decrypt using passphrase-derived key
    Symmetric {
        #[arg(short, long)]
        inpath: String,

        #[arg(short, long)]
        outpath: String,

        /// Passphrase to derive the symmetric key
        #[arg(short, long)]
        passphrase: String,

        /// For large input file(s) that cannot fit into available RAM
        #[arg(short, long)]
        large: bool,
    },
}

pub fn run() -> Result<(), CryptoError> {
    let cli = Cli::parse();

    if let Some(cmd) = cli.command {
        // Normal, non-interactive mode (subcommand given)
        run_command(cmd)?;
    } else {
        // No subcommand: enter interactive REPL mode
        interactive_mode()?;
    }

    Ok(())
}

/// Execute a single `Command` value.
fn run_command(cmd: Command) -> Result<(), CryptoError> {
    match cmd {
        Command::Keygen {
            outpath,
            passphrase,
            bit_size,
        } => {
            let passphrase = SecretString::from(passphrase);
            generate_asymmetric_key_pair(bit_size, &passphrase, &outpath)?;
        }

        Command::Hybrid {
            inpath,
            outpath,
            mut key,
            passphrase,
        } => {
            let passphrase = SecretString::from(passphrase);
            hybrid_encryption(&inpath, &outpath, &mut key, &passphrase)?;
        }

        Command::Symmetric {
            inpath,
            outpath,
            passphrase,
            large,
        } => {
            let passphrase = SecretString::from(passphrase);
            symmetric_encryption(&inpath, &outpath, &passphrase, large)?;
        }
    }

    Ok(())
}

fn interactive_mode() -> Result<(), CryptoError> {
    println!("\nFerrocrypt interactive mode\n");
    println!("Type `keygen`, `hybrid`, or `symmetric` with flags, or `quit` to exit.\n");

    let mut rl = match DefaultEditor::new() {
        Ok(editor) => editor,
        Err(e) => {
            eprintln!("Failed to initialize line editor: {e}");
            // Do not treat this as a crypto failure; just exit REPL gracefully.
            return Ok(());
        }
    };

    loop {
        match rl.readline("fcr> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                if line.eq_ignore_ascii_case("exit") || line.eq_ignore_ascii_case("quit") {
                    break;
                }

                // Save to history so up/down arrows work.
                if let Err(e) = rl.add_history_entry(line) {
                    eprintln!("Failed to add history entry: {e}");
                }

                // Use shell-like splitting so quotes work (e.g., -p "my secret pass").
                let parts: Vec<String> = match shell_words::split(line) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Parse error: {e}");
                        continue;
                    }
                };

                // Build an argv-style iterator: program name + typed args.
                let args = std::iter::once("fcr".to_string()).chain(parts.into_iter());

                // Try to parse as if it was a normal CLI invocation.
                match Cli::try_parse_from(args) {
                    Ok(cli) => {
                        if let Some(cmd) = cli.command {
                            if let Err(e) = run_command(cmd) {
                                eprintln!("Error: {e}");
                            }
                        } else {
                            eprintln!("No command given. Try: keygen, hybrid, symmetric");
                        }
                    }
                    Err(e) => {
                        if let Err(print_err) = e.print() {
                            eprintln!("Failed to print error: {print_err}");
                        }
                    }
                }
            }

            Err(ReadlineError::Interrupted) => {
                // Ctrl+C
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                // Ctrl+D
                println!();
                break;
            }
            Err(err) => {
                eprintln!("Error: {err}");
                break;
            }
        }
    }

    Ok(())
}
