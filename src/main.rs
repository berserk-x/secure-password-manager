use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use rand::Rng;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Serialize, Deserialize)]
struct PasswordEntry {
    name: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PasswordStore {
    entries: Vec<PasswordEntry>,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new password entry
    Add {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        username: String,
    },
    /// List all password entries
    List,
    /// Get a specific password entry
    Get {
        #[arg(short, long)]
        name: String,
        #[arg(short, long, default_value_t = false)]
        show_password: bool,
    },
    /// Remove a password entry
    Remove {
        #[arg(short, long)]
        name: String,
    },
}

struct PasswordManager {
    store_path: PathBuf,
    cipher: Option<Aes256Gcm>,
    last_auth_time: u64,
}

impl PasswordManager {
    const AUTH_TIMEOUT: u64 = 300; // 5 minutes in seconds

    fn new() -> io::Result<Self> {
        let proj_dirs = ProjectDirs::from("com", "secure", "password-manager")
            .expect("Failed to get project directories");
        let data_dir = proj_dirs.data_dir();
        fs::create_dir_all(data_dir)?;

        let store_path = data_dir.join("passwords.enc");
        
        Ok(Self { 
            store_path, 
            cipher: None,
            last_auth_time: 0,
        })
    }

    fn authenticate(&mut self) -> io::Result<()> {
        let master_password = prompt_password("Enter master password: ")?;
        let key = Self::derive_key(&master_password);
        self.cipher = Some(Aes256Gcm::new(&key.into()));
        self.last_auth_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(())
    }

    fn check_auth(&mut self) -> io::Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if self.cipher.is_none() || current_time - self.last_auth_time > Self::AUTH_TIMEOUT {
            self.authenticate()?;
        }
        Ok(())
    }

    fn derive_key(password: &str) -> [u8; 32] {
        let mut key = [0u8; 32];
        let mut hasher = blake3::Hasher::new();
        hasher.update(password.as_bytes());
        hasher.finalize_xof().fill(&mut key);
        key
    }

    fn load_store(&self) -> io::Result<PasswordStore> {
        if !self.store_path.exists() {
            return Ok(PasswordStore { entries: Vec::new() });
        }

        let cipher = self.cipher.as_ref().ok_or_else(|| 
            io::Error::new(io::ErrorKind::PermissionDenied, "Not authenticated")
        )?;

        let mut file = File::open(&self.store_path)?;
        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)?;

        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];

        let decrypted_data = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Decryption failed"))?;

        let store: PasswordStore = serde_json::from_slice(&decrypted_data)?;
        Ok(store)
    }

    fn save_store(&self, store: &PasswordStore) -> io::Result<()> {
        let cipher = self.cipher.as_ref().ok_or_else(|| 
            io::Error::new(io::ErrorKind::PermissionDenied, "Not authenticated")
        )?;

        let data = serde_json::to_vec(store)?;
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        let encrypted_data = cipher
            .encrypt(nonce, data.as_ref())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

        let mut file = File::create(&self.store_path)?;
        file.write_all(nonce)?;
        file.write_all(&encrypted_data)?;
        Ok(())
    }

    fn add_entry(&mut self, name: String, username: String) -> io::Result<()> {
        self.check_auth()?;
        let mut store = self.load_store()?;
        let password = prompt_password("Enter password: ")?;

        let entry = PasswordEntry {
            name,
            username,
            password,
        };

        store.entries.push(entry);
        self.save_store(&store)
    }

    fn list_entries(&mut self) -> io::Result<()> {
        self.check_auth()?;
        let store = self.load_store()?;
        for entry in store.entries {
            println!("Name: {}", entry.name);
            println!("Username: {}", entry.username);
            println!("---");
        }
        Ok(())
    }

    fn get_entry(&mut self, name: &str, show_password: bool) -> io::Result<()> {
        self.check_auth()?;
        let store = self.load_store()?;
        if let Some(entry) = store.entries.iter().find(|e| e.name == name) {
            println!("Name: {}", entry.name);
            println!("Username: {}", entry.username);
            if show_password {
                println!("Password: {}", entry.password);
            } else {
                println!("Password: ********");
            }
        } else {
            println!("Entry not found");
        }
        Ok(())
    }

    fn remove_entry(&mut self, name: &str) -> io::Result<()> {
        self.check_auth()?;
        let mut store = self.load_store()?;
        store.entries.retain(|e| e.name != name);
        self.save_store(&store)
    }
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let mut manager = PasswordManager::new()?;

    match cli.command {
        Commands::Add { name, username } => {
            manager.add_entry(name, username)?;
        }
        Commands::List => {
            manager.list_entries()?;
        }
        Commands::Get { name, show_password } => {
            manager.get_entry(&name, show_password)?;
        }
        Commands::Remove { name } => {
            manager.remove_entry(&name)?;
        }
    }

    Ok(())
}