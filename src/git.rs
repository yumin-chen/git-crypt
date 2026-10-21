use crate::crypto::CryptoKey;
use crate::error::{GitCryptError, Result};
use gix::Repository;
use std::io::{self, Read, Write};
use std::path::Path;

pub struct GitRepo {
    repo: Repository,
}

impl GitRepo {
    /// Open repository at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let repo = gix::discover(path).map_err(|_| GitCryptError::NotInGitRepo)?;
        Ok(Self { repo })
    }

    /// Get the git directory path
    pub fn git_dir(&self) -> &Path {
        self.repo.git_dir()
    }

    /// Configure git filters for git-crypt
    pub fn configure_filters(&self) -> Result<()> {
        let config_path = self.repo.git_dir().join("config");
        let mut config = if config_path.exists() {
            gix::config::File::from_path_no_includes(config_path.clone(), gix::config::Source::Local)
                .map_err(|e| GitCryptError::Git(e.to_string()))?
        } else {
            gix::config::File::new(gix::config::file::Metadata::from(gix::config::Source::Local))
        };

        config.set_raw_value(&"filter.git-crypt.clean", "git-crypt clean")
            .map_err(|e| GitCryptError::Git(e.to_string()))?;
        config.set_raw_value(&"filter.git-crypt.smudge", "git-crypt smudge")
            .map_err(|e| GitCryptError::Git(e.to_string()))?;
        config.set_raw_value(&"filter.git-crypt.diff", "git-crypt diff")
            .map_err(|e| GitCryptError::Git(e.to_string()))?;
        config.set_raw_value(&"filter.git-crypt.required", "true")
            .map_err(|e| GitCryptError::Git(e.to_string()))?;

        let mut file = std::fs::File::create(&config_path)?;
        config.write_to(&mut file)?;

        Ok(())
    }

    /// Remove git-crypt filters
    pub fn remove_filters(&self) -> Result<()> {
        let config_path = self.repo.git_dir().join("config");
        if !config_path.exists() {
            return Ok(());
        }

        let mut config = gix::config::File::from_path_no_includes(config_path.clone(), gix::config::Source::Local)
            .map_err(|e| GitCryptError::Git(e.to_string()))?;

        let _ = config.remove_section("filter", Some("git-crypt".into()));

        let mut file = std::fs::File::create(&config_path)?;
        config.write_to(&mut file)?;

        Ok(())
    }

    /// Get repository root path
    #[allow(dead_code)]
    pub fn workdir(&self) -> Result<&Path> {
        self.repo.work_dir().ok_or(GitCryptError::Other(
            "Repository has no working directory".into(),
        ))
    }
}

/// Clean filter: encrypt file content
pub fn clean_filter(key: &CryptoKey) -> Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    // Check if already encrypted (has magic header)
    if CryptoKey::is_encrypted(&input) {
        io::stdout().write_all(&input)?;
        return Ok(());
    }

    let encrypted = key.encrypt(&input)?;

    // Write encrypted data to stdout
    io::stdout().write_all(&encrypted)?;

    Ok(())
}

/// Smudge filter: decrypt file content
pub fn smudge_filter(key: &CryptoKey) -> Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    // Check if encrypted
    if !CryptoKey::is_encrypted(&input) {
        io::stdout().write_all(&input)?;
        return Ok(());
    }

    let decrypted = key.decrypt(&input)?;

    // Write decrypted data to stdout
    io::stdout().write_all(&decrypted)?;

    Ok(())
}

/// Diff filter: show that file is encrypted
pub fn diff_filter() -> Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    if CryptoKey::is_encrypted(&input) {
        writeln!(
            io::stdout(),
            "*** This file is encrypted with git-crypt ***"
        )?;
    } else {
        io::stdout().write_all(&input)?;
    }

    Ok(())
}
