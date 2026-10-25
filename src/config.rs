use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const APP_NAME: &str = "factum";
pub const ENV_KEYS: [&str; 3] = ["LOG_LEVEL", "FACTUM_DB", "FACTUM_SEAL_DIR"];

#[derive(Debug, Clone)]
pub struct Config {
    pub log_level: String,
    pub db_path: PathBuf,
    /// external copies of seals; None = the GUI setting or <database folder>/seals (see SealService::seal_dir)
    pub seal_dir: Option<PathBuf>,
}

/// The per-user configuration folder (Linux: ~/.config/factum, macOS: ~/Library/Application Support/factum,
/// Windows: %LOCALAPPDATA%\factum), the same folders platformdirs uses.
pub fn user_config_dir() -> PathBuf {
    let base = if cfg!(windows) {
        dirs::data_local_dir()
    } else {
        dirs::config_dir()
    };
    base.unwrap_or_else(|| PathBuf::from(".")).join(APP_NAME)
}

/// The per-user data folder (Linux: ~/.local/share/factum, macOS: ~/Library/Application Support/factum,
/// Windows: %LOCALAPPDATA%\factum).
pub fn user_data_dir() -> PathBuf {
    let base = if cfg!(windows) {
        dirs::data_local_dir()
    } else {
        dirs::data_dir()
    };
    base.unwrap_or_else(|| PathBuf::from(".")).join(APP_NAME)
}

pub fn expand_user(path: &str) -> PathBuf {
    if path == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from(path));
    }
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

/// The values of a .env file, read like python-dotenv does: `KEY=value`, optional `export`, quotes, comments.
pub fn dotenv_values(path: &Path) -> HashMap<String, String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    parse_dotenv(&text)
}

pub fn parse_dotenv(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .map(str::trim_start)
            .unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        let parsed = if let Some(quote) = value.chars().next().filter(|c| *c == '"' || *c == '\'') {
            match value[1..].find(quote) {
                Some(end) => {
                    let inner = &value[1..1 + end];
                    if quote == '"' {
                        inner
                            .replace("\\n", "\n")
                            .replace("\\\"", "\"")
                            .replace("\\\\", "\\")
                    } else {
                        inner.to_string()
                    }
                }
                None => value.to_string(),
            }
        } else {
            // an unquoted value ends at a comment that follows whitespace
            match value.find(" #").or_else(|| value.find("\t#")) {
                Some(index) => value[..index].trim_end().to_string(),
                None => value.to_string(),
            }
        };
        values.insert(key.to_string(), parsed);
    }
    values
}

impl Config {
    pub fn load() -> Self {
        // later sources override earlier ones: user config dir, current working directory, process environment
        let mut env = dotenv_values(&user_config_dir().join(".env"));
        env.extend(dotenv_values(Path::new(".env")));
        for key in ENV_KEYS {
            if let Ok(value) = std::env::var(key) {
                env.insert(key.to_string(), value);
            }
        }
        Self::from_values(&env)
    }

    pub fn from_values(env: &HashMap<String, String>) -> Self {
        let non_empty = |key: &str| env.get(key).filter(|value| !value.is_empty());
        let log_level = non_empty("LOG_LEVEL")
            .map(|level| level.to_uppercase())
            .unwrap_or_else(|| "INFO".into());
        let db_path = non_empty("FACTUM_DB")
            .map(|path| expand_user(path))
            .unwrap_or_else(|| user_data_dir().join("factum.db"));
        let seal_dir = non_empty("FACTUM_SEAL_DIR").map(|path| expand_user(path));
        Self {
            log_level,
            db_path,
            seal_dir,
        }
    }
}

static SETTINGS: OnceLock<Config> = OnceLock::new();

/// The configuration of this process, read once.
pub fn settings() -> &'static Config {
    SETTINGS.get_or_init(Config::load)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_parsing() {
        let values = parse_dotenv(
            "# comment\nLOG_LEVEL=debug # inline\nexport FACTUM_DB=\"/a b/f.db\"\nX='y #z'\nbroken\n",
        );
        assert_eq!(values["LOG_LEVEL"], "debug");
        assert_eq!(values["FACTUM_DB"], "/a b/f.db");
        assert_eq!(values["X"], "y #z");
        assert!(!values.contains_key("broken"));
    }

    #[test]
    fn seal_dir_from_values() {
        let mut env = HashMap::new();
        assert_eq!(Config::from_values(&env).seal_dir, None);
        env.insert(
            "FACTUM_SEAL_DIR".to_string(),
            "/media/usb/seals".to_string(),
        );
        assert_eq!(
            Config::from_values(&env).seal_dir,
            Some(PathBuf::from("/media/usb/seals"))
        );
    }

    #[test]
    fn defaults() {
        let config = Config::from_values(&HashMap::new());
        assert_eq!(config.log_level, "INFO");
        assert!(
            config.db_path.ends_with("factum/factum.db")
                || config.db_path.ends_with("factum\\factum.db")
        );
    }
}
