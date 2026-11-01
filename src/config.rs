use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const APP_NAME: &str = "factum";
pub const ENV_KEYS: [&str; 2] = ["LOG_LEVEL", "FACTUM_DB"];
/// external copies of seals; read anew each time (see seal_dir), not part of Config
pub const SEAL_DIR_KEY: &str = "FACTUM_SEAL_DIR";

#[derive(Debug, Clone)]
pub struct Config {
    pub log_level: String,
    pub db_path: PathBuf,
    /// FACTUM_DB (environment or user .env) chose the path
    pub db_from_env: bool,
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

/// The .env in the user config folder: the only .env factum reads, and where the GUI stores the seal folder.
pub fn user_env_path() -> PathBuf {
    user_config_dir().join(".env")
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
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\"))
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
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
        let line = line.strip_prefix("export ").map(str::trim_start).unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        let parsed = if let Some(rest) = value.strip_prefix('"') {
            double_quoted(rest).unwrap_or_else(|| value.to_string())
        } else if let Some(rest) = value.strip_prefix('\'') {
            match rest.find('\'') {
                Some(end) => rest[..end].to_string(),
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

/// The text of a double-quoted value up to its closing quote, with \n, \" and \\ decoded in one pass.
fn double_quoted(rest: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                escaped @ ('"' | '\\') => out.push(escaped),
                other => {
                    out.push('\\');
                    out.push(other);
                }
            },
            _ => out.push(c),
        }
    }
    None
}

/// A value as .env text that parse_dotenv and python-dotenv read back unchanged. Plain where possible: both take
/// plain values literally, while python-dotenv decodes \\ in single quotes too and reads a backslash before a
/// closing quote as an escaped quote. Anything else is double-quoted with \\, \" and \n escaped.
fn quote_dotenv(value: &str) -> String {
    let plain = !value.is_empty() && !value.contains(|c: char| c.is_whitespace() || matches!(c, '#' | '"' | '\''));
    if plain {
        return value.to_string();
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
    format!("\"{escaped}\"")
}

/// Sets `key` in a .env file, or removes it with None; every other line stays as it is, and so do the line
/// endings. A symlinked .env is written through to its target.
pub fn set_dotenv_value(path: &Path, key: &str, value: Option<&str>) -> std::io::Result<()> {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let path = path.as_path();
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        // never replace a file that could not be read: it holds the user's other settings
        Err(e) => return Err(e),
    };
    let mut lines: Vec<String> = text
        .lines()
        .filter(|raw| {
            let line = raw.trim();
            let line = line.strip_prefix("export ").map(str::trim_start).unwrap_or(line);
            line.starts_with('#') || line.split_once('=').is_none_or(|(k, _)| k.trim() != key)
        })
        .map(str::to_string)
        .collect();
    if let Some(value) = value {
        lines.push(format!("{key}={}", quote_dotenv(value)));
    }
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut content = lines.join(newline);
    if !content.is_empty() {
        content.push_str(newline);
    }
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    crate::files::write_atomically(path, content.as_bytes())
}

/// Sets FACTUM_SEAL_DIR in a .env file (None removes it). Trailing separators are dropped (not from a root such as
/// `E:\` or `/`), so a quoted folder never ends in a backslash, which python-dotenv cannot read.
pub fn set_seal_dir(env_file: &Path, folder: Option<&str>) -> std::io::Result<()> {
    let folder = folder.map(|folder| {
        let trimmed = folder.trim_end_matches(['/', '\\']);
        if trimmed.is_empty() || trimmed.ends_with(':') {
            folder
        } else {
            trimmed
        }
    });
    set_dotenv_value(env_file, SEAL_DIR_KEY, folder)
}

/// FACTUM_SEAL_DIR of the process environment; it overrides the user config and cannot be changed in the GUI.
pub fn env_seal_dir() -> Option<PathBuf> {
    std::env::var(SEAL_DIR_KEY)
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| expand_user(&value))
}

/// FACTUM_SEAL_DIR of a .env file (the user config's is the GUI's seal folder setting).
pub fn file_seal_dir(env_file: &Path) -> Option<PathBuf> {
    dotenv_values(env_file)
        .remove(SEAL_DIR_KEY)
        .filter(|value| !value.is_empty())
        .map(|value| expand_user(&value))
}

/// The configured seal folder: the process environment, else the user config. Read anew on every call, so a
/// change made in the GUI applies at once; never taken from the database, which the verifier checks.
pub fn seal_dir() -> Option<PathBuf> {
    env_seal_dir().or_else(|| file_seal_dir(&user_env_path()))
}

impl Config {
    pub fn load() -> Self {
        // the process environment overrides the user config; a .env in the current directory is not read, so
        // the folder factum happens to be started from cannot change its database
        let mut env = dotenv_values(&user_env_path());
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
        let db_from_env = non_empty("FACTUM_DB");
        let db_path = db_from_env
            .map(|path| expand_user(path))
            .unwrap_or_else(|| user_data_dir().join("factum.db"));
        Self {
            log_level,
            db_path,
            db_from_env: db_from_env.is_some(),
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
        let values =
            parse_dotenv("# comment\nLOG_LEVEL=debug # inline\nexport FACTUM_DB=\"/a b/f.db\"\nX='y #z'\nbroken\n");
        assert_eq!(values["LOG_LEVEL"], "debug");
        assert_eq!(values["FACTUM_DB"], "/a b/f.db");
        assert_eq!(values["X"], "y #z");
        assert!(!values.contains_key("broken"));
    }

    #[test]
    fn double_quoted_values_decode_in_one_pass() {
        // a backslash before "n" is not a newline once the backslash itself is escaped
        let values = parse_dotenv("A=\"C:\\\\new \\\"x\\\" a\\nb\"\nB=\"unterminated\n");
        assert_eq!(values["A"], "C:\\new \"x\" a\nb");
        assert_eq!(values["B"], "\"unterminated");
    }

    #[test]
    fn seal_dir_is_written_to_the_env_file_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join("config").join(".env");
        assert_eq!(file_seal_dir(&env), None);
        std::fs::create_dir(env.parent().unwrap()).unwrap();
        std::fs::write(
            &env,
            "# mine\nLOG_LEVEL=debug\nexport FACTUM_SEAL_DIR=/old\nFACTUM_DB=/x.db\n",
        )
        .unwrap();
        for folder in [
            "/media/usb stick/seals #1",
            "C:\\Users\\O'Neil\\new",
            "\\\\nas\\seals",
            "D:\\seals\\",
            "C:\\My Seals\\",
            "/a\"b",
            "x #y",
            " lead",
            "/plain",
        ] {
            set_dotenv_value(&env, SEAL_DIR_KEY, Some(folder)).unwrap();
            assert_eq!(file_seal_dir(&env), Some(PathBuf::from(folder)), "{folder}");
        }
        let values = dotenv_values(&env);
        assert_eq!(
            (values["LOG_LEVEL"].as_str(), values["FACTUM_DB"].as_str()),
            ("debug", "/x.db")
        );
        assert!(std::fs::read_to_string(&env).unwrap().starts_with("# mine\n"));
        set_dotenv_value(&env, SEAL_DIR_KEY, None).unwrap();
        assert_eq!(file_seal_dir(&env), None);
        assert_eq!(dotenv_values(&env).len(), 2);
    }

    #[test]
    fn a_missing_config_folder_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join("factum").join(".env");
        set_dotenv_value(&env, SEAL_DIR_KEY, Some("/s")).unwrap();
        assert_eq!(std::fs::read_to_string(&env).unwrap(), "FACTUM_SEAL_DIR=/s\n");
    }

    #[test]
    fn plain_values_stay_plain_and_others_are_double_quoted() {
        assert_eq!(quote_dotenv("D:\\seals\\"), "D:\\seals\\");
        assert_eq!(quote_dotenv("\\\\nas\\seals"), "\\\\nas\\seals");
        assert_eq!(quote_dotenv("/usb stick/O'Neil"), "\"/usb stick/O'Neil\"");
        assert_eq!(quote_dotenv("C:\\a b\\\"c\n"), "\"C:\\\\a b\\\\\\\"c\\n\"");
    }

    #[test]
    fn seal_folders_are_stored_without_a_trailing_separator() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join(".env");
        for (typed, stored) in [
            ("C:\\My Seals\\", "C:\\My Seals"),
            ("/media/usb/", "/media/usb"),
            ("E:\\", "E:\\"),
            ("/", "/"),
        ] {
            set_seal_dir(&env, Some(typed)).unwrap();
            assert_eq!(file_seal_dir(&env), Some(PathBuf::from(stored)), "{typed}");
        }
    }

    #[test]
    fn rewriting_keeps_crlf_line_endings() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join(".env");
        std::fs::write(&env, "LOG_LEVEL=debug\r\nFACTUM_SEAL_DIR=/old\r\n").unwrap();
        set_dotenv_value(&env, SEAL_DIR_KEY, Some("/new")).unwrap();
        assert_eq!(
            std::fs::read_to_string(&env).unwrap(),
            "LOG_LEVEL=debug\r\nFACTUM_SEAL_DIR=/new\r\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_env_file_is_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("dotfiles").join("factum.env");
        std::fs::create_dir(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "LOG_LEVEL=debug\n").unwrap();
        let link = dir.path().join(".env");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        set_dotenv_value(&link, SEAL_DIR_KEY, Some("/s")).unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(file_seal_dir(&target), Some(PathBuf::from("/s")));
    }

    #[test]
    fn defaults() {
        let config = Config::from_values(&HashMap::new());
        assert_eq!(config.log_level, "INFO");
        assert!(config.db_path.ends_with("factum/factum.db") || config.db_path.ends_with("factum\\factum.db"));
    }
}
