use clap::Parser;

use factum::cli::{self, Args};
use factum::{Db, config};

fn main() {
    let args = Args::parse();
    let level = args
        .log_level
        .clone()
        .unwrap_or_else(|| config::settings().log_level.clone());
    factum::logger::init(&level);
    log::debug!("Starting Factum with level: {}", level.to_uppercase());

    let db = match Db::open_default() {
        Ok(db) => db,
        Err(e) => {
            log::error!("{e}");
            std::process::exit(1);
        }
    };
    // up to 2.7.1 the GUI kept the seal folder in the database
    let env_file = config::user_env_path();
    let notice = match factum::seals::migrate_seal_dir_setting(&db, &env_file) {
        Ok(moved) => moved.map(|folder| {
            format!(
                "The seal folder {folder} was taken from this database and is now set in {}. Check that it is the \
                 folder you chose.",
                env_file.display()
            )
        }),
        Err(e) => {
            log::warn!("{e}");
            None
        }
    };
    if args.gui {
        run_gui(db, notice);
    } else {
        let mut stdout = std::io::stdout().lock();
        let code = cli::run(&db, &args, None, None, &mut stdout);
        drop(db);
        std::process::exit(code);
    }
}

/// `notice`: shown once in a message when the GUI starts
#[cfg(feature = "gui")]
fn run_gui(db: Db, notice: Option<String>) {
    #[cfg(windows)]
    detach_console();
    if let Err(e) = factum::gui::run(db, notice) {
        log::error!("The GUI could not be started: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "gui"))]
fn run_gui(_db: Db, _notice: Option<String>) {
    log::error!("This factum binary was built without the GUI (cargo feature 'gui').");
    std::process::exit(1);
}

/// A shortcut that starts `factum --gui` gets a console window of its own; close it. A console the GUI was
/// started from (cmd, PowerShell) is shared with other processes and stays.
#[cfg(all(windows, feature = "gui"))]
fn detach_console() {
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
    let mut processes = [0u32; 2];
    // SAFETY: the buffer is valid for the given length
    let count = unsafe { GetConsoleProcessList(processes.as_mut_ptr(), processes.len() as u32) };
    if count == 1 {
        // SAFETY: no handles to the console are held at this point
        unsafe { FreeConsole() };
    }
}
