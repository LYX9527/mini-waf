use chrono::Local;

#[allow(dead_code)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
    Daemon,
}

pub fn print_log(level: LogLevel, prefix: &str, msg: &str) {
    let time = Local::now().format("%H:%M:%S");
    let color_code = match level {
        LogLevel::Info => "\x1b[36m",    // Cyan
        LogLevel::Success => "\x1b[32m", // Green
        LogLevel::Warning => "\x1b[33m", // Yellow
        LogLevel::Error => "\x1b[31m",   // Red
        LogLevel::Daemon => "\x1b[35m",  // Magenta
    };
    let reset = "\x1b[0m";
    // Format: [14:08:19] [SYSTEM] 启动 Rust 企业级 WAF
    println!("\x1b[90m[{}]\x1b[0m {}{:<10}{}\x1b[0m {}", time, color_code, format!("[{}]", prefix), reset, msg);
}

#[macro_export]
macro_rules! log_info {
    ($prefix:expr, $($arg:tt)*) => {
        $crate::logger::print_log($crate::logger::LogLevel::Info, $prefix, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_success {
    ($prefix:expr, $($arg:tt)*) => {
        $crate::logger::print_log($crate::logger::LogLevel::Success, $prefix, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($prefix:expr, $($arg:tt)*) => {
        $crate::logger::print_log($crate::logger::LogLevel::Warning, $prefix, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($prefix:expr, $($arg:tt)*) => {
        $crate::logger::print_log($crate::logger::LogLevel::Error, $prefix, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_daemon {
    ($prefix:expr, $($arg:tt)*) => {
        $crate::logger::print_log($crate::logger::LogLevel::Daemon, $prefix, &format!($($arg)*))
    };
}
