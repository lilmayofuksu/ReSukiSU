// Logger for static builds, where liblog (android_logger) is unavailable.
// Writes to /dev/kmsg, the same sink ksuinit uses.
use std::fs::OpenOptions;
use std::io::Write;

use log::{Level, LevelFilter, Log, Metadata, Record};

struct KmsgLogger {
    level: LevelFilter,
}

impl Log for KmsgLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // syslog priority: err=3, warning=4, info=6, debug/trace=7
        let priority = match record.level() {
            Level::Error => 3,
            Level::Warn => 4,
            Level::Info => 6,
            Level::Debug | Level::Trace => 7,
        };
        if let std::result::Result::Ok(mut kmsg) = OpenOptions::new().write(true).open("/dev/kmsg") {
            let _ = writeln!(kmsg, "<{priority}>KernelSU: {}", record.args());
        }
    }

    fn flush(&self) {}
}

pub fn init(level: LevelFilter) {
    if log::set_boxed_logger(Box::new(KmsgLogger { level })).is_ok() {
        log::set_max_level(level);
    }
}
