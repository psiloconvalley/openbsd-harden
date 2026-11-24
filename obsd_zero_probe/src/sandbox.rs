use std::process;

extern "C" {
    fn pledge(promises: *const libc::c_char, execpromises: *const libc::c_char) -> libc::c_int;
    fn unveil(path: *const libc::c_char, flags: *const libc::c_char) -> libc::c_int;
}

pub fn apply_sandboxing(report_dir: &str) {
    unsafe {
        let ssl_path = std::ffi::CString::new("/etc/ssl").unwrap();
        let read_mode = std::ffi::CString::new("r").unwrap();
        if unveil(ssl_path.as_ptr(), read_mode.as_ptr()) != 0 {
            eprintln!("Error: unveil /etc/ssl failed");
            process::exit(1);
        }

        let report_path = std::ffi::CString::new(report_dir).unwrap();
        let rwc_mode = std::ffi::CString::new("rwc").unwrap();
        if unveil(report_path.as_ptr(), rwc_mode.as_ptr()) != 0 {
            eprintln!("Error: unveil report directory failed");
            process::exit(1);
        }

        if unveil(std::ptr::null(), std::ptr::null()) != 0 {
            eprintln!("Error: unveil lock failed");
            process::exit(1);
        }

        let promises = std::ffi::CString::new("stdio inet dns rpath wpath cpath").unwrap();
        if pledge(promises.as_ptr(), std::ptr::null()) != 0 {
            eprintln!("Error: pledge failed");
            process::exit(1);
        }
    }
}
