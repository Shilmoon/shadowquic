//! jemalloc runs with the settings built into the binary: few arenas, and
//! freed pages returned to the system soon after they are freed.
use std::ffi::{CStr, c_void};

fn option<T: Default>(name: &CStr) -> T {
    let mut value = T::default();
    let mut len = size_of::<T>();
    // SAFETY: `value` is a valid, writable `T` and `len` is its size.
    let status = unsafe {
        tikv_jemalloc_sys::mallctl(
            name.as_ptr(),
            &mut value as *mut T as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(status, 0, "reading {name:?}");
    assert_eq!(len, size_of::<T>(), "size of {name:?}");
    value
}

#[test]
fn built_in_allocator_settings_are_in_effect() {
    if std::env::var_os("_RJEM_MALLOC_CONF").is_some() {
        eprintln!("_RJEM_MALLOC_CONF is set and replaces the built-in settings: test not run");
        return;
    }
    assert_eq!(option::<u32>(c"opt.narenas"), 1);
    assert_eq!(option::<isize>(c"opt.dirty_decay_ms"), 1000);
    assert_eq!(option::<isize>(c"opt.muzzy_decay_ms"), 0);
}
