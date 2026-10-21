//! Format-neutral C ABI. All unsafe code stays in this module.
#[unsafe(no_mangle)]
pub extern "C" fn ffe_abi_version() -> u32 {
    4
}

/// Additive ABI capability: maximum input prefix accepted by ffe_detect.
#[unsafe(no_mangle)]
pub extern "C" fn ffe_probe_limit() -> usize {
    crate::registry::PROBE_LIMIT
}

#[unsafe(no_mangle)]
pub extern "C" fn ffe_format_count() -> usize {
    // Invalid contributor metadata must not unwind across the C boundary.
    std::panic::catch_unwind(|| crate::registry::formats().len()).unwrap_or(0)
}

/// Metadata fields: 0=stable ID, 1=transform name, 2=description. Borrowed
/// immutable UTF-8 bytes live for the loaded library's lifetime.
/// # Safety
/// length points to writable storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffe_format_info(
    index: usize,
    field: u32,
    length: *mut usize,
) -> *const u8 {
    if length.is_null() {
        return std::ptr::null();
    }
    unsafe {
        *length = 0;
    }
    let Ok(Some(format)) = std::panic::catch_unwind(|| crate::registry::formats().get(index))
    else {
        return std::ptr::null();
    };
    let value = match field {
        0 => format.id,
        1 => format.name,
        2 => format.description,
        _ => return std::ptr::null(),
    };
    unsafe {
        *length = value.len();
    }
    value.as_ptr()
}

/// Return inventory index or usize::MAX. Probes receive at most the prefix reported by ffe_probe_limit.
/// # Safety
/// data points to length readable bytes, unchanged during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffe_detect(data: *const u8, length: usize) -> usize {
    if data.is_null() || length > crate::registry::PROBE_LIMIT {
        return usize::MAX;
    }
    std::panic::catch_unwind(|| {
        let input = unsafe { std::slice::from_raw_parts(data, length) };
        crate::registry::detect_index(input).unwrap_or(usize::MAX)
    })
    .unwrap_or(usize::MAX)
}

// Opaque, caller-owned session. The last read buffer remains valid until the
// next read or close. Callers must serialize access to each session.
pub struct NativeArchive {
    archive: crate::archive::Archive,
    last_read: Vec<u8>,
}

unsafe fn report_error(error: &str, buffer: *mut u8, capacity: usize) {
    if !buffer.is_null() && capacity > 0 {
        let length = error.len().min(capacity - 1);
        // SAFETY: caller supplies capacity writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(error.as_ptr(), buffer, length);
            *buffer.add(length) = 0;
        }
    }
}

/// Open a native container. On success the caller must close the returned handle.
///
/// # Safety
/// `data` points to `length` readable bytes; `format` to `format_length` UTF-8
/// bytes (empty selects detection); `output` is writable. A non-null
/// error buffer points to `error_capacity` writable bytes. Buffers do not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffe_archive_open(
    format: *const u8,
    format_length: usize,
    data: *const u8,
    length: usize,
    output: *mut *mut NativeArchive,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if output.is_null()
        || data.is_null()
        || length > crate::archive::MAX_INPUT_SIZE
        || format.is_null()
        || format_length > 256
    {
        unsafe { report_error("invalid archive input", error, error_capacity) };
        return -1;
    }
    unsafe { *output = std::ptr::null_mut() };
    let result = std::panic::catch_unwind(|| {
        // SAFETY: validity and immutability of input is the caller's contract.
        let bytes = unsafe { std::slice::from_raw_parts(data, length) };
        let id = std::str::from_utf8(unsafe { std::slice::from_raw_parts(format, format_length) })
            .map_err(|_| "format ID must be UTF-8".to_string())?;
        if id.is_empty() {
            crate::archive::Archive::open_auto(bytes.to_vec())
        } else {
            crate::archive::Archive::open(id, bytes.to_vec())
        }
    });
    match result {
        Ok(Ok(archive)) => {
            unsafe {
                *output = Box::into_raw(Box::new(NativeArchive {
                    archive,
                    last_read: Vec::new(),
                }))
            };
            0
        }
        other => {
            let message = match other {
                Ok(Err(message)) => message,
                _ => "native parser panicked".into(),
            };
            unsafe { report_error(&message, error, error_capacity) };
            -1
        }
    }
}

/// # Safety
/// Handle is null or a live handle returned by ffe_archive_open.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffe_archive_count(handle: *const NativeArchive) -> usize {
    unsafe { handle.as_ref() }.map_or(0, |archive| archive.archive.names().len())
}

/// Additive ABI capability: borrowed UTF-8 analysis text, valid until close.
/// # Safety
/// Handle is null or live; length is writable; handle access is serialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffe_archive_diagnostics(
    handle: *const NativeArchive,
    length: *mut usize,
) -> *const u8 {
    if length.is_null() {
        return std::ptr::null();
    }
    unsafe {
        *length = 0;
    }
    let Some(archive) = (unsafe { handle.as_ref() }) else {
        return std::ptr::null();
    };
    let Ok(message) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        archive.archive.diagnostics()
    })) else {
        return std::ptr::null();
    };
    unsafe {
        *length = message.len();
    }
    message.as_ptr()
}

/// Generic reader flags: bit 0 means a single automatic decoded stream.
/// # Safety
/// Handle is null or a live handle returned by ffe_archive_open.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffe_archive_flags(handle: *const NativeArchive) -> u32 {
    unsafe { handle.as_ref() }.map_or(0, |archive| u32::from(archive.archive.is_decoded_stream()))
}

/// Additive ABI capability: exact standalone archive extent in a host image.
/// Returns 1 when embedded, 0 when not embedded (including a null handle), or
/// -1 for invalid output pointers or a reader panic. Outputs are zeroed first.
/// # Safety
/// Handle is null or live; offset and length point to distinct writable usize
/// values; handle access is serialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffe_archive_embedded_range(
    handle: *const NativeArchive,
    offset: *mut usize,
    length: *mut usize,
) -> i32 {
    if offset.is_null() || length.is_null() {
        return -1;
    }
    unsafe {
        *offset = 0;
        *length = 0;
    }
    let Some(archive) = (unsafe { handle.as_ref() }) else {
        return 0;
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        archive.archive.embedded_range()
    })) {
        Ok(Some(range)) => {
            unsafe {
                *offset = range.start;
                *length = range.end - range.start;
            }
            1
        }
        Ok(None) => 0,
        Err(_) => -1,
    }
}

/// Return borrowed UTF-8 name bytes, valid until close. Null on invalid index.
///
/// # Safety
/// Handle is null or live; length is writable; access is serialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffe_archive_name(
    handle: *const NativeArchive,
    index: usize,
    length: *mut usize,
) -> *const u8 {
    if length.is_null() {
        return std::ptr::null();
    }
    unsafe { *length = 0 };
    let Some(archive) = (unsafe { handle.as_ref() }) else {
        return std::ptr::null();
    };
    let Some(name) = archive.archive.names().get(index) else {
        return std::ptr::null();
    };
    unsafe { *length = name.len() };
    name.as_ptr()
}

/// Extract one member into a borrowed session buffer. No file is written.
///
/// # Safety
/// Handle is live and exclusively accessed. Output and length are writable.
/// Error buffer, if non-null, has error_capacity writable bytes. Returned data
/// remains readable until the next read or close on this handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffe_archive_read(
    handle: *mut NativeArchive,
    index: usize,
    output: *mut *const u8,
    length: *mut usize,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if handle.is_null() || output.is_null() || length.is_null() {
        return -1;
    }
    unsafe {
        *output = std::ptr::null();
        *length = 0
    };
    let archive = unsafe { &mut *handle };
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| archive.archive.read(index)));
    match result {
        Ok(Ok(content)) => {
            archive.last_read = content;
            unsafe {
                *output = archive.last_read.as_ptr();
                *length = archive.last_read.len()
            };
            0
        }
        other => {
            let message = match other {
                Ok(Err(message)) => message,
                _ => "native extraction panicked".into(),
            };
            unsafe { report_error(&message, error, error_capacity) };
            -1
        }
    }
}

/// # Safety
/// Handle is null or an unclosed handle from ffe_archive_open. No concurrent users.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffe_archive_close(handle: *mut NativeArchive) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)) }
    }
}
