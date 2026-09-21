pub fn attach_is_not_allowed(err: &stackpulse::Error) -> bool {
    if matches!(
        err.kind(),
        stackpulse::ErrorKind::Permission | stackpulse::ErrorKind::Unsupported
    ) {
        return true;
    }
    matches!(err.raw_os_error(), Some(libc::EPERM | libc::EACCES))
        || err.to_string().to_ascii_lowercase().contains("permission")
}

pub fn environment_skips_allowed() -> bool {
    std::env::var_os("CI").is_none() || std::env::var_os("STACKPULSE_ALLOW_PERF_SKIP").is_some()
}
