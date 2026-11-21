//! Platform-independent browser URL observation and host-change tracking.
//! Only normalized hostnames are retained; URL paths, queries and fragments are discarded.

use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BrowserWindowIdentity { pub hwnd: isize, pub process_id: u32, pub process_creation_time_100ns: u64 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserObservation { pub identity: BrowserWindowIdentity, pub browser: String, pub hostname: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserChange {
    pub identity: BrowserWindowIdentity,
    pub browser: String,
    pub previous_hostname: Option<String>,
    pub hostname: String,
}

/// Accept only committed HTTP(S) URLs and return only a normalized hostname.
pub fn normalize_browser_url(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 16_384 || value.chars().any(char::is_control) { return None; }
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() { return None; }
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || (host.parse::<std::net::IpAddr>().is_err() && !valid_dns_name(&host)) { return None; }
    Some(host)
}

fn valid_dns_name(host: &str) -> bool {
    host.split('.').all(|label| !label.is_empty() && label.len() <= 63
        && label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

#[derive(Debug, Default)]
pub struct BrowserTracker { current: Option<BrowserObservation>, baseline_established: bool }

impl BrowserTracker {
    /// First supported-browser observation establishes a baseline. Later active-window or hostname changes are reported.
    pub fn update(&mut self, observation: Option<BrowserObservation>) -> Option<BrowserChange> {
        let observation = observation?;
        let change = if self.baseline_established {
            match self.current.as_ref() {
                Some(previous) if previous.identity == observation.identity && previous.hostname == observation.hostname => None,
                Some(previous) => Some(BrowserChange {
                    identity: observation.identity, browser: observation.browser.clone(),
                    previous_hostname: Some(previous.hostname.clone()), hostname: observation.hostname.clone(),
                }),
                None => Some(BrowserChange {
                    identity: observation.identity, browser: observation.browser.clone(),
                    previous_hostname: None, hostname: observation.hostname.clone(),
                }),
            }
        } else { self.baseline_established = true; None };
        self.current = Some(observation);
        change
    }
    pub fn clear(&mut self) { self.current = None; self.baseline_established = false; }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation(hwnd: isize, host: &str) -> BrowserObservation {
        BrowserObservation { identity: BrowserWindowIdentity { hwnd, process_id: 10, process_creation_time_100ns: 20 }, browser: "chrome.exe".into(), hostname: host.into() }
    }
    #[test] fn url_normalization_keeps_only_http_hostname() {
        assert_eq!(normalize_browser_url("https://Example.COM:443/path?q=secret#fragment").as_deref(), Some("example.com"));
        assert_eq!(normalize_browser_url("http://127.0.0.1:8080/private").as_deref(), Some("127.0.0.1"));
    }
    #[test] fn rejects_non_web_urls_credentials_and_uncommitted_text() {
        for value in ["file:///C:/secret", "about:blank", "javascript:alert(1)", "example.com", "https://user:pass@example.com/", ""] {
            assert!(normalize_browser_url(value).is_none(), "{value}");
        }
    }
    #[test] fn first_observation_is_baseline_and_host_changes_emit() {
        let mut tracker = BrowserTracker::default();
        assert!(tracker.update(Some(observation(1, "example.com"))).is_none());
        assert!(tracker.update(Some(observation(1, "example.com"))).is_none());
        let change = tracker.update(Some(observation(1, "example.org"))).unwrap();
        assert_eq!(change.previous_hostname.as_deref(), Some("example.com"));
        assert_eq!(change.hostname, "example.org");
    }
    #[test] fn switching_browser_window_is_reported() {
        let mut tracker = BrowserTracker::default();
        tracker.update(Some(observation(1, "example.com")));
        assert_eq!(tracker.update(Some(observation(2, "example.com"))).unwrap().identity.hwnd, 2);
    }
    #[test] fn no_browser_observation_does_not_reset_last_seen_state() {
        let mut tracker = BrowserTracker::default();
        tracker.update(Some(observation(1, "example.com")));
        assert!(tracker.update(None).is_none());
        assert!(tracker.update(Some(observation(1, "example.com"))).is_none());
    }
}
