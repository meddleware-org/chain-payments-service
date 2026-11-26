//! Database connection settings: `DATABASE_URL` with `sslmode=verify-full` and `sslrootcert` (the tier's
//! CA), or plaintext only behind `ALLOW_INSECURE_DATABASE=1` (local tests). The URL and password are never
//! printed: `Debug` and every error redact them.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgSslMode};
use sqlx::{ConnectOptions, Executor};
use url::Url;

/// Why the database settings were refused. No message repeats the URL or the password.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A required variable is not set.
    #[error("{0} is not set")]
    Missing(&'static str),
    /// `DATABASE_URL` is not a `postgres://` URL.
    #[error("DATABASE_URL is not a valid postgres:// URL")]
    NotAUrl,
    /// The URL lacks a part it needs (user, password, host or database).
    #[error("DATABASE_URL has no {0}")]
    Incomplete(&'static str),
    #[error(
        "DATABASE_URL must use sslmode=verify-full with sslrootcert=<the tier's CA> (set ALLOW_INSECURE_DATABASE=1 \
         only for a local test server)"
    )]
    /// The URL does not use `sslmode=verify-full` with a CA file.
    NotVerifyFull,
    /// The URL carries a parameter that is not allowed.
    #[error("DATABASE_URL parameter {0} is not allowed (only sslmode, sslrootcert and application_name)")]
    UnknownParameter(String),
}

/// Name a configured URL in a message without repeating anything that can carry a credential: only an `http` or `https`
/// scheme, the host and the port are returned. A URL can hold a user name, a password, a token in its path or a key in its
/// query, and a message reaches a log or a terminal (CONF lens), so a value that is not a URL, has no host or has another
/// scheme is described by a fixed phrase instead of being echoed.
pub fn describe_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else { return "(not a valid URL)".into() };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return "(an address that is not http or https)".into();
    }
    // The authority ends at the first `/`, `?` or `#`; anything before an `@` is a user name and password.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host_port.is_empty() {
        return "(an address with no host)".into();
    }
    format!("{}://{host_port}", scheme.to_ascii_lowercase())
}

/// How a pool's connections behave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read and write (the api and worker processes, as the writer role).
    // Used by every process except a reporting one.
    ReadWrite,
    /// Every connection also sets `default_transaction_read_only` (a read-only reporting process;
    /// the role carries the same default, this makes it independent of the role's configuration).
    ReadOnly,
}

/// Parsed connection settings for one role.
#[derive(Clone)]
pub struct DatabaseSettings {
    /// The parsed URL (it holds the password, so it is never printed).
    url: Url,
    /// Whether TLS with verification is on.
    tls: bool,
}

impl fmt::Debug for DatabaseSettings {
    /// Show host, port, user, database and TLS only; the password is shown as redacted and the URL never.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseSettings")
            .field("host", &self.url.host_str().unwrap_or_default())
            .field("port", &self.url.port_or_known_default())
            .field("user", &self.url.username())
            .field("database", &self.database())
            .field("password", &"<redacted>")
            .field("tls", &self.tls)
            .finish()
    }
}

impl DatabaseSettings {
    /// Parse a URL. Without `allow_insecure` only `sslmode=verify-full` with `sslrootcert` is accepted.
    pub fn parse(raw: &str, allow_insecure: bool) -> Result<Self, ConfigError> {
        // A parse failure says "not a URL", never why or where: the text holds the password.
        let url = Url::parse(raw).map_err(|_| ConfigError::NotAUrl)?;
        // Only the two PostgreSQL schemes.
        if !matches!(url.scheme(), "postgres" | "postgresql") {
            return Err(ConfigError::NotAUrl);
        }
        // Every part the connection needs must be present; the error names the part.
        if url.host_str().is_none_or(str::is_empty) {
            return Err(ConfigError::Incomplete("host"));
        }
        if url.username().is_empty() {
            return Err(ConfigError::Incomplete("user"));
        }
        // A URL without a password is refused.
        if url.password().is_none_or(str::is_empty) {
            return Err(ConfigError::Incomplete("password"));
        }
        if url.path().trim_start_matches('/').is_empty() {
            return Err(ConfigError::Incomplete("database name"));
        }
        // TLS settings are read from the query string.
        let mut sslmode = None;
        let mut root = None;
        // Only three parameters are understood; anything else is refused so a parameter cannot weaken the connection.
        for (k, v) in url.query_pairs() {
            match &*k {
                "sslmode" => sslmode = Some(v.into_owned()),
                "sslrootcert" => root = Some(v.into_owned()),
                "application_name" => {}
                other => return Err(ConfigError::UnknownParameter(other.to_owned())),
            }
        }
        // `verify-full` with a CA file is the only accepted TLS mode.
        let verify_full = sslmode.as_deref() == Some("verify-full") && root.as_deref().is_some_and(|r| !r.is_empty());
        // Plain text needs the explicit local-test switch.
        if !verify_full && !allow_insecure {
            return Err(ConfigError::NotVerifyFull);
        }
        // The URL is kept (it holds the password) for building the connection options.
        Ok(DatabaseSettings { url, tls: verify_full })
    }

    /// From the process environment (`get` is `std::env::var(..).ok()` in production, a map in tests).
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let url = get("DATABASE_URL").filter(|v| !v.is_empty()).ok_or(ConfigError::Missing("DATABASE_URL"))?;
        // Exactly `1` turns the local-test switch on; any other value leaves it off.
        let insecure = get("ALLOW_INSECURE_DATABASE").is_some_and(|v| v == "1");
        Self::parse(&url, insecure)
    }

    /// The user name.
    pub fn user(&self) -> &str {
        self.url.username()
    }

    /// The database name.
    pub fn database(&self) -> &str {
        self.url.path().trim_start_matches('/')
    }

    /// Whether the connection is encrypted and the server verified.
    pub fn tls_enabled(&self) -> bool {
        self.tls
    }

    /// The URL with its password. Only for handing to a child process's environment in tests.
    pub fn url_unredacted(&self) -> &str {
        self.url.as_str()
    }

    /// The same server and TLS settings with other credentials and another database.
    pub fn with_credentials(&self, user: &str, password: &str, database: &str) -> DatabaseSettings {
        // Start from the same URL so the host, port, CA and TLS mode are kept.
        let mut url = self.url.clone();
        // Setting these on a URL that already has a host cannot fail.
        let _ = url.set_username(user);
        // The password is set on the URL, never formatted into a message.
        let _ = url.set_password(Some(password));
        // The database is the URL path.
        url.set_path(&format!("/{database}"));
        // The derived settings keep the TLS mode of the original.
        DatabaseSettings { url, tls: self.tls }
    }

    /// SQLx connection options (statement logging off: queries can carry post text).
    pub fn connect_options(&self) -> Result<PgConnectOptions, ConfigError> {
        let mut o = PgConnectOptions::from_str(self.url.as_str()).map_err(|_| ConfigError::NotAUrl)?;
        if self.tls {
            o = o.ssl_mode(PgSslMode::VerifyFull);
        }
        Ok(o.application_name("chain-payments").disable_statement_logging())
    }

    /// A pool of at most `size` connections; nothing connects until the first use, so a process starts (and
    /// answers its health check) while the database is unreachable.
    pub fn lazy_pool(&self, size: u32, access: Access) -> Result<PgPool, ConfigError> {
        let options = PgPoolOptions::new()
            .max_connections(size.max(1))
            .acquire_timeout(Duration::from_secs(5))
            .idle_timeout(Duration::from_secs(300));
        let options = match access {
            Access::ReadWrite => options,
            Access::ReadOnly => options.after_connect(|conn, _meta| {
                Box::pin(async move {
                    conn.execute("SET default_transaction_read_only = on").await?;
                    Ok(())
                })
            }),
        };
        Ok(options.connect_lazy_with(self.connect_options()?))
    }
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    /// A URL is named by its scheme, host and port only, never its credentials, path or query.
    #[test]
    fn a_url_is_named_by_its_origin_only() {
        let secret = "https://user:s3cret@hooks.example:443/tok3n/path?key=k3y#frag";
        assert_eq!(describe_url(secret), "https://hooks.example:443");
        for part in ["user", "s3cret", "tok3n", "k3y", "frag"] {
            assert!(!describe_url(secret).contains(part), "{part}");
        }
        assert_eq!(describe_url("s3cret://host.example"), "(an address that is not http or https)");
        assert_eq!(describe_url("user:s3cret@host.example"), "(not a valid URL)");
        assert_eq!(describe_url("https://user:s3cret@"), "(an address with no host)");
    }

    use super::*;

    /// A well-formed (throwaway) URL for the tests.
    const GOOD: &str =
        "postgres://cp_app:s3cret@db.example:5432/chain_payments?sslmode=verify-full&sslrootcert=/etc/ca.crt";

    /// Verify full with a root is accepted.
    #[test]
    fn verify_full_with_a_root_is_accepted() {
        let s = DatabaseSettings::parse(GOOD, false).expect("valid");
        assert!(s.tls_enabled());
        assert_eq!((s.user(), s.database()), ("cp_app", "chain_payments"));
    }

    /// Every weaker tls setting is refused.
    #[test]
    fn every_weaker_tls_setting_is_refused() {
        for url in [
            "postgres://u:p@h/db",
            "postgres://u:p@h/db?sslmode=require&sslrootcert=/ca",
            "postgres://u:p@h/db?sslmode=verify-ca&sslrootcert=/ca",
            "postgres://u:p@h/db?sslmode=verify-full",
            "postgres://u:p@h/db?sslmode=verify-full&sslrootcert=",
            "postgres://u:p@h/db?sslmode=disable",
        ] {
            assert_eq!(DatabaseSettings::parse(url, false).unwrap_err(), ConfigError::NotVerifyFull, "{url}");
        }
        // Behind the explicit local-test switch a plaintext server is accepted (and reported as such).
        let s = DatabaseSettings::parse("postgres://u:p@localhost/db", true).expect("insecure allowed");
        assert!(!s.tls_enabled());
    }

    /// Incomplete or foreign urls are refused.
    #[test]
    fn incomplete_or_foreign_urls_are_refused() {
        let cases = [
            ("mysql://u:p@h/db", ConfigError::NotAUrl),
            ("not a url", ConfigError::NotAUrl),
            ("postgres://u@h/db?sslmode=verify-full&sslrootcert=/ca", ConfigError::Incomplete("password")),
            ("postgres://:p@h/db?sslmode=verify-full&sslrootcert=/ca", ConfigError::Incomplete("user")),
            ("postgres://u:p@h/?sslmode=verify-full&sslrootcert=/ca", ConfigError::Incomplete("database name")),
            (
                "postgres://u:p@h/db?sslmode=verify-full&sslrootcert=/ca&options=-c%20x",
                ConfigError::UnknownParameter("options".into()),
            ),
        ];
        for (url, want) in cases {
            assert_eq!(DatabaseSettings::parse(url, false).unwrap_err(), want, "{url}");
        }
    }

    /// The password never appears in debug or errors.
    #[test]
    fn the_password_never_appears_in_debug_or_errors() {
        let s = DatabaseSettings::parse(GOOD, false).expect("valid");
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("s3cret") && dbg.contains("<redacted>"), "{dbg}");
        let e = DatabaseSettings::parse("postgres://u:s3cret@h/db", false).unwrap_err();
        assert!(!e.to_string().contains("s3cret"));
    }

    /// From env needs the url and reads the insecure switch.
    #[test]
    fn from_env_needs_the_url_and_reads_the_insecure_switch() {
        let none = |_: &str| None;
        assert_eq!(DatabaseSettings::from_env(none).unwrap_err(), ConfigError::Missing("DATABASE_URL"));
        let local = |k: &str| match k {
            "DATABASE_URL" => Some("postgres://u:p@localhost/db".to_owned()),
            "ALLOW_INSECURE_DATABASE" => Some("1".to_owned()),
            _ => None,
        };
        assert!(DatabaseSettings::from_env(local).is_ok());
        let not_one = |k: &str| match k {
            "DATABASE_URL" => Some("postgres://u:p@localhost/db".to_owned()),
            "ALLOW_INSECURE_DATABASE" => Some("true".to_owned()),
            _ => None,
        };
        assert_eq!(DatabaseSettings::from_env(not_one).unwrap_err(), ConfigError::NotVerifyFull);
    }

    /// Credentials can be swapped keeping tls.
    #[test]
    fn credentials_can_be_swapped_keeping_tls() {
        let s = DatabaseSettings::parse(GOOD, false).expect("valid");
        let t = s.with_credentials("other", "pw2", "other_db");
        assert_eq!((t.user(), t.database(), t.tls_enabled()), ("other", "other_db", true));
        assert!(t.url_unredacted().contains("sslrootcert"));
    }
}
