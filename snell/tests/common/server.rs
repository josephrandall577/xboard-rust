//! Starts a snell server for interop tests, in place of the Go suite's Docker
//! launcher:
//!
//! * `SNELL_SERVER_BIN=/path/to/snell-server` runs that binary with
//!   `-c <config> -l error --protocol <v5|v6>` (for example the Go reference
//!   server, or this crate's `snell-server` example);
//! * otherwise, when `docker` is available, the official linux-amd64 binaries
//!   are downloaded, verified and run in a container, like the Go suite;
//! * otherwise the test is skipped.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const BASE_IMAGE: &str = "debian:bookworm-slim";

fn binary_spec(version: &str) -> (&'static str, &'static str) {
    match version {
        "v4" => ("v4.1.1", "8e02974916645aafc0521c49faf0ab9916a0a8a7922ae7261cfd74b96899d25a"),
        "v5" => ("v5.0.1", "5b2e221f2c6e29b1db8e47053e1221be29d5627da807cb932b089f514a3609f0"),
        "v6" => ("v6.0.0rc", "02fa15ac1e18cde6a3e072eeb5d15328c7fd759dbefb1e77e33891a71a1202ae"),
        _ => panic!("unknown snell version: {version}"),
    }
}

pub enum SnellServer {
    Process(Child, tempdir::TempDir),
    Container(String, tempdir::TempDir),
}

impl Drop for SnellServer {
    fn drop(&mut self) {
        match self {
            SnellServer::Process(child, _) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            SnellServer::Container(id, _) => {
                let _ =
                    Command::new("docker").args(["rm", "-f", id]).stdout(Stdio::null()).stderr(Stdio::null()).status();
            }
        }
    }
}

mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new() -> TempDir {
            let path = std::env::temp_dir().join(format!("sing-snell-test-{}", rand::random::<u64>()));
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn docker_available() -> bool {
    Command::new("docker").arg("info").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

fn sha256_file(path: &Path) -> Option<String> {
    let content = std::fs::read(path).ok()?;
    Some(Sha256::digest(&content).iter().map(|b| format!("{b:02x}")).collect())
}

fn cache_dir() -> PathBuf {
    std::env::var_os("SNELL_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("sing-snell-test-bin"))
}

fn official_binary(version: &str) -> PathBuf {
    // Tests run in parallel threads; download each binary once.
    static DOWNLOAD: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = DOWNLOAD.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    let (tag, sha256) = binary_spec(version);
    if let Some(dir) = std::env::var_os("SNELL_BIN_DIR") {
        let dir = PathBuf::from(dir).join(format!("{tag}-linux-amd64"));
        assert_eq!(Some(sha256.to_string()), sha256_file(&dir.join("snell-server")), "binary sha256 mismatch");
        return dir;
    }
    let dir = cache_dir().join(tag);
    let binary = dir.join("snell-server");
    if sha256_file(&binary).as_deref() == Some(sha256) {
        return dir;
    }
    std::fs::create_dir_all(&dir).unwrap();
    // Extract into a private directory and rename the verified binary into place, so that a
    // concurrent test process never sees a partial file.
    let staging = tempdir::TempDir::new();
    let archive = staging.path().join("snell-server.zip");
    let url = format!("https://dl.nssurge.com/snell/snell-server-{tag}-linux-amd64.zip");
    eprintln!("downloading {url}");
    assert!(Command::new("curl").args(["-fsSL", "-o"]).arg(&archive).arg(&url).status().unwrap().success());
    assert!(
        Command::new("unzip")
            .args(["-o", "-j", "-q"])
            .arg(&archive)
            .arg("-d")
            .arg(staging.path())
            .status()
            .unwrap()
            .success()
    );
    let staged = staging.path().join("snell-server");
    assert_eq!(Some(sha256.to_string()), sha256_file(&staged), "binary sha256 mismatch");
    std::fs::rename(&staged, &binary).unwrap();
    dir
}

fn wait_for_listen(port: u16, describe: impl Fn() -> String) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_secs(1))
            .is_ok()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("snell server did not listen on {port}: {}", describe());
}

/// Starts a server for `version` ("v4", "v5" or "v6"), or returns `None` to skip.
pub fn start_snell_server(version: &str, config: &str, port: u16) -> Option<SnellServer> {
    let conf_dir = tempdir::TempDir::new();
    let conf_path = conf_dir.path().join("snell.conf");
    std::fs::write(&conf_path, config).unwrap();
    if let Some(binary) = std::env::var_os("SNELL_SERVER_BIN") {
        let protocol = if version == "v4" { "v5" } else { version };
        let child = Command::new(binary)
            .arg("-c")
            .arg(&conf_path)
            .args(["-l", "error", "--protocol", protocol])
            .stdout(Stdio::null())
            .spawn()
            .expect("start SNELL_SERVER_BIN");
        let server = SnellServer::Process(child, conf_dir);
        wait_for_listen(port, || "process".into());
        return Some(server);
    }
    if !docker_available() {
        eprintln!("skipping: set SNELL_SERVER_BIN or install docker to run official server tests");
        return None;
    }
    let bin_dir = official_binary(version);
    let output = Command::new("docker")
        .args(["run", "-d", "--network", "host", "--platform", "linux/amd64", "--entrypoint", "/snell/snell-server"])
        .arg("-v")
        .arg(format!("{}:/snell:ro", bin_dir.display()))
        .arg("-v")
        .arg(format!("{}:/conf:ro", conf_dir.path().display()))
        .arg(BASE_IMAGE)
        .args(["-l", "error", "-c", "/conf/snell.conf"])
        .output()
        .expect("docker run");
    assert!(output.status.success(), "docker run: {}", String::from_utf8_lossy(&output.stderr));
    let id = String::from_utf8(output.stdout).unwrap().trim().to_string();
    let server = SnellServer::Container(id.clone(), conf_dir);
    wait_for_listen(port, || {
        let logs = Command::new("docker").args(["logs", &id]).output().unwrap();
        String::from_utf8_lossy(&logs.stdout).into_owned() + &String::from_utf8_lossy(&logs.stderr)
    });
    Some(server)
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}
