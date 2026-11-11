//! Both services speak the `OpenShell` contract of one upstream revision. The
//! manifest pins it, and the lockfile must resolve every `OpenShell` crate at
//! that same revision, so a stale lockfile cannot change the contract quietly.

const OPENSHELL_GIT: &str = "github.com/NVIDIA/OpenShell.git";

fn manifest_revs(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .filter(|line| line.contains(OPENSHELL_GIT))
        .filter_map(|line| line.split("rev = \"").nth(1))
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect()
}

fn lock_revs(lock: &str) -> Vec<String> {
    lock.lines()
        .filter(|line| line.starts_with("source = ") && line.contains(OPENSHELL_GIT))
        .filter_map(|line| line.split('#').nth(1))
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn openshell_pin_is_one_revision_and_locked() {
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |name: &str| std::fs::read_to_string(here.join(name)).unwrap();
    let pinned = manifest_revs(&read("Cargo.toml"));
    let locked = lock_revs(&read("Cargo.lock"));

    assert!(!pinned.is_empty(), "no OpenShell dependency in Cargo.toml");
    assert!(!locked.is_empty(), "no OpenShell crate in Cargo.lock");
    assert!(
        pinned.iter().chain(&locked).all(|rev| rev == &pinned[0]),
        "Cargo.toml pins {pinned:?}, Cargo.lock resolves {locked:?}"
    );
}
