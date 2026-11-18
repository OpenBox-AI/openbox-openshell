//! Both services speak the `OpenShell` contract of one upstream revision. The
//! manifest pins it, and the lockfile must resolve every `OpenShell` crate at
//! that same revision, so a stale lockfile cannot change the contract quietly.
//!
//! The manifest is also the one place that names where `OpenShell` comes from
//! (its git URL) and which release it is (`[package.metadata.openshell]`). The
//! scripts read both from there; `deny.toml` cannot, so it is checked here.
//! Moving to another GitHub organisation is then a change to the manifest, the
//! lockfile and `deny.toml`, and this test fails until all three agree.

/// Any organisation: the URL itself comes from the manifest.
const OPENSHELL_REPO: &str = "/OpenShell.git";

fn read(name: &str) -> String {
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(here.join(name)).unwrap()
}

/// The quoted value after `key = "` on a line.
fn value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split(&format!("{key} = \"")).nth(1)?.split('"').next()
}

fn manifest_deps(manifest: &str) -> Vec<(String, String)> {
    manifest
        .lines()
        .filter(|line| line.contains(OPENSHELL_REPO))
        .filter_map(|line| {
            Some((
                value(line, "git")?.to_owned(),
                value(line, "rev")?.to_owned(),
            ))
        })
        .collect()
}

fn lock_sources(lock: &str) -> Vec<(String, String)> {
    lock.lines()
        .filter(|line| line.starts_with("source = ") && line.contains(OPENSHELL_REPO))
        .filter_map(|line| {
            let source = value(line, "source")?.strip_prefix("git+")?;
            let (url, rest) = source.split_once('?')?;
            Some((url.to_owned(), rest.split_once('#')?.1.to_owned()))
        })
        .collect()
}

#[test]
fn openshell_pin_is_one_revision_and_locked() {
    let pinned = manifest_deps(&read("Cargo.toml"));
    let locked = lock_sources(&read("Cargo.lock"));

    assert!(!pinned.is_empty(), "no OpenShell dependency in Cargo.toml");
    assert!(!locked.is_empty(), "no OpenShell crate in Cargo.lock");
    assert!(
        pinned.iter().chain(&locked).all(|dep| dep == &pinned[0]),
        "Cargo.toml pins {pinned:?}, Cargo.lock resolves {locked:?}"
    );
}

#[test]
fn openshell_source_is_named_in_the_manifest_only() {
    let manifest = read("Cargo.toml");
    let (git, _) = manifest_deps(&manifest)
        .into_iter()
        .next()
        .expect("no OpenShell dependency");

    let release = manifest
        .split("[package.metadata.openshell]")
        .nth(1)
        .and_then(|table| {
            table
                .lines()
                .take_while(|l| !l.starts_with('['))
                .find_map(|l| value(l, "release"))
        })
        .expect("Cargo.toml has no [package.metadata.openshell] release");
    assert!(
        release.starts_with('v'),
        "release {release:?} is not a tag like v0.1.8"
    );

    let allowed: Vec<String> = read("deny.toml")
        .lines()
        .filter(|line| line.starts_with("allow-git"))
        .flat_map(|line| {
            line.split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(
        allowed,
        [git],
        "deny.toml allow-git must be exactly the manifest's OpenShell source"
    );
}
