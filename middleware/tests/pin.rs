//! The middleware and the sandbox service must speak the same `OpenShell`
//! contract, so both crates pin the same upstream revision.

fn openshell_revs(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .filter(|line| line.contains("github.com/NVIDIA/OpenShell.git"))
        .filter_map(|line| line.split("rev = \"").nth(1))
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn openshell_pin_matches_the_sandbox_service() {
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ours = openshell_revs(&std::fs::read_to_string(here.join("Cargo.toml")).unwrap());
    let root = openshell_revs(&std::fs::read_to_string(here.join("../Cargo.toml")).unwrap());
    assert!(!ours.is_empty() && !root.is_empty());
    assert!(
        ours.iter().chain(&root).all(|rev| rev == &root[0]),
        "{ours:?} vs {root:?}"
    );
}
