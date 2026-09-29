//! Runs the collector over a directory of real `OpenShell` OCSF files.
//! Skipped unless `OPENBOX_OCSF_DIR` points at one.

use openbox_verdict_middleware::ocsf_tail::{Checkpoint, Tail};

#[test]
fn collects_a_real_openshell_ocsf_directory() {
    let Some(dir) = std::env::var_os("OPENBOX_OCSF_DIR") else {
        eprintln!("SKIP: OPENBOX_OCSF_DIR not set");
        return;
    };
    let mut tail = Tail::new(&dir);
    let first = tail.poll(&Checkpoint::default()).unwrap();
    eprintln!(
        "records={} gaps={:?} duplicates={} sandboxes={:?}",
        first.records.len(),
        first.gaps,
        first.duplicates,
        first
            .records
            .iter()
            .filter_map(|record| record.sandbox_id.as_deref())
            .collect::<std::collections::BTreeSet<_>>()
    );
    assert!(!first.records.is_empty());
    assert!(first.gaps.is_empty(), "{:?}", first.gaps);
    let again = tail.poll(&first.checkpoint).unwrap();
    assert!(again.records.is_empty() && again.gaps.is_empty());
}
