use fictor::store::{Store, StoreError, blobs::BlobError};
use std::{fs, path::Path};

fn replace_home(home: &Path, original: &Path) {
    fs::rename(home, original).unwrap();
    fictor::home::prepare(home).unwrap();
}

#[tokio::test]
async fn replaced_home_refuses_blob_publication_and_new_captures() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let original = root.path().join("original");
    fictor::home::prepare(&home).unwrap();
    let store = Store::open(&home).await.unwrap();
    replace_home(&home, &original);
    let publication = store.put_blob(b"fake-new-blob".to_vec()).await;
    let capture = store.begin_capture();
    assert!(matches!(
        publication,
        Err(StoreError::Blob(BlobError::Ownership))
    ));
    assert!(matches!(
        capture,
        Err(StoreError::Blob(BlobError::Ownership))
    ));
    assert_eq!(fs::read_dir(home.join("blobs")).unwrap().count(), 0);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn replaced_home_refuses_capture_mutations_and_drop_never_unlinks_foreign_names() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let original = root.path().join("original");
    fictor::home::prepare(&home).unwrap();
    let store = Store::open(&home).await.unwrap();
    let dropped = store.begin_capture().unwrap();
    let mut finalized = store.begin_capture().unwrap();
    finalized.append(b"fake-original-capture").unwrap();
    let previous_length = finalized.len();
    let names = fs::read_dir(home.join("blobs"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_str().unwrap().starts_with(".model-capture-"))
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 2);
    replace_home(&home, &original);
    for name in &names {
        fs::write(home.join("blobs").join(name), b"foreign-name-canary").unwrap();
    }
    let appended = finalized.append(b"not-admitted");
    let current_length = finalized.len();
    drop(dropped);
    let published = store.finish_capture(finalized).await;
    assert!(matches!(appended, Err(BlobError::Ownership)));
    assert_eq!(current_length, previous_length);
    assert!(matches!(
        published,
        Err(StoreError::Blob(BlobError::Ownership))
    ));
    for name in &names {
        assert_eq!(
            fs::read(home.join("blobs").join(name)).unwrap(),
            b"foreign-name-canary"
        );
        assert!(
            !original.join("blobs").join(name).exists(),
            "owned temporary must still be removed through its pinned home"
        );
    }
    assert_eq!(fs::read_dir(home.join("blobs")).unwrap().count(), 2);
    store.shutdown().await.unwrap();
}
