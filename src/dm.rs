#[cfg(test)]
mod tests {
    use heapless::Vec;

    use crate::Note;

    use super::*;
    const DM_RECV: &str = r#"{"content":"sZhES/uuV1uMmt9neb6OQw6mykdLYerAnTN+LodleSI=?iv=eM0mGFqFhxmmMwE4YPsQMQ==","created_at":1691110186,"id":"517a5f0f29f5037d763bbd5fbe96c9082c1d39eca917aa22b514c5effc36bab9","kind":4,"pubkey":"ed984a5438492bdc75860aad15a59f8e2f858792824d615401fb49d79c2087b0","sig":"3097de7d5070b892b81b245a5b276eccd7cb283a29a934a71af4960188e55e87d639b774cc331eb9f94ea7c46373c52b8ab39bfee75fe4bb11a1dd4c187e1f3e","tags":[["p","098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf"]]}"#;
    const DM_SEND: &str = r#"{"content":"lPQ9iBd6abUrDBJbHWaL3qqhqsuAxK0aU80IgsZ2aqE=?iv=O1zZfD9HPiig1yuZEWX7uQ==","created_at":1691117390,"id":"c0be8c32d95f7599ccfe324711ad50890ee08985710997fcda1a1a3840a23d51","kind":4,"pubkey":"098ef66bce60dd4cf10b4ae5949d1ec6dd777ddeb4bc49b47f97275a127a63cf","sig":"8ee1e83ab037c9e9ff1ac97db88aa045b2f1d9204daa7fee25e5f42274ee8d5f4365b87677c4f27827ca043becc65c1f38f646d05adf3d2c570b66fea57e5918","tags":[["p","ed984a5438492bdc75860aad15a59f8e2f858792824d615401fb49d79c2087b0"]]}"#;
    const FROM_PUBKEY: &str = "ed984a5438492bdc75860aad15a59f8e2f858792824d615401fb49d79c2087b0";
    const EXPCTD_MSG: &str = "hello from the internet";

    #[test]
    fn test_dm() {
        let note: Note = Note::try_from(DM_RECV).unwrap();
    }
}
