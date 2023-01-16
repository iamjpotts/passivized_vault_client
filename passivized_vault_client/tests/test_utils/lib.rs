use std::future::Future;

pub fn run_async<F: Future<Output = ()>>(run_test: F) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(run_test)
}