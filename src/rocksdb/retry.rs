
/// Retry is used because optimistic transactions can fail if other thread change some value.
macro_rules! retry {
    {$($tokens:tt)*} => {
        const NUM_RETRY: usize = 500; // ~10ms-100ms
        #[allow(unused_mut)]
        let mut retry = move || -> Result<_, anyhow::Error> {
            let result = { $($tokens)* };
            Ok(result)
        };
        let mut e = None; //use option because rust think that this variable can be uninit
        for retry_count in 0..NUM_RETRY {
            e = Some(retry().map(|v|(v, retry_count)));
            match e.as_ref().unwrap() {
                Ok(_) => break,
                Err(e) => log::trace!("Error during transaction execution retry_count:{} reason:{}", retry_count + 1,  e)

            }
        }
        let (result, num_retry) = e.unwrap()
        .expect(&format!("Failed to retry operation for {} times", NUM_RETRY));
        if num_retry > 1 && num_retry < NUM_RETRY - 1 { log::warn!("Error transaction execution failed multiple time retry_count:{}", num_retry + 1)}
        result

    };
}
