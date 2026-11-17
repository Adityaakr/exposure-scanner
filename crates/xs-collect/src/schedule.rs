//! The scan's schedule: one task per item on a thread pool, largest first.
//!
//! Design report, section 6.2 decision 5: **one task per file, largest files
//! first, with `with_max_len(1)`**. Rayon's default splitting hands a whole
//! run of neighbouring items to one thread. On a list sorted by size that
//! run is the head of the list, the handful of files that hold half of all
//! bytes, and the scan ran four times slower in the prototype (12.7 s against
//! 3.5 s). Forcing one item per task lets idle threads steal the big files
//! one at a time.
//!
//! Largest first, because the sizes are very uneven: on the laptop the
//! design was measured on, half of all bytes sat in 12 of 11,789 files. A
//! large file that started last would be read alone, on one thread, after
//! every other thread had run out of work.
//!
//! Workers share nothing mutable and results come back in input order, so
//! which thread ran what, and when, cannot reach the output. Neither can the
//! order of the queue: it decides when a file is read, never what is made of
//! it.

use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

/// A thread pool for one scan.
///
/// The pool is private to the scan rather than Rayon's global one, so the
/// thread count is exactly what was asked for and is not read from the
/// environment.
#[derive(Debug)]
pub struct Pool(rayon::ThreadPool);

impl Pool {
    /// A pool of `threads` workers, or one per available core when `threads`
    /// is zero.
    ///
    /// # Errors
    ///
    /// Fails if the operating system refuses to start the threads.
    pub fn new(threads: usize) -> Result<Self, String> {
        let threads = if threads == 0 {
            std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
        } else {
            threads
        };
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|index| format!("exposure-scan-{index}"))
            .build()
            .map(Self)
            .map_err(|error| error.to_string())
    }

    /// Number of worker threads.
    #[must_use]
    pub fn threads(&self) -> usize {
        self.0.current_num_threads()
    }

    /// Applies `task` to every item, one task per item, and returns the
    /// results in the order of `items`.
    pub fn map<T, R, F>(&self, items: &[T], task: F) -> Vec<R>
    where
        T: Sync,
        R: Send,
        F: Fn(&T) -> R + Sync,
    {
        self.0.install(|| items.par_iter().with_max_len(1).map(&task).collect())
    }

    /// Puts `jobs` in the order they are to be started in, largest first,
    /// then applies `task` to the work of each, one task per job, and
    /// returns the results in that order.
    ///
    /// Jobs of one size are started in the order of their work, so the queue
    /// is the same whatever order the jobs were listed in.
    pub fn largest_first<W, R, F>(&self, jobs: &mut [Job<W>], task: F) -> Vec<R>
    where
        W: Ord + Sync,
        R: Send,
        F: Fn(&W) -> R + Sync,
    {
        jobs.sort_unstable_by(|a, b| b.size.cmp(&a.size).then_with(|| a.work.cmp(&b.work)));
        self.map(jobs, |job| task(&job.work))
    }
}

/// One item of the scan's queue: a piece of work and how large it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Job<W> {
    /// How many bytes the work is expected to read. It only orders the
    /// queue, so a size that is no longer true costs time, not correctness.
    pub size: u64,
    /// What to do.
    pub work: W,
}

#[cfg(test)]
mod tests {
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    use super::*;

    #[test]
    fn results_come_back_in_input_order() {
        let pool = Pool::new(4).unwrap();
        let items: Vec<u32> = (0..1000).collect();
        assert_eq!(pool.map(&items, |n| n * 2), items.iter().map(|n| n * 2).collect::<Vec<_>>());
        assert_eq!(pool.map(&[] as &[u32], |n| *n), Vec::<u32>::new());
    }

    #[test]
    fn the_thread_count_is_what_was_asked_for() {
        assert_eq!(Pool::new(1).unwrap().threads(), 1);
        assert_eq!(Pool::new(3).unwrap().threads(), 3);
        assert!(Pool::new(0).unwrap().threads() >= 1);
    }

    /// The queue is a function of the jobs alone: largest first, and jobs of
    /// one size by their work, whatever order they were listed in.
    #[test]
    fn jobs_are_started_largest_first_whatever_order_they_were_listed_in() {
        let pool = Pool::new(3).unwrap();
        let listed = [(5, 'c'), (900, 'x'), (5, 'a'), (0, 'z'), (70, 'm'), (5, 'b'), (900, 'w')];
        let queue = |order: &[usize]| {
            let mut jobs: Vec<Job<char>> = order
                .iter()
                .map(|&index| Job { size: listed[index].0, work: listed[index].1 })
                .collect();
            let results = pool.largest_first(&mut jobs, |work| work.to_ascii_uppercase());
            (jobs.iter().map(|job| job.work).collect::<String>(), results)
        };
        let expected = (String::from("wxmabcz"), vec!['W', 'X', 'M', 'A', 'B', 'C', 'Z']);
        assert_eq!(queue(&[0, 1, 2, 3, 4, 5, 6]), expected);
        assert_eq!(queue(&[6, 5, 4, 3, 2, 1, 0]), expected);
        assert_eq!(queue(&[3, 0, 6, 2, 5, 1, 4]), expected);
        assert_eq!(pool.largest_first(&mut [] as &mut [Job<char>], |work| *work), Vec::new());
    }

    /// The regression test for the splitting trap.
    ///
    /// The four "large" items at the head of the list each wait until all
    /// four have started. That can only happen if they run on four different
    /// threads at once. With Rayon's default splitting the head of a
    /// 64-item list lands in one task on one thread, the four never overlap,
    /// and the wait times out.
    #[test]
    fn the_head_of_the_list_is_spread_across_threads() {
        const LARGE: usize = 4;
        let pool = Pool::new(LARGE).unwrap();
        let items: Vec<usize> = (0..64).collect();
        let started = Mutex::new(0usize);
        let all_started = Condvar::new();

        let overlapped = pool.map(&items, |&index| {
            if index >= LARGE {
                return true;
            }
            let mut count = started.lock().unwrap();
            *count += 1;
            all_started.notify_all();
            let (count, timeout) = all_started
                .wait_timeout_while(count, Duration::from_secs(20), |count| *count < LARGE)
                .unwrap();
            drop(count);
            !timeout.timed_out()
        });

        assert!(
            overlapped.iter().all(|ok| *ok),
            "the largest items did not run concurrently: one task per item is not in effect"
        );
    }
}
