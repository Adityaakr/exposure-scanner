//! The scan's schedule: one task per item on a thread pool, in two lanes.
//!
//! Design report, section 6.2 decision 5: **one task per file, largest files
//! first**. The sizes are very uneven: on the laptop the design was
//! measured on, half of all bytes sat in 12 of 11,789 files. A large file
//! that started last would be read alone, on one thread, after every other
//! thread had run out of work.
//!
//! Every worker takes the next item not yet started from a shared counter,
//! so the second-largest file starts on the second thread to be free.
//! Rayon's splitting, even with one item per task, deals a list out by
//! halves: a thief steals the back half first, and the items just behind
//! the first wait on the first thread's own queue. Replacing it, and
//! nothing else, took a scan of the 14 apps of an Apple M5 from 1.42 s to
//! 1.19 s (the median of five runs of each).
//!
//! # Two lanes
//!
//! A large file costs reading, hashing and searching its bytes, which keeps
//! a core busy. A small file costs system calls: opening, a read or two,
//! closing. Those do not scale with threads on macOS: reading a folder of
//! 102,161 files, all but 80 of them small, on an Apple M5 (4 performance
//! and 6 efficiency cores) took 1.1 s with 3 or 4 threads and 2.2 to 2.5 s
//! with 10, which spent 16 to 18 s in the kernel against 3 to 4.6 s. So the
//! queue has two lanes:
//!
//! * **Large files**, of [`SMALL_BYTES`] or more, largest first, on any
//!   number of threads.
//! * **Small files**, by their place in the list, which keeps the files of
//!   one folder together, on at most [`io_lanes`] threads at a time.
//!
//! Some workers start on the small lane and the others on the large one,
//! and a worker whose lane runs dry moves to the other, so the system calls
//! of the small files overlap the reading of the large ones instead of
//! coming after it.
//!
//! Workers share nothing mutable and results come back in the order of the
//! queue, so which thread ran what, and when, cannot reach the output.
//! Neither can the order of the queue: it decides when a file is read,
//! never what is made of it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};

use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

/// A file smaller than this is read on the small lane: what it costs is
/// system calls, not bytes.
pub const SMALL_BYTES: u64 = 256 << 10;

/// How many workers may be on the small lane at once, or list folders, of
/// a pool of `threads`.
///
/// On macOS, four: past that, reading small files takes longer, not
/// shorter, and several times the system time (see the module
/// documentation). Elsewhere every worker may: no such limit was measured
/// there.
#[must_use]
pub const fn io_lanes(threads: usize) -> usize {
    let limit = if cfg!(target_os = "macos") { 4 } else { usize::MAX };
    if threads < limit { threads } else { limit }
}

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

    /// Applies `task` to every item, started in the order of `items` on at
    /// most [`io_lanes`] workers at once, and returns the results in that
    /// order. For work that is all system calls, such as listing folders.
    pub fn map_io<T, R, F>(&self, items: &[T], task: F) -> Vec<R>
    where
        T: Sync,
        R: Send,
        F: Fn(&T) -> R + Sync,
    {
        let lanes = io_lanes(self.threads()).max(1);
        let next = AtomicUsize::new(0);
        let results = Places::new(items.len());
        self.0.broadcast(|context| {
            if context.index() < lanes {
                while let Some((index, item)) = take(&next, items) {
                    results.put(index, task(item));
                }
            }
        });
        results.into_vec()
    }

    /// Puts `jobs` in the order they are to be started in, then applies
    /// `task` to the work of each, one task per job, and returns the
    /// results in that order.
    ///
    /// The large jobs come first, largest first, and the small ones after
    /// them (see the module documentation). Jobs of one size, and small
    /// jobs, are in the order of their work, so the queue is the same
    /// whatever order the jobs were listed in.
    pub fn largest_first<W, R, F>(&self, jobs: &mut [Job<W>], task: F) -> Vec<R>
    where
        W: Ord + Sync,
        R: Send,
        F: Fn(&W) -> R + Sync,
    {
        let small = |job: &Job<W>| job.size < SMALL_BYTES;
        jobs.sort_unstable_by(|a, b| {
            small(a).cmp(&small(b)).then_with(|| {
                if small(a) { a.work.cmp(&b.work) } else { b.size.cmp(&a.size) }
                    .then_with(|| a.work.cmp(&b.work))
            })
        });
        let split = jobs.partition_point(|job| !small(job));
        let (large, small) = jobs.split_at(split);

        let threads = self.threads();
        let lanes = io_lanes(threads).max(1);
        // Workers that start on the small lane: up to its limit, and never
        // all of them while there are large files to read.
        let small_first = if threads < 2 { 0 } else { lanes.min(threads / 2) };
        let gate = Gate::new(lanes);
        let (next_large, next_small) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let results = Places::new(jobs.len());
        let run_large = || {
            while let Some((index, job)) = take(&next_large, large) {
                results.put(index, task(&job.work));
            }
        };
        let run_small = || {
            while let Some((index, job)) = gate.enter(|| take(&next_small, small)) {
                results.put(split + index, task(&job.work));
                gate.leave();
            }
        };
        self.0.broadcast(|context| {
            if context.index() < small_first {
                run_small();
                run_large();
            } else {
                run_large();
                run_small();
            }
        });
        results.into_vec()
    }
}

/// The next item of `items` that no worker has taken, with its place.
fn take<'a, T>(next: &AtomicUsize, items: &'a [T]) -> Option<(usize, &'a T)> {
    let index = next.fetch_add(1, Ordering::Relaxed);
    items.get(index).map(|item| (index, item))
}

/// The results of a run, each put in its place as soon as it is done, so
/// that no worker keeps a list of its own: one list of results is held,
/// as when Rayon collects them.
struct Places<R>(Mutex<Vec<Option<R>>>);

impl<R> Places<R> {
    fn new(len: usize) -> Self {
        Self(Mutex::new((0..len).map(|_| None).collect()))
    }

    fn put(&self, index: usize, result: R) {
        let mut places = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(place) = places.get_mut(index) {
            *place = Some(result);
        }
    }

    /// The results in their order. Every place below the length was taken
    /// by exactly one worker; the list is turned into the result in place.
    fn into_vec(self) -> Vec<R> {
        let places = self.0.into_inner().unwrap_or_else(PoisonError::into_inner);
        places.into_iter().flatten().collect()
    }
}

/// At most a fixed number of workers between [`enter`](Self::enter) and
/// [`leave`](Self::leave) at once.
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
}

struct GateState {
    /// Places not taken.
    free: usize,
    /// Whether the lane has run dry: then nobody waits for a place.
    dry: bool,
}

impl Gate {
    const fn new(lanes: usize) -> Self {
        Self { state: Mutex::new(GateState { free: lanes, dry: false }), changed: Condvar::new() }
    }

    /// Waits for a place, then takes the next item with `next` and keeps
    /// the place for it. Once `next` has found nothing, every worker that
    /// waits, and every one that comes later, gets nothing at once.
    fn enter<T>(&self, next: impl FnOnce() -> Option<T>) -> Option<T> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while state.free == 0 && !state.dry {
            state = self.changed.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
        if state.dry {
            return None;
        }
        let item = next();
        if item.is_some() {
            state.free -= 1;
        } else {
            state.dry = true;
            drop(state);
            self.changed.notify_all();
        }
        item
    }

    /// Gives a place back.
    fn leave(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.free = state.free.saturating_add(1);
        drop(state);
        self.changed.notify_one();
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
        let doubled: Vec<u32> = items.iter().map(|n| n * 2).collect();
        assert_eq!(pool.map(&items, |n| n * 2), doubled);
        assert_eq!(pool.map_io(&items, |n| n * 2), doubled);
        assert_eq!(pool.map(&[] as &[u32], |n| *n), Vec::<u32>::new());
        assert_eq!(pool.map_io(&[] as &[u32], |n| *n), Vec::<u32>::new());
    }

    #[test]
    fn the_thread_count_is_what_was_asked_for() {
        assert_eq!(Pool::new(1).unwrap().threads(), 1);
        assert_eq!(Pool::new(3).unwrap().threads(), 3);
        assert!(Pool::new(0).unwrap().threads() >= 1);
    }

    #[test]
    fn there_is_always_an_io_lane_and_never_more_than_threads() {
        assert_eq!(io_lanes(1), 1);
        for threads in 1..64 {
            assert!(io_lanes(threads) >= 1 && io_lanes(threads) <= threads);
        }
        if cfg!(target_os = "macos") {
            assert_eq!(io_lanes(10), 4);
        }
    }

    /// The queue is a function of the jobs alone: large jobs largest first,
    /// then small ones, and jobs of one size and small jobs by their work,
    /// whatever order they were listed in.
    #[test]
    fn jobs_are_started_largest_first_whatever_order_they_were_listed_in() {
        let pool = Pool::new(3).unwrap();
        let large = SMALL_BYTES;
        let listed = [
            (large + 5, 'c'),
            (large + 900, 'x'),
            (large + 5, 'a'),
            (0, 'z'),
            (large + 70, 'm'),
            (large + 5, 'b'),
            (large + 900, 'w'),
            (SMALL_BYTES - 1, 'e'),
            (5, 'd'),
        ];
        let queue = |order: &[usize]| {
            let mut jobs: Vec<Job<char>> = order
                .iter()
                .map(|&index| Job { size: listed[index].0, work: listed[index].1 })
                .collect();
            let results = pool.largest_first(&mut jobs, |work| work.to_ascii_uppercase());
            (jobs.iter().map(|job| job.work).collect::<String>(), results)
        };
        let expected =
            (String::from("wxmabcdez"), vec!['W', 'X', 'M', 'A', 'B', 'C', 'D', 'E', 'Z']);
        assert_eq!(queue(&[0, 1, 2, 3, 4, 5, 6, 7, 8]), expected);
        assert_eq!(queue(&[8, 7, 6, 5, 4, 3, 2, 1, 0]), expected);
        assert_eq!(queue(&[3, 0, 6, 2, 8, 5, 1, 7, 4]), expected);
        assert_eq!(pool.largest_first(&mut [] as &mut [Job<char>], |work| *work), Vec::new());
    }

    /// Keeps the thread busy for a while, giving way to others, so that
    /// tasks overlap the way reads of files do.
    fn linger(turns: u64) {
        for _ in 0..turns {
            std::thread::yield_now();
        }
    }

    /// Waits until `count` calls are inside at once, or times out.
    struct Rendezvous {
        inside: Mutex<usize>,
        changed: Condvar,
    }

    impl Rendezvous {
        fn new() -> Self {
            Self { inside: Mutex::new(0), changed: Condvar::new() }
        }

        fn meet(&self, count: usize) -> bool {
            let mut inside = self.inside.lock().unwrap();
            *inside += 1;
            self.changed.notify_all();
            let (inside, timeout) = self
                .changed
                .wait_timeout_while(inside, Duration::from_secs(20), |inside| *inside < count)
                .unwrap();
            drop(inside);
            !timeout.timed_out()
        }
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
        let meeting = Rendezvous::new();
        let overlapped =
            pool.map(&items, |&index| if index >= LARGE { true } else { meeting.meet(LARGE) });
        assert!(
            overlapped.iter().all(|ok| *ok),
            "the largest items did not run concurrently: one task per item is not in effect"
        );

        // The same through the queue, with the largest jobs at its head.
        let meeting = Rendezvous::new();
        let mut jobs: Vec<Job<usize>> = (0..64)
            .map(|index| Job { size: SMALL_BYTES * (100 - index as u64), work: index })
            .collect();
        let overlapped =
            pool.largest_first(&mut jobs, |&index| index >= LARGE || meeting.meet(LARGE));
        assert!(overlapped.iter().all(|ok| *ok), "the largest jobs did not run concurrently");
    }

    /// Small jobs run on at most `io_lanes` threads at once, and they start
    /// while large jobs are still being read.
    #[test]
    fn small_jobs_are_gated_and_overlap_the_large_ones() {
        let pool = Pool::new(8).unwrap();
        let lanes = io_lanes(8);
        let (inside, most) = (Mutex::new(0usize), Mutex::new(0usize));
        let (started, signal) = (Mutex::new(false), Condvar::new());
        let mut jobs: Vec<Job<usize>> = (0..400)
            .map(|index| Job { size: if index < 4 { SMALL_BYTES * 10 } else { 10 }, work: index })
            .collect();
        let large_saw_small = pool.largest_first(&mut jobs, |&index| {
            if index < 4 {
                // A large job: wait for a small one to start.
                let flag = started.lock().unwrap();
                let (flag, _) = signal
                    .wait_timeout_while(flag, Duration::from_secs(20), |flag| !*flag)
                    .unwrap();
                return *flag;
            }
            *started.lock().unwrap() = true;
            signal.notify_all();
            let now = {
                let mut inside = inside.lock().unwrap();
                *inside += 1;
                *inside
            };
            {
                let mut most = most.lock().unwrap();
                *most = (*most).max(now);
            }
            linger(200);
            *inside.lock().unwrap() -= 1;
            true
        });
        assert!(large_saw_small.iter().all(|ok| *ok), "no small job started beside the large");
        let most = *most.lock().unwrap();
        assert!(most >= 1 && most <= lanes, "{most} small jobs at once, limit {lanes}");
    }

    #[test]
    fn listing_runs_on_at_most_the_io_lanes() {
        let pool = Pool::new(8).unwrap();
        let lanes = io_lanes(8);
        let (inside, most) = (Mutex::new(0usize), Mutex::new(0usize));
        let items: Vec<usize> = (0..200).collect();
        let out = pool.map_io(&items, |&item| {
            let now = {
                let mut inside = inside.lock().unwrap();
                *inside += 1;
                *inside
            };
            {
                let mut most = most.lock().unwrap();
                *most = (*most).max(now);
            }
            linger(200);
            *inside.lock().unwrap() -= 1;
            item + 1
        });
        assert_eq!(out, (1..201).collect::<Vec<_>>());
        assert!(*most.lock().unwrap() <= lanes);
    }

    /// More workers than small-lane places, all of them waiting for a place
    /// at the end of the lane: each must find out that it has run dry. A
    /// worker that took the last wake-up and found nothing once left the
    /// others waiting for good.
    #[test]
    fn workers_waiting_for_the_small_lane_all_finish_when_it_runs_dry() {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let pool = Pool::new(12).unwrap();
            for round in 0..50u64 {
                let mut jobs: Vec<Job<u64>> =
                    (0..round + 1).map(|index| Job { size: index % 7, work: index }).collect();
                let done = pool.largest_first(&mut jobs, |&work| {
                    linger(50 * (work % 3));
                    work
                });
                assert_eq!(done.len() as u64, round + 1);
            }
            sender.send(()).unwrap();
        });
        assert!(
            receiver.recv_timeout(Duration::from_secs(60)).is_ok(),
            "a worker never left the small lane"
        );
    }

    #[test]
    fn one_thread_runs_every_job() {
        let pool = Pool::new(1).unwrap();
        let mut jobs: Vec<Job<u64>> =
            (0..50).map(|index| Job { size: index * SMALL_BYTES / 10, work: index }).collect();
        let mut done = pool.largest_first(&mut jobs, |work| *work);
        done.sort_unstable();
        assert_eq!(done, (0..50).collect::<Vec<_>>());
    }
}
