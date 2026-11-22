//! The memory the entries of packages are read into, bounded by the scan's
//! threads and not by how many packages it reads.
//!
//! Each entry the collector reads is copied out of the archive as stored,
//! and a deflated one is then inflated. A fresh allocation for each of the
//! two would be freed as soon as the entry is parsed, but freeing is not
//! giving back: the allocator of macOS keeps large freed blocks for the
//! process, and blocks of ever-different sizes are rarely used again. A
//! folder of crafted packages, each a few hundred kilobytes that inflate to
//! hundreds of megabytes, then drives one scan into many gigabytes.
//!
//! So nothing large is allocated per entry:
//!
//! - **Kept buffers.** Each worker thread keeps one buffer for stored bytes,
//!   one for inflated bytes and one for a resource table, and uses them for
//!   every entry it reads. Each grows to what its largest entry needed, at
//!   most [`KEPT_BYTES`] (the table to its own reader's budget), and is
//!   never shrunk, so no large block is ever freed.
//! - **Shared buffers.** An entry larger than that (a DEX file can declare
//!   up to [`MAX_ENTRY_BYTES`]) takes a buffer from a pool that every thread
//!   shares. All of them have the same capacity, enough for any entry, so a
//!   buffer given back is a buffer the next entry can use. There are at
//!   most [`SHARED_BUFFERS`] of them: a thread that finds none free waits
//!   until another thread gives one back. That bounds the scan's large
//!   memory at `SHARED_BUFFERS × SHARED_BYTES` whatever the thread count.
//!
//! What a scan finds does not depend on any of this: a thread that waits
//! reads the same bytes later. A thread that already holds a shared buffer
//! never waits for another one, so two threads cannot wait on each other;
//! should it need one more (only a manifest or resource table that the
//! resource loader reads past its span, into the next entry, gets there),
//! it makes one for the time it holds it.

use std::cell::{Cell, RefCell};
use std::ops::{Deref, DerefMut};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

use xs_formats::zip;

use super::MAX_ENTRY_BYTES;

/// The most bytes a kept buffer for stored or inflated bytes grows to. Real
/// DEX files are rarely over 16 MiB, so they never need a shared buffer.
pub(super) const KEPT_BYTES: usize = 32 << 20;
/// The most bytes the kept buffer for a resource table grows to: the most
/// either table reader accepts.
const KEPT_TABLE_BYTES: usize = xs_formats::android_resources::MAX_BYTES;
/// Capacity of every shared buffer: the largest entry and the longest local
/// header it can have.
pub(super) const SHARED_BYTES: usize =
    MAX_ENTRY_BYTES as usize + zip::LOCAL_HEADER_BYTES + 2 * u16::MAX as usize;
/// The most shared buffers there are at once, over all threads, but for the
/// rare one a thread makes while it holds another: 1 GiB.
pub(super) const SHARED_BUFFERS: usize = 4;

/// Which kept buffer of its thread a buffer is.
#[derive(Debug, Clone, Copy)]
enum Slot {
    Stored = 0,
    Inflated = 1,
    Table = 2,
}

impl Slot {
    const fn limit(self) -> usize {
        match self {
            Self::Stored | Self::Inflated => KEPT_BYTES,
            Self::Table => KEPT_TABLE_BYTES,
        }
    }
}

thread_local! {
    /// The kept buffers of this thread, while no entry is using them.
    static KEPT: RefCell<[Vec<u8>; 3]> = const { RefCell::new([Vec::new(), Vec::new(), Vec::new()]) };
    /// How many shared buffers this thread holds.
    static HELD: Cell<usize> = const { Cell::new(0) };
}

/// The shared buffers no thread is using, and how many there are in all.
struct Pool {
    state: Mutex<PoolState>,
    returned: Condvar,
}

struct PoolState {
    idle: Vec<Vec<u8>>,
    made: usize,
}

static POOL: Pool =
    Pool { state: Mutex::new(PoolState { idle: Vec::new(), made: 0 }), returned: Condvar::new() };

impl Pool {
    /// The state, also after a thread panicked while holding it: the state
    /// is two counts and a list, and stays consistent.
    fn lock(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `count` shared buffers, all at once, so a thread never holds some of
    /// what it needs while it waits for the rest.
    fn take(&self, count: usize) -> Vec<Vec<u8>> {
        if count == 0 {
            return Vec::new();
        }
        let holds = HELD.with(Cell::get) > 0;
        let mut state = self.lock();
        while !holds
            && state.idle.len().saturating_add(SHARED_BUFFERS.saturating_sub(state.made)) < count
        {
            state = self.returned.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
        let mut taken = Vec::with_capacity(count);
        for _ in 0..count {
            let buffer = state.idle.pop().unwrap_or_else(|| {
                state.made = state.made.saturating_add(1);
                Vec::with_capacity(SHARED_BYTES)
            });
            taken.push(buffer);
        }
        drop(state);
        HELD.with(|held| held.set(held.get().saturating_add(count)));
        taken
    }

    /// Gives a shared buffer back. One made beyond the limit is let go.
    fn give(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        let mut state = self.lock();
        if state.made > SHARED_BUFFERS {
            state.made = state.made.saturating_sub(1);
        } else {
            state.idle.push(buffer);
        }
        drop(state);
        self.returned.notify_all();
        HELD.with(|held| held.set(held.get().saturating_sub(1)));
    }
}

/// Where a buffer goes back to when it is dropped.
#[derive(Debug, Clone, Copy)]
enum Home {
    Kept(Slot),
    Shared,
}

/// A buffer for one entry, which goes back where it came from when it is
/// dropped. It is a `Vec<u8>` with room for at least what it was asked
/// for; filling it to that never reallocates.
#[derive(Debug)]
pub(super) struct Buffer {
    bytes: Vec<u8>,
    home: Home,
}

impl Deref for Buffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.bytes
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.bytes);
        match self.home {
            Home::Shared => POOL.give(bytes),
            Home::Kept(slot) => {
                bytes.clear();
                // While the thread ends, its buffers are gone already and
                // this one is let go with them.
                let _ = KEPT.try_with(|kept| {
                    if let Ok(mut kept) = kept.try_borrow_mut()
                        && let Some(place) = kept.get_mut(slot as usize)
                        && place.capacity() < bytes.capacity()
                    {
                        *place = bytes;
                    }
                });
            }
        }
    }
}

/// The kept buffer `slot` of this thread, empty, with room for `need`
/// bytes. It grows by doubling, up to its limit, so a thread whose entries
/// grow a little at a time does not leave a trail of freed blocks.
fn kept(slot: Slot, need: usize) -> Buffer {
    let mut bytes = KEPT
        .try_with(|kept| {
            kept.try_borrow_mut()
                .ok()
                .and_then(|mut kept| kept.get_mut(slot as usize).map(std::mem::take))
        })
        .ok()
        .flatten()
        .unwrap_or_default();
    bytes.clear();
    if bytes.capacity() < need {
        let room = need.max(bytes.capacity().saturating_mul(2).min(slot.limit()));
        bytes.reserve_exact(room);
    }
    Buffer { bytes, home: Home::Kept(slot) }
}

/// The buffers one entry is read into: its bytes as stored, and its bytes
/// inflated.
#[derive(Debug)]
pub(super) struct EntryBuffers {
    pub(super) stored: Buffer,
    pub(super) inflated: Buffer,
}

/// Buffers for an entry of `stored` bytes as stored, local header included,
/// that inflates to `inflated` bytes (0 if it is not inflated). Waits while
/// every shared buffer is in use and the entry needs one.
pub(super) fn for_entry(stored: usize, inflated: usize) -> EntryBuffers {
    let large = |need: usize| need > KEPT_BYTES;
    let mut shared =
        POOL.take(usize::from(large(stored)) + usize::from(large(inflated))).into_iter();
    let mut buffer = |slot: Slot, need: usize| match large(need).then(|| shared.next()).flatten() {
        Some(bytes) => Buffer { bytes, home: Home::Shared },
        None => kept(slot, need),
    };
    EntryBuffers {
        stored: buffer(Slot::Stored, stored),
        inflated: buffer(Slot::Inflated, inflated),
    }
}

/// The buffer a resource table is kept in until the package has been read,
/// with room for `need` bytes. Never shared: it is held while other entries
/// of the package are read.
pub(super) fn for_table(need: usize) -> Buffer {
    kept(Slot::Table, need)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests that count shared buffers run one at a time.
    static COUNTING: Mutex<()> = Mutex::new(());

    #[test]
    fn a_kept_buffer_is_used_again_by_the_next_entry_of_the_thread() {
        std::thread::spawn(|| {
            let first = for_entry(1000, 5000);
            assert!(first.stored.capacity() >= 1000 && first.inflated.capacity() >= 5000);
            let address = first.inflated.as_ptr();
            drop(first);
            let second = for_entry(10, 4000);
            assert_eq!(second.inflated.as_ptr(), address, "the same block, not a new one");
            assert!(second.inflated.is_empty() && second.stored.is_empty());
        })
        .join()
        .unwrap();
    }

    #[test]
    fn a_kept_buffer_grows_by_doubling_up_to_its_limit() {
        std::thread::spawn(|| {
            drop(for_entry(0, 1 << 20));
            let grown = for_entry(0, (1 << 20) + 1);
            assert_eq!(grown.inflated.capacity(), 2 << 20);
            drop(grown);
            let near = for_entry(0, KEPT_BYTES - 1);
            drop(near);
            let at_limit = for_entry(0, KEPT_BYTES);
            assert_eq!(at_limit.inflated.capacity(), KEPT_BYTES, "never past the limit");
        })
        .join()
        .unwrap();
    }

    /// A large entry takes a shared buffer, which the next large entry of
    /// any thread gets back, and holds no more than the limit.
    #[test]
    fn large_entries_share_a_bounded_pool() {
        let _one = COUNTING.lock().unwrap_or_else(PoisonError::into_inner);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..4 {
                        let buffers = for_entry(100, KEPT_BYTES + 1);
                        assert!(buffers.stored.capacity() < SHARED_BYTES, "a small one is kept");
                        assert!(buffers.inflated.capacity() >= SHARED_BYTES);
                        assert_eq!(HELD.with(Cell::get), 1);
                        let made = POOL.lock().made;
                        assert!(made <= SHARED_BUFFERS, "{made} shared buffers");
                        drop(buffers);
                        assert_eq!(HELD.with(Cell::get), 0);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert!(POOL.lock().made <= SHARED_BUFFERS);
    }

    /// A thread that holds a shared buffer and needs another does not wait,
    /// even when the pool is empty: it would wait for itself.
    #[test]
    fn a_thread_that_holds_a_shared_buffer_never_waits_for_another() {
        let _one = COUNTING.lock().unwrap_or_else(PoisonError::into_inner);
        std::thread::spawn(|| {
            let held: Vec<EntryBuffers> =
                (0..SHARED_BUFFERS + 2).map(|_| for_entry(KEPT_BYTES + 1, 0)).collect();
            assert_eq!(HELD.with(Cell::get), SHARED_BUFFERS + 2);
            drop(held);
            assert_eq!(HELD.with(Cell::get), 0);
            assert!(POOL.lock().made <= SHARED_BUFFERS, "the extra ones are let go");
        })
        .join()
        .unwrap();
    }
}
