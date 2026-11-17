//! Mach-O files: recognising them, and reading where things are in them.
//!
//! Executables in an app bundle carry no file extension, so the only reliable
//! way to find them is the magic number: [`sniff`].
//!
//! Beyond that, the scanner needs to know *where* in a file to look for
//! *what* (design report, section 5.1): the section that holds Objective-C
//! class names, the sections that hold instructions and so no strings, a
//! section that holds script text, the code signature, and the names of the
//! libraries the file links. All of that is in the load commands at the
//! start of each image, and a universal file holds one image per
//! architecture.
//!
//! A file is read once, front to back, in bounded windows (section 6.2), so
//! it is never available whole. [`Walker`] therefore takes the bytes of a
//! file in order, in pieces of any size, keeps only the headers and load
//! commands, and hands out one [`Image`] per architecture as soon as the
//! commands of that image have gone by. An image describes byte ranges that
//! all lie ahead of the commands that name them, so a caller that reads on
//! meets every range after learning of it.
//!
//! Every limit is a count: at most [`MAX_FAT_ARCHES`] images per file and
//! [`MAX_COMMAND_BYTES`] of load commands per image. What a walker keeps in
//! memory is bounded by those two and never by the size of the file.

use std::collections::VecDeque;

use crate::{Budget, FormatError};

/// How many leading bytes [`sniff`] looks at.
pub const SNIFF_BYTES: usize = 8;

/// The shape of a Mach-O file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachOKind {
    /// A single-architecture file.
    Thin,
    /// A universal file holding one image per architecture.
    Fat,
}

/// `MH_MAGIC`, `MH_MAGIC_64` and their byte-swapped forms, as stored on disk.
const THIN_MAGICS: [[u8; 4]; 4] = [
    [0xfe, 0xed, 0xfa, 0xce],
    [0xce, 0xfa, 0xed, 0xfe],
    [0xfe, 0xed, 0xfa, 0xcf],
    [0xcf, 0xfa, 0xed, 0xfe],
];

/// `FAT_MAGIC` and `FAT_MAGIC_64`. Fat headers are always big-endian.
const FAT_MAGICS: [[u8; 4]; 2] = [[0xca, 0xfe, 0xba, 0xbe], [0xca, 0xfe, 0xba, 0xbf]];

/// Most architectures a universal file may list. A Java class file starts
/// with the same four bytes as `FAT_MAGIC`, followed by a version number
/// that is never below 45, so a small count tells the two apart.
pub const MAX_FAT_ARCHES: u32 = 30;

/// Most bytes of load commands one image may have: 1 MiB. Real images stay
/// below a tenth of that.
pub const MAX_COMMAND_BYTES: u32 = 1 << 20;

/// Longest name [`Names`] hands out, in bytes. A longer entry of a name
/// table is not a name anyone wrote and is counted instead.
pub const MAX_NAME_BYTES: usize = 1024;

/// Sections that hold script text rather than data of the program: the
/// segment and section name of each. A runtime that compiles an app into a
/// single executable stores the app's script here (design report, M6).
///
/// `__BUN,__bun` is where `bun build --compile` puts it.
pub const SCRIPT_SECTIONS: [(&[u8], &[u8]); 1] = [(b"__BUN", b"__bun")];

/// Classifies a file from its first [`SNIFF_BYTES`] bytes.
///
/// Returns `None` if the bytes are not the start of a Mach-O file, including
/// when fewer than eight bytes are given.
#[must_use]
pub fn sniff(header: &[u8]) -> Option<MachOKind> {
    let (magic, rest) = header.split_first_chunk::<4>()?;
    let (count, _) = rest.split_first_chunk::<4>()?;
    if THIN_MAGICS.contains(magic) {
        return Some(MachOKind::Thin);
    }
    if FAT_MAGICS.contains(magic) {
        let arches = u32::from_be_bytes(*count);
        if (1..=MAX_FAT_ARCHES).contains(&arches) {
            return Some(MachOKind::Fat);
        }
    }
    None
}

/// A range of bytes of a file: from `start` up to and not including `end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span {
    /// Offset of the first byte.
    pub start: u64,
    /// Offset just past the last byte.
    pub end: u64,
}

impl Span {
    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// What the load commands of one image say about the file.
///
/// Every offset is an offset into the file, not into the image. Every span
/// starts at or after the end of the image's load commands and ends inside
/// the image. Within each list the spans are in ascending order and do not
/// overlap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Image {
    /// Where the image starts in the file.
    pub start: u64,
    /// Where it ends, if the file says: a universal file gives each image a
    /// size, a single-architecture file runs to its end.
    pub end: Option<u64>,
    /// Bytes that hold no readable strings: sections of instructions, and
    /// the encrypted part of an encrypted image.
    pub masked: Vec<Span>,
    /// The `__objc_classname` sections: names of Objective-C classes,
    /// categories and protocols, each ended by a zero byte.
    pub class_names: Vec<Span>,
    /// Sections that hold script text (see [`SCRIPT_SECTIONS`]).
    pub scripts: Vec<Span>,
    /// The embedded code signature.
    pub signature: Option<Span>,
    /// The install names of the libraries the image links, in command order,
    /// as stored: `@rpath/Sparkle.framework/Versions/B/Sparkle`.
    pub libraries: Vec<Vec<u8>>,
    /// Whether part of the image is encrypted, so that its bytes are
    /// ciphertext. Name tables and script sections inside that part are not
    /// listed, and the part is in `masked`.
    pub encrypted: bool,
    /// How many things the commands name that cannot be where they say: a
    /// section outside the image or on top of the commands, a library name
    /// outside its command. Each was left out.
    pub damaged: u32,
}

/// What a [`Walker`] could not read, as counts of images.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Problems {
    /// Images whose header or commands are not well formed, or that the file
    /// ends before.
    pub malformed: u32,
    /// Images with more load commands than [`MAX_COMMAND_BYTES`].
    pub over_budget: u32,
}

impl Problems {
    fn note(&mut self, error: FormatError) {
        let count = match error {
            FormatError::Malformed => &mut self.malformed,
            FormatError::OverBudget(_) => &mut self.over_budget,
        };
        *count = count.saturating_add(1);
    }
}

fn u32_at(bytes: &[u8], at: usize, big_endian: bool) -> Option<u32> {
    let chunk = bytes.get(at..)?.first_chunk::<4>()?;
    Some(if big_endian { u32::from_be_bytes(*chunk) } else { u32::from_le_bytes(*chunk) })
}

fn u64_at(bytes: &[u8], at: usize, big_endian: bool) -> Option<u64> {
    let chunk = bytes.get(at..)?.first_chunk::<8>()?;
    Some(if big_endian { u64::from_be_bytes(*chunk) } else { u64::from_le_bytes(*chunk) })
}

/// The bytes of a fixed-width name field up to its first zero byte.
fn name_field(bytes: &[u8], at: usize) -> Option<&[u8]> {
    let field = bytes.get(at..)?.first_chunk::<16>()?;
    let len = field.iter().position(|&byte| byte == 0).unwrap_or(field.len());
    field.get(..len)
}

/// Size of the header of a 32-bit image. A 64-bit one has four more bytes,
/// which are reserved.
const HEADER_BYTES_32: usize = 28;
const HEADER_BYTES_64: u64 = 32;

/// The header of one image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    wide: bool,
    big_endian: bool,
    commands: u32,
    command_bytes: u32,
}

impl Header {
    /// Reads the first 28 bytes of an image.
    fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        let (wide, big_endian) = match bytes.first_chunk::<4>() {
            Some([0xfe, 0xed, 0xfa, 0xce]) => (false, true),
            Some([0xce, 0xfa, 0xed, 0xfe]) => (false, false),
            Some([0xfe, 0xed, 0xfa, 0xcf]) => (true, true),
            Some([0xcf, 0xfa, 0xed, 0xfe]) => (true, false),
            _ => return Err(FormatError::Malformed),
        };
        let commands = u32_at(bytes, 16, big_endian).ok_or(FormatError::Malformed)?;
        let command_bytes = u32_at(bytes, 20, big_endian).ok_or(FormatError::Malformed)?;
        // Every command is at least eight bytes long. A header whose two
        // counts contradict each other is damaged, whatever their size.
        if u64::from(commands).saturating_mul(8) > u64::from(command_bytes) {
            return Err(FormatError::Malformed);
        }
        if command_bytes > MAX_COMMAND_BYTES {
            return Err(FormatError::OverBudget(Budget::Bytes));
        }
        Ok(Self { wide, big_endian, commands, command_bytes })
    }

    fn len(self) -> u64 {
        if self.wide { HEADER_BYTES_64 } else { HEADER_BYTES_32 as u64 }
    }
}

const LC_REQ_DYLD: u32 = 0x8000_0000;
const LC_SEGMENT: u32 = 0x1;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;

/// The low byte of a section's flags is its type. These three kinds are
/// filled with zeros at load time and have no bytes in the file.
const SECTION_TYPE: u32 = 0xff;
const ZERO_FILL_TYPES: [u32; 3] = [0x1, 0xc, 0x12];
/// `S_ATTR_PURE_INSTRUCTIONS` and `S_ATTR_SOME_INSTRUCTIONS`.
const HOLDS_INSTRUCTIONS: u32 = 0x8000_0000 | 0x0000_0400;

const CLASS_NAMES: &[u8] = b"__objc_classname";

/// The byte ranges of one image while its commands are read.
struct Draft {
    image: Image,
    /// The first byte after the load commands. Nothing the commands name
    /// may start before it.
    floor: u64,
    encrypted: Vec<Span>,
    code: Vec<Span>,
}

impl Draft {
    /// The span of `size` bytes at `offset` into the image, cut to what lies
    /// between the load commands and the end of the image. `None`, counted
    /// as damage, if nothing of it lies there.
    ///
    /// Cutting at the end of the commands is not only for damaged files. A
    /// tool that adds a load command to an image whose header has no room
    /// left grows the commands over the first bytes of the first section,
    /// and such files are in real apps.
    fn span(&mut self, offset: u64, size: u64) -> Option<Span> {
        let limit = self.image.end.unwrap_or(u64::MAX);
        let span = self.image.start.checked_add(offset).map(|start| Span {
            start: start.max(self.floor),
            end: start.saturating_add(size).min(limit),
        });
        match span {
            Some(span) if span.start < span.end => Some(span),
            _ => {
                self.image.damaged = self.image.damaged.saturating_add(1);
                None
            }
        }
    }

    /// One section header of a segment command.
    fn section(&mut self, bytes: &[u8], header: Header) -> Option<()> {
        let section_name = name_field(bytes, 0)?;
        let segment_name = name_field(bytes, 16)?;
        let big_endian = header.big_endian;
        let (size, offset, flags) = if header.wide {
            (
                u64_at(bytes, 40, big_endian)?,
                u32_at(bytes, 48, big_endian)?,
                u32_at(bytes, 64, big_endian)?,
            )
        } else {
            (
                u64::from(u32_at(bytes, 36, big_endian)?),
                u32_at(bytes, 40, big_endian)?,
                u32_at(bytes, 56, big_endian)?,
            )
        };
        // A section without bytes in the file: empty, filled with zeros at
        // load time, or (offset zero) left out of this file altogether, as
        // in the debug companion of a binary.
        if size == 0 || offset == 0 || ZERO_FILL_TYPES.contains(&(flags & SECTION_TYPE)) {
            return Some(());
        }
        let wanted_as_names = section_name == CLASS_NAMES;
        let wanted_as_script = SCRIPT_SECTIONS.contains(&(segment_name, section_name));
        let holds_code = flags & HOLDS_INSTRUCTIONS != 0;
        if !(wanted_as_names || wanted_as_script || holds_code) {
            return Some(());
        }
        let Some(span) = self.span(u64::from(offset), size) else { return Some(()) };
        if holds_code {
            self.code.push(span);
        } else if wanted_as_names {
            self.image.class_names.push(span);
        } else {
            self.image.scripts.push(span);
        }
        Some(())
    }

    /// One load command, `bytes` being exactly the command.
    fn command(&mut self, kind: u32, bytes: &[u8], header: Header) -> Option<()> {
        let big_endian = header.big_endian;
        match kind {
            LC_SEGMENT | LC_SEGMENT_64 => {
                let wide = kind == LC_SEGMENT_64;
                // A segment command's own width decides its layout; one that
                // does not match the image's width is not valid.
                if wide != header.wide {
                    return None;
                }
                let (count_at, first, each) = if wide { (64, 72, 80) } else { (48, 56, 68) };
                let count = usize::try_from(u32_at(bytes, count_at, big_endian)?).ok()?;
                let sections = bytes.get(first..)?;
                if count.checked_mul(each)? > sections.len() {
                    return None;
                }
                for section in sections.chunks_exact(each).take(count) {
                    self.section(section, header)?;
                }
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB => {
                let at = usize::try_from(u32_at(bytes, 8, big_endian)?).ok()?;
                // The name follows the fixed part of the command.
                match bytes.get(at..).filter(|_| at >= 24) {
                    Some(name) => {
                        let len = name.iter().position(|&byte| byte == 0).unwrap_or(name.len());
                        self.image.libraries.push(name.get(..len)?.to_vec());
                    }
                    None => self.image.damaged = self.image.damaged.saturating_add(1),
                }
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                let offset = u32_at(bytes, 8, big_endian)?;
                let size = u32_at(bytes, 12, big_endian)?;
                let id = u32_at(bytes, 16, big_endian)?;
                // Zero means the image is stored decrypted.
                if id != 0 {
                    self.image.encrypted = true;
                    if let Some(span) =
                        self.span(u64::from(offset), u64::from(size)).filter(|_| size != 0)
                    {
                        self.encrypted.push(span);
                    }
                }
            }
            LC_CODE_SIGNATURE => {
                let offset = u32_at(bytes, 8, big_endian)?;
                let size = u32_at(bytes, 12, big_endian)?;
                // An image is signed once. A second command is damage and
                // the first one stands.
                if self.image.signature.is_some() {
                    self.image.damaged = self.image.damaged.saturating_add(1);
                } else if size != 0 {
                    self.image.signature = self.span(u64::from(offset), u64::from(size));
                }
            }
            _ => {}
        }
        Some(())
    }

    fn finish(mut self) -> Image {
        // Ciphertext holds no names and no script.
        let encrypted = self.encrypted;
        let readable = |span: &Span| !encrypted.iter().any(|secret| secret.overlaps(*span));
        self.image.class_names.retain(readable);
        self.image.scripts.retain(readable);
        disjoint(&mut self.image.class_names);
        disjoint(&mut self.image.scripts);

        let mut masked = self.code;
        masked.extend(encrypted);
        masked.sort_unstable();
        // The union: runs that touch or overlap become one.
        for span in masked {
            match self.image.masked.last_mut() {
                Some(last) if span.start <= last.end => last.end = last.end.max(span.end),
                _ => self.image.masked.push(span),
            }
        }
        self.image
    }
}

/// Sorts `spans` and cuts each one back to start where the one before it
/// ends, so that no byte is in two of them. What is left empty is dropped.
fn disjoint(spans: &mut Vec<Span>) {
    spans.sort_unstable();
    let mut floor = 0;
    for span in spans.iter_mut() {
        span.start = span.start.max(floor);
        floor = floor.max(span.end);
    }
    spans.retain(|span| span.start < span.end);
}

/// Reads the load commands of one image that starts at `start` in the file.
fn parse_commands(
    header: Header,
    commands: &[u8],
    start: u64,
    end: Option<u64>,
) -> Result<Image, FormatError> {
    let floor = start
        .checked_add(header.len())
        .and_then(|at| at.checked_add(u64::from(header.command_bytes)))
        .ok_or(FormatError::Malformed)?;
    let mut draft = Draft {
        image: Image { start, end, ..Image::default() },
        floor,
        encrypted: Vec::new(),
        code: Vec::new(),
    };
    let mut rest = commands;
    for _ in 0..header.commands {
        let kind = u32_at(rest, 0, header.big_endian).ok_or(FormatError::Malformed)?;
        let size = u32_at(rest, 4, header.big_endian)
            .and_then(|size| usize::try_from(size).ok())
            .filter(|&size| size >= 8)
            .ok_or(FormatError::Malformed)?;
        let (command, after) = rest.split_at_checked(size).ok_or(FormatError::Malformed)?;
        draft.command(kind, command, header).ok_or(FormatError::Malformed)?;
        rest = after;
    }
    Ok(draft.finish())
}

/// Bytes the walker is waiting for.
struct Grab {
    purpose: Purpose,
    /// File offset of the first byte of `buf`.
    start: u64,
    /// How many bytes `buf` has to hold before it can be read.
    want: usize,
    buf: Vec<u8>,
}

enum Purpose {
    /// The first eight bytes of the file.
    Magic,
    /// The list of images of a universal file.
    Arches { wide: bool },
    /// The header of the image that covers `start` to `end`.
    Header { start: u64, end: Option<u64> },
    /// The load commands of that image.
    Commands { header: Header, start: u64, end: Option<u64> },
}

/// Reads the structure of a Mach-O file from its bytes as they go by.
///
/// Feed it every byte of the file, in order, through [`push`](Self::push).
/// After each call, [`take_images`](Self::take_images) returns the images
/// whose load commands are now complete, in file order.
/// [`finish`](Self::finish) says what could not be read.
///
/// The result is a function of the file's bytes alone: how they are cut
/// into pieces changes nothing.
pub struct Walker {
    /// File offset of the next byte `push` will be given.
    position: u64,
    grab: Option<Grab>,
    /// Images of a universal file not reached yet, in ascending order.
    ahead: VecDeque<(u64, u64)>,
    images: Vec<Image>,
    problems: Problems,
}

impl Default for Walker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Walker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Walker")
            .field("position", &self.position)
            .field("ahead", &self.ahead.len())
            .field("problems", &self.problems)
            .finish_non_exhaustive()
    }
}

impl Walker {
    /// A walker at the start of a file.
    #[must_use]
    pub fn new() -> Self {
        Self {
            position: 0,
            grab: Some(Grab {
                purpose: Purpose::Magic,
                start: 0,
                want: SNIFF_BYTES,
                buf: Vec::with_capacity(SNIFF_BYTES),
            }),
            ahead: VecDeque::new(),
            images: Vec::new(),
            problems: Problems::default(),
        }
    }

    /// Takes the next bytes of the file.
    pub fn push(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let Some(grab) = &mut self.grab else {
                // Nothing more is wanted from this file.
                self.position = self.position.saturating_add(bytes.len() as u64);
                return;
            };
            let wanted_from = grab.start.saturating_add(grab.buf.len() as u64);
            let gap = wanted_from.saturating_sub(self.position);
            if gap > 0 {
                let skip = usize::try_from(gap).map_or(bytes.len(), |gap| gap.min(bytes.len()));
                bytes = bytes.get(skip..).unwrap_or_default();
                self.position = self.position.saturating_add(skip as u64);
                continue;
            }
            let take = grab.want.saturating_sub(grab.buf.len()).min(bytes.len());
            let (taken, rest) = bytes.split_at_checked(take).unwrap_or((bytes, &[]));
            grab.buf.extend_from_slice(taken);
            bytes = rest;
            self.position = self.position.saturating_add(take as u64);
            self.settle();
        }
    }

    /// The images whose load commands have been read since the last call.
    pub fn take_images(&mut self) -> Vec<Image> {
        std::mem::take(&mut self.images)
    }

    /// Ends the file and says what could not be read. An image the file
    /// ended before, or in the middle of, counts as malformed.
    #[must_use]
    pub fn finish(mut self) -> Problems {
        if self.grab.is_some() {
            self.problems.note(FormatError::Malformed);
        }
        for _ in &self.ahead {
            self.problems.note(FormatError::Malformed);
        }
        self.problems
    }

    /// Acts on every grab that is complete. One grab can lead straight to
    /// the next, as when an image has no load commands at all.
    fn settle(&mut self) {
        while let Some(grab) = self.grab.take_if(|grab| grab.buf.len() >= grab.want) {
            self.grab = self.complete(grab).or_else(|| self.next_image());
        }
    }

    /// Waits for the header of the next image of a universal file, if there
    /// is one that the file has not gone past already.
    fn next_image(&mut self) -> Option<Grab> {
        while let Some((start, end)) = self.ahead.pop_front() {
            if start < self.position {
                self.problems.note(FormatError::Malformed);
                continue;
            }
            return Some(Grab {
                purpose: Purpose::Header { start, end: Some(end) },
                start,
                want: HEADER_BYTES_32,
                buf: Vec::with_capacity(HEADER_BYTES_32),
            });
        }
        None
    }

    /// Reads a complete grab. Returns what to wait for next within the same
    /// image, or `None` when the image is done with.
    fn complete(&mut self, grab: Grab) -> Option<Grab> {
        let Grab { purpose, buf, .. } = grab;
        let step = match purpose {
            Purpose::Magic => Self::after_magic(buf),
            Purpose::Arches { wide } => {
                self.arches(&buf, wide);
                Ok(None)
            }
            Purpose::Header { start, end } => Header::parse(&buf).and_then(|header| {
                let from = start.checked_add(header.len()).ok_or(FormatError::Malformed)?;
                let want = usize::try_from(header.command_bytes)
                    .map_err(|_| FormatError::OverBudget(Budget::Bytes))?;
                let to = from.checked_add(want as u64).ok_or(FormatError::Malformed)?;
                if end.is_some_and(|end| to > end) {
                    return Err(FormatError::Malformed);
                }
                Ok(Some(Grab {
                    purpose: Purpose::Commands { header, start, end },
                    start: from,
                    want,
                    buf: Vec::with_capacity(want),
                }))
            }),
            Purpose::Commands { header, start, end } => parse_commands(header, &buf, start, end)
                .map(|image| {
                    self.images.push(image);
                    None
                }),
        };
        step.unwrap_or_else(|error| {
            self.problems.note(error);
            None
        })
    }

    /// Decides from the first eight bytes what the file is.
    fn after_magic(buf: Vec<u8>) -> Result<Option<Grab>, FormatError> {
        match sniff(&buf) {
            // The header of the one image starts with these same bytes.
            Some(MachOKind::Thin) => Ok(Some(Grab {
                purpose: Purpose::Header { start: 0, end: None },
                start: 0,
                want: HEADER_BYTES_32,
                buf,
            })),
            Some(MachOKind::Fat) => {
                let wide = buf.get(3) == Some(&0xbf);
                let count = u32_at(&buf, 4, true).ok_or(FormatError::Malformed)?;
                let each: usize = if wide { 32 } else { 20 };
                let want = usize::try_from(count)
                    .ok()
                    .and_then(|count| count.checked_mul(each))
                    .and_then(|list| list.checked_add(SNIFF_BYTES))
                    .ok_or(FormatError::Malformed)?;
                Ok(Some(Grab { purpose: Purpose::Arches { wide }, start: 0, want, buf }))
            }
            None => Err(FormatError::Malformed),
        }
    }

    /// Reads the list of images of a universal file. An image that starts
    /// inside the list, is empty, or overlaps an earlier one is malformed
    /// and left out.
    fn arches(&mut self, buf: &[u8], wide: bool) {
        let each = if wide { 32 } else { 20 };
        let mut listed: Vec<(u64, u64)> = buf
            .get(SNIFF_BYTES..)
            .unwrap_or_default()
            .chunks_exact(each)
            .filter_map(|arch| {
                let (offset, size) = if wide {
                    (u64_at(arch, 8, true)?, u64_at(arch, 16, true)?)
                } else {
                    (u64::from(u32_at(arch, 8, true)?), u64::from(u32_at(arch, 12, true)?))
                };
                Some((offset, offset.saturating_add(size)))
            })
            .collect();
        listed.sort_unstable();
        let mut floor = buf.len() as u64;
        for (start, end) in listed {
            if start < floor || end <= start {
                self.problems.note(FormatError::Malformed);
            } else {
                self.ahead.push_back((start, end));
                floor = end;
            }
        }
    }
}

/// Splits a name table into its names.
///
/// A name table, such as the `__objc_classname` section, is a run of names
/// each ended by a zero byte. Feed it the bytes of one table in order, in
/// pieces of any size, and it calls back once per name. Empty names are
/// passed over. A name longer than [`MAX_NAME_BYTES`] is not handed out; it
/// is counted in [`overlong`](Self::overlong), so memory stays bounded
/// whatever the table holds.
#[derive(Debug, Clone, Default)]
pub struct Names {
    pending: Vec<u8>,
    /// Whether the name being read has already outgrown the limit.
    dropping: bool,
    overlong: u32,
}

impl Names {
    /// A splitter at the start of a table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many names were longer than [`MAX_NAME_BYTES`] and left out.
    #[must_use]
    pub const fn overlong(&self) -> u32 {
        self.overlong
    }

    /// Takes the next bytes of the table and calls `each` for every name
    /// that ends in them.
    pub fn push(&mut self, bytes: &[u8], mut each: impl FnMut(&[u8])) {
        for piece in bytes.split_inclusive(|&byte| byte == 0) {
            let (text, ended) = match piece.split_last() {
                Some((0, text)) => (text, true),
                _ => (piece, false),
            };
            if !self.dropping {
                if self.pending.len().saturating_add(text.len()) > MAX_NAME_BYTES {
                    self.dropping = true;
                    self.pending.clear();
                    self.overlong = self.overlong.saturating_add(1);
                } else if ended && self.pending.is_empty() {
                    // The common case: a whole name in one piece, no copy.
                    if !text.is_empty() {
                        each(text);
                    }
                } else {
                    self.pending.extend_from_slice(text);
                }
            }
            if ended {
                if !self.pending.is_empty() {
                    each(&self.pending);
                    self.pending.clear();
                }
                self.dropping = false;
            }
        }
    }

    /// Ends the table. A last name that no zero byte ended is still a name.
    pub fn finish(&mut self, mut each: impl FnMut(&[u8])) {
        if !self.pending.is_empty() {
            each(&self.pending);
            self.pending.clear();
        }
        self.dropping = false;
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::macho_build::{Binary, Section, fat};

    #[test]
    fn recognises_every_thin_magic() {
        for magic in THIN_MAGICS {
            let mut header = magic.to_vec();
            header.extend_from_slice(&[0x0c, 0, 0, 1]);
            assert_eq!(sniff(&header), Some(MachOKind::Thin));
        }
    }

    #[test]
    fn recognises_universal_files_but_not_java_classes() {
        // Two architectures.
        assert_eq!(sniff(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]), Some(MachOKind::Fat));
        assert_eq!(sniff(&[0xca, 0xfe, 0xba, 0xbf, 0, 0, 0, 1]), Some(MachOKind::Fat));
        // Java 8 class file: minor 0, major 52.
        assert_eq!(sniff(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]), None);
        // Zero architectures is not a usable universal file.
        assert_eq!(sniff(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0]), None);
    }

    #[test]
    fn rejects_short_and_foreign_input() {
        assert_eq!(sniff(&[]), None);
        assert_eq!(sniff(&[0xcf, 0xfa, 0xed, 0xfe]), None, "needs eight bytes");
        assert_eq!(sniff(b"#!/bin/sh\n"), None);
        assert_eq!(sniff(b"\x7fELF\x02\x01\x01\x00"), None);
        assert_eq!(sniff(b"PK\x03\x04\x14\x00\x00\x00"), None);
    }

    /// Walks `file` in pieces of `step` bytes.
    fn walk(file: &[u8], step: usize) -> (Vec<Image>, Problems) {
        let mut walker = Walker::new();
        let mut images = Vec::new();
        for piece in file.chunks(step.max(1)) {
            walker.push(piece);
            images.extend(walker.take_images());
        }
        (images, walker.finish())
    }

    fn one(file: &[u8]) -> Image {
        let (images, problems) = walk(file, usize::MAX);
        assert_eq!(problems, Problems::default());
        assert_eq!(images.len(), 1);
        images.into_iter().next().unwrap()
    }

    /// The bytes of `file` that `span` covers.
    fn bytes(file: &[u8], span: Span) -> &[u8] {
        &file[span.start as usize..span.end as usize]
    }

    /// A binary with one of everything the scanner looks for.
    fn sample() -> Binary {
        Binary::new()
            .library("/usr/lib/libSystem.B.dylib")
            .library("@rpath/Sparkle.framework/Versions/B/Sparkle")
            .section(Section::code("__TEXT", "__text", b"\x90\x90\x90\x90 instructions"))
            .section(Section::data("__TEXT", "__cstring", b"a string\0another\0"))
            .section(Section::data("__TEXT", "__objc_classname", b"AppDelegate\0MSACAppCenter\0"))
            .section(Section::data("__BUN", "__bun", b"fetch('https://us.i.posthog.com')"))
            .section(Section::zero_fill("__DATA", "__bss", 4096))
            .signature(b"signature bytes")
    }

    /// The oracle is the builder's own record of where it put each part.
    #[test]
    fn an_image_says_where_each_part_of_the_file_is() {
        for big_endian in [false, true] {
            for wide in [true, false] {
                let binary = sample().big_endian(big_endian).wide(wide);
                let file = binary.build();
                let image = one(&file);
                let context = format!("big_endian {big_endian} wide {wide}");

                assert_eq!((image.start, image.end), (0, None), "{context}");
                assert_eq!(
                    image.libraries,
                    [
                        b"/usr/lib/libSystem.B.dylib".to_vec(),
                        b"@rpath/Sparkle.framework/Versions/B/Sparkle".to_vec()
                    ],
                    "{context}"
                );
                let parts = |spans: &[Span]| -> Vec<&[u8]> {
                    spans.iter().map(|span| bytes(&file, *span)).collect()
                };
                assert_eq!(parts(&image.masked), [&b"\x90\x90\x90\x90 instructions"[..]]);
                assert_eq!(parts(&image.class_names), [&b"AppDelegate\0MSACAppCenter\0"[..]]);
                assert_eq!(parts(&image.scripts), [&b"fetch('https://us.i.posthog.com')"[..]]);
                assert_eq!(bytes(&file, image.signature.unwrap()), b"signature bytes");
                assert!(!image.encrypted, "{context}");
                assert_eq!(image.damaged, 0, "{context}");
            }
        }
    }

    #[test]
    fn a_universal_file_yields_one_image_per_architecture_at_its_own_offset() {
        let first = sample().build();
        let second = Binary::new()
            .wide(false)
            .section(Section::data("__TEXT", "__objc_classname", b"SUUpdater\0"))
            .build();
        for wide_list in [false, true] {
            let file = fat(&[&first, &second], wide_list);
            let (images, problems) = walk(&file, usize::MAX);
            assert_eq!(problems, Problems::default());
            assert_eq!(images.len(), 2);

            // Each image is the same as when it stands alone, moved.
            for (image, alone) in images.iter().zip([&first, &second]) {
                let end = image.end.unwrap();
                assert_eq!(&file[image.start as usize..end as usize], &alone[..]);
                let moved = |span: Span| Span {
                    start: span.start - image.start,
                    end: span.end - image.start,
                };
                let lone = one(alone);
                let names: Vec<Span> = image.class_names.iter().copied().map(moved).collect();
                assert_eq!(names, lone.class_names);
                assert_eq!(image.signature.map(moved), lone.signature);
                assert_eq!(image.libraries, lone.libraries);
            }
            assert_eq!(bytes(&file, images[1].class_names[0]), b"SUUpdater\0");
        }
    }

    /// Build plan, task 6: an encrypted binary is recognised. What lies in
    /// the encrypted part is not listed, and the part is masked.
    #[test]
    fn an_encrypted_image_lists_nothing_inside_the_ciphertext() {
        // `cryptid` zero is the same file after decryption: every part is
        // where it is in the encrypted one, and nothing is hidden.
        let binary = sample().encrypt_from("__TEXT", "__cstring");
        let clear = one(&binary.clone().crypt_id(0).build());
        assert!(!clear.encrypted);
        assert_eq!((clear.masked.len(), clear.class_names.len(), clear.scripts.len()), (1, 1, 1));

        let image = one(&binary.build());
        assert!(image.encrypted);
        // The class names and the script lie after `__cstring`.
        assert!(image.class_names.is_empty());
        assert!(image.scripts.is_empty());
        // The code section, then the encrypted run to the end of the last
        // section. They touch, so they are one run.
        assert_eq!(image.masked.len(), 1);
        assert_eq!(image.masked[0].start, clear.masked[0].start);
        assert_eq!(image.masked[0].end, clear.scripts[0].end);
        // What the commands say stays readable.
        assert_eq!(image.libraries, clear.libraries);
        assert_eq!(image.signature, clear.signature);
        assert_eq!(image.damaged, 0);
    }

    #[test]
    fn what_cannot_be_where_the_commands_say_is_left_out_and_counted() {
        // A section that claims to lie on top of the header.
        let on_header = Binary::new()
            .section(Section::data("__TEXT", "__objc_classname", b"Real\0"))
            .section(Section::data("__TEXT", "__objc_classname", b"Fake\0").at(4))
            .build();
        let image = one(&on_header);
        assert_eq!(image.damaged, 1);
        assert_eq!(image.class_names.len(), 1);
        assert_eq!(bytes(&on_header, image.class_names[0]), b"Real\0");

        // A section that begins in the last bytes of the load commands, as
        // after a tool grew the commands over it: cut, not left out.
        let floor = Binary::new()
            .section(Section::data("__TEXT", "__objc_classname", b"12345678Real\0"))
            .build()
            .len() as u32
            - 13;
        let grown = Binary::new()
            .section(
                Section::data("__TEXT", "__objc_classname", b"12345678Real\0")
                    .at(floor - 8)
                    .claim(21),
            )
            .build();
        let image = one(&grown);
        assert_eq!(image.damaged, 0);
        assert_eq!(bytes(&grown, image.class_names[0]), b"12345678Real\0");

        // A section past the end of its image in a universal file.
        let inner = Binary::new()
            .section(Section::data("__TEXT", "__objc_classname", b"Late\0").at(1 << 20))
            .build();
        let (images, problems) = walk(&fat(&[&inner], false), usize::MAX);
        assert_eq!(problems, Problems::default());
        assert_eq!((images[0].damaged, images[0].class_names.len()), (1, 0));

        // A section that runs past the end of its image is cut there.
        let long = Binary::new()
            .section(Section::data("__TEXT", "__objc_classname", b"Name\0").claim(1 << 30))
            .build();
        let (images, _) = walk(&fat(&[&long], false), usize::MAX);
        assert_eq!(images[0].class_names[0].end, images[0].end.unwrap());

        // Two sections over the same bytes: no byte is listed twice.
        let twice = Binary::new()
            .section(Section::data("__TEXT", "__objc_classname", b"One\0Two\0"))
            .section(Section::data("__DATA", "__objc_classname", b"").overlap_previous(4))
            .build();
        let image = one(&twice);
        let covered: u64 = image.class_names.iter().map(|span| span.end - span.start).sum();
        assert_eq!(covered, 8);
        assert!(image.class_names.windows(2).all(|pair| pair[0].end <= pair[1].start));
    }

    #[test]
    fn a_damaged_command_table_yields_no_image() {
        let good = sample().build();
        assert_eq!(walk(&good, usize::MAX).1, Problems::default());

        // The first command claims to be larger than all the commands.
        let mut oversized = good.clone();
        oversized[32 + 4..32 + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        // A command shorter than its own header.
        let mut undersized = good.clone();
        undersized[32 + 4..32 + 8].copy_from_slice(&4u32.to_le_bytes());
        // More commands than the bytes can hold.
        let mut too_many = good.clone();
        too_many[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        // The file ends inside the load commands.
        let cut = &good[..40];
        for (name, file) in [
            ("oversized", &oversized[..]),
            ("undersized", &undersized[..]),
            ("too many", &too_many[..]),
            ("cut", cut),
        ] {
            let (images, problems) = walk(file, usize::MAX);
            assert!(images.is_empty(), "{name}");
            assert_eq!(problems, Problems { malformed: 1, over_budget: 0 }, "{name}");
        }

        // More load commands than the budget is its own kind of problem.
        let mut huge = good;
        huge[20..24].copy_from_slice(&(MAX_COMMAND_BYTES + 1).to_le_bytes());
        let (images, problems) = walk(&huge, usize::MAX);
        assert!(images.is_empty());
        assert_eq!(problems, Problems { malformed: 0, over_budget: 1 });
    }

    #[test]
    fn images_a_universal_file_cannot_hold_are_counted() {
        let inner = sample().build();
        let good = fat(&[&inner, &inner], false);
        let entry = |index: usize| 8 + index * 20;

        // The second image claims to start inside the first.
        let mut overlapping = good.clone();
        let first_offset = good[entry(0) + 8..entry(0) + 12].to_vec();
        overlapping[entry(1) + 8..entry(1) + 12].copy_from_slice(&first_offset);
        let (images, problems) = walk(&overlapping, usize::MAX);
        assert_eq!(images.len(), 1);
        assert_eq!(problems, Problems { malformed: 1, over_budget: 0 });

        // An image that starts inside the list of images.
        let mut inside_list = good.clone();
        inside_list[entry(0) + 8..entry(0) + 12].copy_from_slice(&4u32.to_be_bytes());
        let (images, problems) = walk(&inside_list, usize::MAX);
        assert_eq!(images.len(), 1);
        assert_eq!(problems.malformed, 1);

        // The file ends before the second image.
        let second_start =
            u32::from_be_bytes(good[entry(1) + 8..entry(1) + 12].try_into().unwrap());
        let (images, problems) = walk(&good[..second_start as usize], usize::MAX);
        assert_eq!(images.len(), 1);
        assert_eq!(problems.malformed, 1);

        // An image too small to hold its own header and commands.
        let mut tiny = good;
        tiny[entry(0) + 12..entry(0) + 16].copy_from_slice(&40u32.to_be_bytes());
        let (images, problems) = walk(&tiny, usize::MAX);
        assert_eq!(images.len(), 1);
        assert_eq!(problems.malformed, 1);
    }

    #[test]
    fn an_image_without_commands_is_an_image() {
        let file = Binary::new().build();
        assert_eq!(file.len(), 32);
        assert_eq!(one(&file), Image { start: 0, end: None, ..Image::default() });
        // The scanner's own fixtures: a header, then anything.
        let mut with_text = file;
        with_text.extend_from_slice(b"not load commands");
        assert_eq!(one(&with_text).damaged, 0);
    }

    fn names_of(table: &[u8], step: usize) -> (Vec<Vec<u8>>, u32) {
        let mut names = Names::new();
        let mut found = Vec::new();
        for piece in table.chunks(step.max(1)) {
            names.push(piece, |name| found.push(name.to_vec()));
        }
        names.finish(|name| found.push(name.to_vec()));
        (found, names.overlong())
    }

    #[test]
    fn a_name_table_splits_at_zero_bytes_however_it_is_cut() {
        let table = b"AppDelegate\0\0MSACAppCenter\0X\0unterminated";
        let expected: Vec<Vec<u8>> = [&b"AppDelegate"[..], b"MSACAppCenter", b"X", b"unterminated"]
            .map(<[u8]>::to_vec)
            .into();
        for step in [1, 2, 3, 5, 11, 12, 13, 100] {
            assert_eq!(names_of(table, step), (expected.clone(), 0), "step {step}");
        }
        assert_eq!(names_of(b"", 4), (vec![], 0));
        assert_eq!(names_of(b"\0\0\0", 2), (vec![], 0));
    }

    #[test]
    fn an_overlong_name_is_counted_and_the_next_one_is_read() {
        let mut table = vec![b'a'; MAX_NAME_BYTES];
        table.push(0);
        table.extend_from_slice(&vec![b'b'; MAX_NAME_BYTES + 1]);
        table.push(0);
        table.extend_from_slice(b"after\0");
        table.extend_from_slice(&vec![b'c'; MAX_NAME_BYTES * 3]);
        for step in [1, 7, 1000, 1024, 1025, 5000] {
            let (names, overlong) = names_of(&table, step);
            assert_eq!(names, [vec![b'a'; MAX_NAME_BYTES], b"after".to_vec()], "step {step}");
            assert_eq!(overlong, 2, "step {step}");
        }
    }

    proptest! {
        #[test]
        fn sniff_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..32)) {
            let _ = sniff(&bytes);
        }

        /// Design report, section 6.4 rule 4: how a file is cut into windows
        /// cannot change what is found in it.
        #[test]
        fn the_walk_does_not_depend_on_how_the_file_is_cut(
            step in 1..300usize,
            universal in any::<bool>(),
            encrypted in any::<bool>(),
        ) {
            let mut binary = sample();
            if encrypted {
                binary = binary.encrypt_from("__TEXT", "__objc_classname");
            }
            let image = binary.build();
            let file = if universal { fat(&[&image, &image], false) } else { image };
            prop_assert_eq!(walk(&file, step), walk(&file, usize::MAX));
        }

        /// Hostile input may be rejected but must never panic, and every
        /// span that comes out obeys the documented order.
        #[test]
        fn damage_anywhere_never_panics_and_spans_stay_in_order(
            edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
            cut in any::<prop::sample::Index>(),
            step in 1..200usize,
            universal in any::<bool>(),
        ) {
            let image = sample().encrypt_from("__TEXT", "__cstring").crypt_id(1).build();
            let mut file = if universal { fat(&[&image, &image], true) } else { image };
            // Damage lands where the structure is: the first few hundred bytes.
            for (at, value) in edits {
                let at = at.index(file.len().min(700));
                file[at] = value;
            }
            file.truncate(cut.index(file.len() + 1));

            let (images, problems) = walk(&file, step);
            prop_assert_eq!(&(images.clone(), problems), &walk(&file, usize::MAX));
            let mut floor = 0;
            for image in &images {
                prop_assert!(image.start >= floor);
                let limit = image.end.unwrap_or(u64::MAX);
                floor = image.end.unwrap_or(floor);
                let signature = image.signature.iter().copied().collect::<Vec<_>>();
                for spans in [&image.masked, &image.class_names, &image.scripts, &signature] {
                    let mut last = image.start;
                    for span in spans {
                        prop_assert!(span.start >= last && span.start < span.end);
                        prop_assert!(span.end <= limit);
                        last = span.end;
                    }
                }
            }
        }

        #[test]
        fn names_do_not_depend_on_how_the_table_is_cut(
            table in prop::collection::vec(prop_oneof![3 => Just(0u8), 5 => any::<u8>()], 0..400),
            step in 1..64usize,
        ) {
            let whole = names_of(&table, usize::MAX);
            prop_assert_eq!(&names_of(&table, step), &whole);
            // The oracle: split at zero bytes, drop the empty names.
            let expected: Vec<Vec<u8>> = table
                .split(|&byte| byte == 0)
                .filter(|name| !name.is_empty())
                .map(<[u8]>::to_vec)
                .collect();
            prop_assert_eq!(whole, (expected, 0));
        }
    }
}
