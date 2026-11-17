//! Test support: writes small Mach-O files.
//!
//! Tests of the Mach-O reader and of the macOS collector need files whose
//! content is known exactly, and the repository stores no real binary. This
//! module builds them: a header, load commands, and the bytes the commands
//! point at. Nothing it writes can run. It is compiled only for tests and
//! under the `testkit` feature, which no shipped crate enables.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test support: it writes files and parses nothing"
)]

/// One section of a [`Binary`].
#[derive(Debug, Clone)]
pub struct Section {
    segment: String,
    name: String,
    data: Vec<u8>,
    flags: u32,
    /// The size the section header claims, if not the size of `data`.
    claimed_size: Option<u64>,
    /// The file offset the section header claims, if not where `data` is.
    claimed_offset: Option<u32>,
    /// Claim to cover the last bytes of the section before this one.
    overlap_previous: Option<u32>,
    zero_fill: bool,
}

impl Section {
    fn new(segment: &str, name: &str, data: &[u8], flags: u32) -> Self {
        Self {
            segment: segment.into(),
            name: name.into(),
            data: data.to_vec(),
            flags,
            claimed_size: None,
            claimed_offset: None,
            overlap_previous: None,
            zero_fill: false,
        }
    }

    /// A section of instructions.
    #[must_use]
    pub fn code(segment: &str, name: &str, data: &[u8]) -> Self {
        // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
        Self::new(segment, name, data, 0x8000_0400)
    }

    /// A section of data.
    #[must_use]
    pub fn data(segment: &str, name: &str, data: &[u8]) -> Self {
        Self::new(segment, name, data, 0)
    }

    /// A section that has a size and no bytes in the file.
    #[must_use]
    pub fn zero_fill(segment: &str, name: &str, size: u64) -> Self {
        let mut section = Self::new(segment, name, b"", 0x1);
        section.claimed_size = Some(size);
        section.zero_fill = true;
        section
    }

    /// Makes the header claim the section lies at `offset` in the image.
    #[must_use]
    pub fn at(mut self, offset: u32) -> Self {
        self.claimed_offset = Some(offset);
        self
    }

    /// Makes the header claim the section is `size` bytes long.
    #[must_use]
    pub fn claim(mut self, size: u64) -> Self {
        self.claimed_size = Some(size);
        self
    }

    /// Makes the header claim the last `bytes` bytes of the section before
    /// this one.
    #[must_use]
    pub fn overlap_previous(mut self, bytes: u32) -> Self {
        self.overlap_previous = Some(bytes);
        self
    }
}

/// A single-architecture Mach-O file to be built.
#[derive(Debug, Clone)]
pub struct Binary {
    wide: bool,
    big_endian: bool,
    libraries: Vec<String>,
    sections: Vec<Section>,
    signature: Option<Vec<u8>>,
    encrypt_from: Option<(String, String)>,
    crypt_id: u32,
    trailer: Vec<u8>,
}

impl Default for Binary {
    fn default() -> Self {
        Self::new()
    }
}

impl Binary {
    /// An empty 64-bit little-endian executable: a header and no commands.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            wide: true,
            big_endian: false,
            libraries: Vec::new(),
            sections: Vec::new(),
            signature: None,
            encrypt_from: None,
            crypt_id: 1,
            trailer: Vec::new(),
        }
    }

    /// 64-bit (the default) or 32-bit.
    #[must_use]
    pub const fn wide(mut self, wide: bool) -> Self {
        self.wide = wide;
        self
    }

    /// Big-endian, or little-endian (the default).
    #[must_use]
    pub const fn big_endian(mut self, big_endian: bool) -> Self {
        self.big_endian = big_endian;
        self
    }

    /// Links a library by its install name.
    #[must_use]
    pub fn library(mut self, install_name: &str) -> Self {
        self.libraries.push(install_name.into());
        self
    }

    /// Adds a section. Sections are stored in the order they are added.
    #[must_use]
    pub fn section(mut self, section: Section) -> Self {
        self.sections.push(section);
        self
    }

    /// Embeds `blob` as the code signature, after the last section.
    #[must_use]
    pub fn signature(mut self, blob: &[u8]) -> Self {
        self.signature = Some(blob.to_vec());
        self
    }

    /// Marks the file as encrypted from the start of the named section to
    /// the end of the last section. The bytes themselves are left as they
    /// are; only the load command says they are ciphertext.
    #[must_use]
    pub fn encrypt_from(mut self, segment: &str, section: &str) -> Self {
        self.encrypt_from = Some((segment.into(), section.into()));
        self
    }

    /// The `cryptid` of the encryption command: non-zero (the default is 1)
    /// for an encrypted file, zero for one that was decrypted.
    #[must_use]
    pub const fn crypt_id(mut self, id: u32) -> Self {
        self.crypt_id = id;
        self
    }

    /// Appends bytes after everything the load commands describe.
    #[must_use]
    pub fn trailer(mut self, bytes: &[u8]) -> Self {
        self.trailer = bytes.to_vec();
        self
    }

    fn word(&self, out: &mut Vec<u8>, value: u32) {
        out.extend(if self.big_endian { value.to_be_bytes() } else { value.to_le_bytes() });
    }

    fn long(&self, out: &mut Vec<u8>, value: u64) {
        out.extend(if self.big_endian { value.to_be_bytes() } else { value.to_le_bytes() });
    }

    /// A machine word: 64 bits in a 64-bit file, 32 otherwise.
    fn native(&self, out: &mut Vec<u8>, value: u64) {
        if self.wide {
            self.long(out, value);
        } else {
            self.word(out, value as u32);
        }
    }

    fn name16(out: &mut Vec<u8>, name: &str) {
        let mut field = [0u8; 16];
        let len = name.len().min(16);
        field[..len].copy_from_slice(&name.as_bytes()[..len]);
        out.extend(field);
    }

    fn library_command_len(&self, name: &str) -> usize {
        let align = if self.wide { 8 } else { 4 };
        (24 + name.len() + 1).div_ceil(align) * align
    }

    /// The bytes of the file.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let header_len = if self.wide { 32 } else { 28 };
        let segment_len = if self.wide { 72 + 80 } else { 56 + 68 };
        let encryption_len = if self.wide { 24 } else { 20 };
        let commands_len = self.sections.len() * segment_len
            + self.libraries.iter().map(|name| self.library_command_len(name)).sum::<usize>()
            + if self.encrypt_from.is_some() { encryption_len } else { 0 }
            + if self.signature.is_some() { 16 } else { 0 };
        let command_count = self.sections.len()
            + self.libraries.len()
            + usize::from(self.encrypt_from.is_some())
            + usize::from(self.signature.is_some());

        // Where each section's bytes go.
        let mut offsets = Vec::with_capacity(self.sections.len());
        let mut cursor = header_len + commands_len;
        for section in &self.sections {
            offsets.push(cursor);
            cursor += section.data.len();
        }
        let data_end = cursor;

        let mut out = Vec::with_capacity(data_end + 64);
        let magic: u32 = if self.wide { 0xfeed_facf } else { 0xfeed_face };
        self.word(&mut out, magic);
        self.word(&mut out, if self.wide { 0x0100_000c } else { 0xc }); // cputype
        self.word(&mut out, 0); // cpusubtype
        self.word(&mut out, 2); // MH_EXECUTE
        self.word(&mut out, command_count as u32);
        self.word(&mut out, commands_len as u32);
        self.word(&mut out, 0); // flags
        if self.wide {
            self.word(&mut out, 0); // reserved
        }

        for (index, section) in self.sections.iter().enumerate() {
            let offset = if section.zero_fill {
                0
            } else if let Some(offset) = section.claimed_offset {
                offset
            } else if let Some(back) = section.overlap_previous {
                (offsets[index] as u32).saturating_sub(back)
            } else {
                offsets[index] as u32
            };
            let size = match (section.claimed_size, section.overlap_previous) {
                (Some(size), _) => size,
                (None, Some(back)) => u64::from(back),
                (None, None) => section.data.len() as u64,
            };
            self.word(&mut out, if self.wide { 0x19 } else { 0x1 });
            self.word(&mut out, segment_len as u32);
            Self::name16(&mut out, &section.segment);
            self.native(&mut out, 0); // vmaddr
            self.native(&mut out, size); // vmsize
            self.native(&mut out, u64::from(offset)); // fileoff
            self.native(&mut out, section.data.len() as u64); // filesize
            self.word(&mut out, 7); // maxprot
            self.word(&mut out, 5); // initprot
            self.word(&mut out, 1); // nsects
            self.word(&mut out, 0); // flags
            Self::name16(&mut out, &section.name);
            Self::name16(&mut out, &section.segment);
            self.native(&mut out, 0); // addr
            self.native(&mut out, size);
            self.word(&mut out, offset);
            self.word(&mut out, 0); // align
            self.word(&mut out, 0); // reloff
            self.word(&mut out, 0); // nreloc
            self.word(&mut out, section.flags);
            self.word(&mut out, 0); // reserved1
            self.word(&mut out, 0); // reserved2
            if self.wide {
                self.word(&mut out, 0); // reserved3
            }
        }
        for name in &self.libraries {
            let len = self.library_command_len(name);
            let start = out.len();
            self.word(&mut out, 0xc); // LC_LOAD_DYLIB
            self.word(&mut out, len as u32);
            self.word(&mut out, 24); // name offset
            self.word(&mut out, 0); // timestamp
            self.word(&mut out, 0x1_0000); // current version
            self.word(&mut out, 0x1_0000); // compatibility version
            out.extend(name.as_bytes());
            out.resize(start + len, 0);
        }
        if let Some((segment, name)) = &self.encrypt_from {
            let from = self
                .sections
                .iter()
                .position(|section| section.segment == *segment && section.name == *name)
                .map_or(data_end, |index| offsets[index]);
            self.word(&mut out, if self.wide { 0x2c } else { 0x21 });
            self.word(&mut out, encryption_len as u32);
            self.word(&mut out, from as u32);
            self.word(&mut out, (data_end - from) as u32);
            self.word(&mut out, self.crypt_id);
            if self.wide {
                self.word(&mut out, 0); // pad
            }
        }
        if let Some(signature) = &self.signature {
            self.word(&mut out, 0x1d); // LC_CODE_SIGNATURE
            self.word(&mut out, 16);
            self.word(&mut out, data_end as u32);
            self.word(&mut out, signature.len() as u32);
        }
        debug_assert_eq!(out.len(), header_len + commands_len);

        for section in &self.sections {
            out.extend(&section.data);
        }
        if let Some(signature) = &self.signature {
            out.extend(signature);
        }
        out.extend(&self.trailer);
        out
    }
}

/// A universal file that holds `images`, each at the next offset that is a
/// multiple of 64 bytes. `wide` selects the 64-bit form of the list.
#[must_use]
pub fn fat(images: &[&[u8]], wide: bool) -> Vec<u8> {
    let each = if wide { 32 } else { 20 };
    let mut out = Vec::new();
    out.extend(if wide { [0xca, 0xfe, 0xba, 0xbf] } else { [0xca, 0xfe, 0xba, 0xbe] });
    out.extend((images.len() as u32).to_be_bytes());
    let mut cursor = 8 + images.len() * each;
    let mut offsets = Vec::with_capacity(images.len());
    for image in images {
        cursor = cursor.div_ceil(64) * 64;
        offsets.push(cursor);
        out.extend(0x0100_000cu32.to_be_bytes()); // cputype
        out.extend(0u32.to_be_bytes()); // cpusubtype
        if wide {
            out.extend((cursor as u64).to_be_bytes());
            out.extend((image.len() as u64).to_be_bytes());
            out.extend(6u32.to_be_bytes()); // align
            out.extend(0u32.to_be_bytes()); // reserved
        } else {
            out.extend((cursor as u32).to_be_bytes());
            out.extend((image.len() as u32).to_be_bytes());
            out.extend(6u32.to_be_bytes()); // align
        }
        cursor += image.len();
    }
    for (image, offset) in images.iter().zip(offsets) {
        out.resize(offset, 0);
        out.extend(*image);
    }
    out
}

/// An embedded code signature whose code directory names `identifier` and,
/// if given, `team_id`. It holds no hashes and signs nothing.
#[must_use]
pub fn signature(identifier: &str, team_id: Option<&str>) -> Vec<u8> {
    // The fixed part of a version 0x20400 code directory is 88 bytes long.
    const FIXED: u32 = 88;
    let ident_offset = FIXED;
    let team_offset = ident_offset + identifier.len() as u32 + 1;
    let hash_offset = team_offset + team_id.map_or(0, |team| team.len() as u32 + 1);

    let mut directory = Vec::new();
    let put = |out: &mut Vec<u8>, value: u32| out.extend(value.to_be_bytes());
    put(&mut directory, 0xfade_0c02); // magic
    put(&mut directory, hash_offset); // length
    put(&mut directory, 0x2_0400); // version
    put(&mut directory, if team_id.is_some() { 0x1_0000 } else { 0x2 }); // runtime, or adhoc
    put(&mut directory, hash_offset);
    put(&mut directory, ident_offset);
    put(&mut directory, 0); // nSpecialSlots
    put(&mut directory, 0); // nCodeSlots
    put(&mut directory, 0); // codeLimit
    directory.extend([32, 2, 0, 12]); // hashSize, hashType, platform, pageSize
    put(&mut directory, 0); // spare2
    put(&mut directory, 0); // scatterOffset
    put(&mut directory, if team_id.is_some() { team_offset } else { 0 });
    put(&mut directory, 0); // spare3
    directory.extend(0u64.to_be_bytes()); // codeLimit64
    directory.extend(0u64.to_be_bytes()); // execSegBase
    directory.extend(0u64.to_be_bytes()); // execSegLimit
    directory.extend(0u64.to_be_bytes()); // execSegFlags
    debug_assert_eq!(directory.len() as u32, FIXED);
    directory.extend(identifier.as_bytes());
    directory.push(0);
    if let Some(team) = team_id {
        directory.extend(team.as_bytes());
        directory.push(0);
    }

    // A super blob with one entry: the code directory, in slot zero.
    let mut blob = Vec::new();
    put(&mut blob, 0xfade_0cc0);
    put(&mut blob, 20 + directory.len() as u32);
    put(&mut blob, 1);
    put(&mut blob, 0); // slot: code directory
    put(&mut blob, 20); // its offset
    blob.extend(directory);
    blob
}
