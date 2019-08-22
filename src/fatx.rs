use crate::errors::DiskError;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use std::path::Path;
use std::rc::Rc;

const ENTRY_SIZE: usize = 0x40;
const SECTOR_SIZE: usize = 0x200;
pub const DELETED_FILE_FLAG: u8 = 0xE5;
const MAX_FILENAME_LEN: usize = 0x2A;
const FAT_TABLE_OFFSET: usize = 0x1000;

#[derive(Debug)]
pub struct DevkitHddInfo<'a> {
    major: u16,
    minor: u16,
    revision: u16,
    patch: u16,
    partitions: [Partition<'a>; 2],
}

impl<'a> DevkitHddInfo<'a> {
    pub fn partitions(&self) -> &[Partition] {
        &self.partitions
    }
}

bitflags! {
    pub struct EntryAttributes: u8 {
        const NONE = 0x0;
        const READONLY = 0x1;
        const HIDDEN = 0x2;
        const SYSTEM = 0x4;
        const DIRECTORY = 0x10;
        const ARCHIVE = 0x20;
        const DEVICE = 0x40;
        const NORMAL = 0x80;
    }
}

#[derive(Debug)]
enum EntrySize {
    Fat16,
    Fat32,
}

struct DataRef<'a>(&'a [u8]);
impl<'a> Deref for DataRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl fmt::Debug for DataRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[...]")
    }
}

#[derive(Debug)]
pub struct Partition<'a> {
    offset: u64,
    len: usize,
    name: &'static str,
    data: DataRef<'a>,
    sectors_per_cluster: usize,
    root_dir_cluster: usize,
    entry_size: EntrySize,
    data_offset: u64,
}

impl<'a> Partition<'a> {
    pub fn new(
        data: &'a [u8],
        offset: u64,
        len: usize,
        name: &'static str,
    ) -> Result<Partition<'a>, DiskError> {
        debug!(
            "Reading partition at offset 0x{:X} with length: 0x{:X}",
            offset, len
        );

        if data.len() < offset as usize {
            return Err(DiskError::InvalidDiskLength {
                expected: offset as usize,
                actual: data.len(),
            });
        }

        if data.len() < offset as usize + len {
            return Err(DiskError::InvalidDiskLength {
                expected: offset as usize + len,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        cursor.seek(SeekFrom::Start(offset))?;
        let magic = cursor.read_u32::<BigEndian>()?;
        if magic != u32::from_be_bytes(*b"XTAF") {
            let offset = cursor.position();
            return Err(DiskError::InvalidFilesystemMagic { magic, offset });
        }

        cursor.seek(SeekFrom::Start(offset + 0x8))?;
        let sectors_per_cluster = cursor.read_u32::<BigEndian>()?;
        debug!("sectors per cluster: 0x{:X}", sectors_per_cluster);

        let root_dir_cluster = cursor.read_u32::<BigEndian>()?;

        debug!("Cluster size: 0x{:X}", sectors_per_cluster << 9);
        debug!(
            "leading zeros: {}",
            (sectors_per_cluster << 9).leading_zeros()
        );
        let shift_factor = 0x1F - (sectors_per_cluster << 9).leading_zeros();
        let mut allocation_table_size = (len >> shift_factor) + 1;

        let entry_shift = if allocation_table_size < 0xfff0 { 1 } else { 2 };

        allocation_table_size <<= entry_shift;
        allocation_table_size += 0x1000 - 1;
        allocation_table_size &= !0xFFF;
        allocation_table_size &= 0xFFFFFFFF;

        debug!("allocation table size: 0x{:X}", allocation_table_size);

        Ok(Partition {
            offset,
            len,
            name,
            data: DataRef(data),
            sectors_per_cluster: sectors_per_cluster as usize,
            root_dir_cluster: root_dir_cluster as usize,
            entry_size: if entry_shift == 1 {
                EntrySize::Fat16
            } else {
                EntrySize::Fat32
            },
            data_offset: offset + 0x1000 + allocation_table_size as u64,
        })
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn sectors_per_cluster(&self) -> usize {
        self.sectors_per_cluster
    }

    pub fn cluster_size(&self) -> usize {
        self.sectors_per_cluster() * SECTOR_SIZE
    }

    pub fn root_cluster(&self) -> usize {
        self.root_dir_cluster
    }

    pub fn root_dir(&self) -> Result<Directory, io::Error> {
        debug!(
            "Getting root directory for partition at 0x{:X}",
            self.offset
        );

        let root_entry = Entry::new_root(&self)?;

        Directory::parse(&root_entry, &self, "/".to_owned())
    }

    pub fn data_start(&self) -> u64 {
        self.data_offset
    }

    pub fn data(&self) -> &[u8] {
        self.data.0
    }

    pub fn block_chain_from_root(&self, root: usize) -> Result<Vec<usize>, io::Error> {
        debug!("Reading block chain from index 0x{:X}", root);

        let mut cursor = Cursor::new(self.data());
        let table_start = self.offset + 0x1000;

        let final_block = match self.entry_size {
            EntrySize::Fat16 => 0xffff,
            EntrySize::Fat32 => 0xffffffff,
        };

        let mut chain = vec![];

        let mut next = root;
        while next != final_block {
            debug!("next = 0x{:X}", next);
            chain.push(next);

            cursor.seek(SeekFrom::Start(
                table_start
                    + (next as u64
                        * match self.entry_size {
                            EntrySize::Fat16 => 2,
                            EntrySize::Fat32 => 4,
                        }),
            ))?;

            match self.entry_size {
                EntrySize::Fat16 => {
                    next = cursor.read_u16::<BigEndian>()? as usize;
                }
                EntrySize::Fat32 => {
                    next = cursor.read_u32::<BigEndian>()? as usize;
                }
            }
        }

        Ok(chain)
    }

    pub fn block_offset(&self, block: usize) -> u64 {
        self.data_offset + ((block - 1) * self.cluster_size()) as u64
    }

    pub fn block_data(&self, block: usize) -> &[u8] {
        let block_offset = self.block_offset(block) as usize;
        &self.data()[block_offset..block_offset + self.cluster_size()]
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

pub struct Directory {
    name: String,
    entries: Vec<Entry>,
}

impl Directory {
    pub fn parse(
        entry: &Entry,
        partition: &Partition,
        name: String,
    ) -> Result<Directory, io::Error> {
        let entries: Vec<Entry> = entry
            .block_chain
            .iter()
            .flat_map(|block| Self::read_block(partition, *block).expect("failed to read block"))
            .collect();

        Ok(Directory {
            name: name,
            entries,
        })
    }

    pub fn read_block(partition: &Partition, block: usize) -> Result<Vec<Entry>, io::Error> {
        let mut entry_data: [u8; 0x40] = [0u8; 0x40];
        let block_size = partition.cluster_size();
        let block_offset = partition.block_offset(block);

        let mut cursor = Cursor::new(partition.data());

        cursor.seek(SeekFrom::Start(block_offset))?;

        let mut entries = vec![];

        while cursor.position() < block_offset + block_size as u64 {
            let offset = cursor.position();
            debug!("Reading entry at 0x{:X}", offset);
            cursor.read(&mut entry_data)?;

            let entry = Entry::parse(partition, &entry_data, offset)?;
            debug!("Entry: {:?}", entry);
            match entry {
                Some(e) => entries.push(e),
                None => break,
            }
        }

        Ok(entries)
    }

    pub fn entries(&self) -> &[Entry] {
        self.entries.as_slice()
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    offset: u64,
    is_deleted: bool,
    name: String,
    size: usize,
    block: usize,
    attr: EntryAttributes,
    block_chain: Vec<usize>,
}

impl Entry {
    pub fn new_root(partition: &Partition) -> Result<Self, io::Error> {
        Ok(Entry {
            offset: partition.data_start(),
            is_deleted: false,
            name: "".to_owned(),
            block: partition.root_cluster(),
            attr: EntryAttributes::DIRECTORY,
            block_chain: partition.block_chain_from_root(partition.root_cluster())?,
            size: 0,
        })
    }

    pub fn parse(
        partition: &Partition,
        data: &[u8],
        offset: u64,
    ) -> Result<Option<Self>, io::Error> {
        let mut cursor = Cursor::new(data);

        // Figure out the name length
        let mut name_len = cursor.read_u8()?;
        // 0xFF or 0x00 are invalid
        if name_len == 0xFF || name_len == 0x0 {
            return Ok(None);
        }
        let is_deleted = name_len == DELETED_FILE_FLAG;
        // Read attributes
        let attributes = cursor.read_u8()?;

        // Read the maximum number of bytes in a filename
        let mut name_bytes: [u8; MAX_FILENAME_LEN] = [0u8; MAX_FILENAME_LEN];
        cursor.read(&mut name_bytes)?;

        // If the file is deleted we need to figure out the number of bytes that were actually in this filename
        if is_deleted {
            // figure out the file name len
            for i in 0..MAX_FILENAME_LEN {
                name_len = i as u8;

                match name_bytes[i] {
                    0xFF | 0x00 => break,
                    _ => continue,
                }
            }
        }

        for b in &name_bytes[0..name_len as usize] {
            if !char::from(*b).is_ascii() {
                return Ok(None);
            }
        }

        // Convert the name to a string
        let name = String::from_utf8_lossy(&name_bytes[0..name_len as usize]);

        // Read the start bloc
        let block = cursor.read_u32::<BigEndian>()? as usize;
        // Read the file size
        let file_size = cursor.read_u32::<BigEndian>()? as usize;

        // From here we ignore the rest of the data

        // Read the block chain
        let block_chain = if is_deleted {
            partition.block_chain_from_root(block)?
        } else {
            let mut num_blocks = file_size / partition.cluster_size();
            if file_size % partition.cluster_size() > 0 {
                num_blocks += 1;
            }

            (block..=block + num_blocks).collect()
        };

        let parsed_entry = Entry {
            offset,
            is_deleted: name_len == DELETED_FILE_FLAG,
            name: name.to_string(),
            size: file_size,
            block,
            attr: EntryAttributes::from_bits(attributes).unwrap_or(EntryAttributes::NONE),
            block_chain,
        };

        Ok(Some(parsed_entry))
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_dir(&self) -> bool {
        (self.attr & EntryAttributes::DIRECTORY) != EntryAttributes::NONE
    }

    pub fn write_to_file(&self, path: &Path, partition: &Partition) -> Result<(), io::Error> {
        if !path.parent().unwrap().exists() {
            fs::create_dir(path.parent().unwrap())?;
        }

        let mut file = File::create(path)?;

        let all_data: Vec<u8> = self
            .block_chain
            .iter()
            .flat_map(|block| partition.block_data(*block).to_vec())
            .take(self.size)
            .collect();

        file.write(&all_data)?;

        Ok(())
    }
}

pub fn devkit_partitions<'a>(data: &'a [u8]) -> Result<DevkitHddInfo<'a>, DiskError> {
    const MIN_DISK_LENGTH: usize = 0x18;

    if data.len() < MIN_DISK_LENGTH {
        return Err(DiskError::InvalidDiskLength {
            expected: MIN_DISK_LENGTH,
            actual: data.len(),
        });
    }

    let mut cursor = Cursor::new(data);

    let info = DevkitHddInfo {
        major: cursor.read_u16::<BigEndian>()?,
        minor: cursor.read_u16::<BigEndian>()?,
        revision: cursor.read_u16::<BigEndian>()?,
        patch: cursor.read_u16::<BigEndian>()?,
        partitions: [
            Partition::new(
                data,
                cursor.read_u32::<BigEndian>()? as u64 * SECTOR_SIZE as u64,
                cursor.read_u32::<BigEndian>()? as usize * SECTOR_SIZE,
                "Data",
            )?,
            Partition::new(
                data,
                cursor.read_u32::<BigEndian>()? as u64 * SECTOR_SIZE as u64,
                cursor.read_u32::<BigEndian>()? as usize * SECTOR_SIZE,
                "System",
            )?,
        ],
    };

    Ok(info)
}
