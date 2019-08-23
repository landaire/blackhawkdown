use crate::fatx::{self, Directory, Entry, Partition};
use byteorder::{BigEndian, ByteOrder};
use indicatif::ProgressBar;
use std::sync::{Arc, RwLock};
use std::thread;

#[derive(Debug, Clone)]
pub enum DeletedFileType {
    XEX(u64),
    STFS(u64),
    FatxEntry(Entry),
    Bink(u64),
}

pub fn find_deleted_files(
    data: &[u8],
    start_offset: u64,
    end_offset: u64,
    known_files: &[Entry],
    partition: &Partition,
) -> Vec<DeletedFileType> {
    // let bar = ProgressBar::new(end_offset - start_offset);
    let deleted_files = Arc::new(RwLock::new(vec![]));
    const NUM_THREADS: usize = 8;

    let mut join_handles = vec![];
    let slice_size = (end_offset - start_offset) / NUM_THREADS as u64;

    println!("Start offset that came in was: 0x{:X}", start_offset);
    for i in 0..NUM_THREADS {
        let builder = thread::Builder::new();

        let deleted_files = Arc::clone(&deleted_files);
        let join_handle = unsafe {
            builder
                .spawn_unchecked(move || {
                    let start_offset = start_offset + (slice_size * i as u64);
                    let start_offset = start_offset - (start_offset % 0x10);
                    let end_offset = start_offset + slice_size;

                    let mut current_offset = start_offset as usize;
                    let magics = vec![
                        u32::from_be_bytes(*b"XEX2"),
                        u32::from_be_bytes(*b"CON "),
                        u32::from_be_bytes(*b"LIVE"),
                        u32::from_be_bytes(*b"PIRS"),
                        u32::from_be_bytes(*b"BIKi"),
                    ];

                    while (current_offset as u64) < end_offset {
                        // Check for a deleted entry
                        let filename_len = data[current_offset];
                        let attr = data[current_offset + 1];

                        if filename_len == fatx::DELETED_FILE_FLAG {
                            match fatx::EntryAttributes::from_bits(attr) {
                                Some(fatx::EntryAttributes::NONE)
                                | Some(fatx::EntryAttributes::DIRECTORY) => {
                                    let data = &data[current_offset..current_offset + 0x40];
                                    let new_entry =
                                        Entry::parse(partition, data, current_offset as u64)
                                            .expect(&format!(
                                                "failed to parse entry at 0x{:X}",
                                                current_offset
                                            ));

                                    if let Some(new_entry) = new_entry {
                                        println!(
                                            "Maybe found hidden file found at 0x{:X}",
                                            current_offset
                                        );
                                        let mut deleted_files = deleted_files.write().unwrap();
                                        deleted_files.push(DeletedFileType::FatxEntry(new_entry));
                                    }
                                }
                                _ => {}
                            }
                        }

                        // Check for an XEX2 header
                        let magic =
                            BigEndian::read_u32(&data[current_offset..current_offset + 0x4]);
                        for m in &magics {
                            if magic == *m {
                                match data[current_offset + 0x5] {
                                    0x20 | 0x2e => break,
                                    _ => {}
                                }

                                let mut is_known = false;
                                for entry in known_files {
                                    if entry.offset() == current_offset as u64 {
                                        is_known = true;
                                        break;
                                    }
                                }

                                if !is_known {
                                    println!(
                                        "Found {} magic at 0x{:X}",
                                        String::from_utf8_lossy(&magic.to_be_bytes()),
                                        current_offset
                                    );

                                    let mut deleted_files = deleted_files.write().unwrap();
                                    if magic == u32::from_be_bytes(*b"XEX2") {
                                        deleted_files
                                            .push(DeletedFileType::XEX(current_offset as u64));
                                    } else if magic == u32::from_be_bytes(*b"BIKi") {
                                        deleted_files
                                            .push(DeletedFileType::Bink(current_offset as u64));
                                    } else {
                                        deleted_files
                                            .push(DeletedFileType::STFS(current_offset as u64));
                                    }
                                }
                            }
                        }

                        current_offset += 0x10;
                    }
                })
                .unwrap()
        };

        join_handles.push(join_handle);
    }

    for (i, thread) in join_handles.drain(..).enumerate() {
        println!("Waiting for thread {} to join", i);
        thread.join();
    }

    let entries = deleted_files.read().unwrap();
    entries.clone()
}
