use crate::fatx::{self, Directory, Entry, Partition};
use byteorder::{BigEndian, ByteOrder};
use indicatif::ProgressBar;

pub fn find_deleted_files(
    data: &[u8],
    start_offset: u64,
    end_offset: u64,
    known_files: &[Entry],
    partition: &Partition,
) -> Vec<Entry> {
    let bar = ProgressBar::new(end_offset - start_offset);
    let mut entries = vec![];

    let mut current_offset = start_offset as usize;
    let magics = vec![
        u32::from_be_bytes(*b"XEX2"),
        u32::from_be_bytes(*b"CON "),
        u32::from_be_bytes(*b"LIVE"),
        u32::from_be_bytes(*b"PIRS"),
    ];

    while (current_offset as u64) < end_offset {
        // Check for a deleted entry
        let filename_len = data[current_offset];
        let attr = data[current_offset + 1];

        if filename_len == fatx::DELETED_FILE_FLAG {
            match fatx::EntryAttributes::from_bits(attr) {
                Some(fatx::EntryAttributes::NONE) | Some(fatx::EntryAttributes::DIRECTORY) => {
                    let new_entry = Entry::parse(
                        partition,
                        &data[current_offset..current_offset + 0x40],
                        current_offset as u64,
                    )
                    .expect("failed to parse entry");

                    if let Some(new_entry) = new_entry {
                        bar.println(format!(
                            "Maybe found hidden file found at 0x{:X}",
                            current_offset
                        ));
                        bar.println(format!("{:?}", new_entry));
                        entries.push(new_entry);
                    }
                }
                _ => {}
            }
        }

        // Check for an XEX2 header
        let magic = BigEndian::read_u32(&data[current_offset..current_offset + 0x4]);
        for m in &magics {
            if magic == *m {
                let mut is_known = false;
                for entry in known_files {
                    if entry.offset() == current_offset as u64 {
                        is_known = true;
                        break;
                    }
                }

                if !is_known {
                    bar.println(format!(
                        "Found {} magic at 0x{:X}",
                        String::from_utf8_lossy(&magic.to_be_bytes()),
                        current_offset
                    ));
                }
            }
        }

        current_offset += 0x10;
        bar.inc(0x10);
    }

    bar.finish();

    entries
}
