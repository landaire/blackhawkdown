#![feature(thread_spawn_unchecked)]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate log;

use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use memmap::MmapOptions;
use std::cmp;
use std::fs::{self, File};
use std::io::{self, Cursor, Seek, SeekFrom, Write};
use std::path::Path;
use std::path::PathBuf;
use structopt::StructOpt;

mod errors;
mod fatx;
mod scanners;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(parse(from_os_str))]
    input: PathBuf,

    #[structopt(parse(from_os_str))]
    output: PathBuf,
}

fn main() -> Result<(), io::Error> {
    env_logger::init();

    let opt = Opt::from_args();

    let input_file = File::open(opt.input)?;
    let mmap = unsafe { MmapOptions::new().map(&input_file)? };

    let devkit_info = fatx::devkit_partitions(&mmap).unwrap();
    println!("{:#X?}", devkit_info);

    for partition in devkit_info.partitions() {
        let dir = partition.root_dir()?;
        let path = Path::new(partition.name());
        print_dir(&dir, &path, partition, &opt.output);
    }

    for partition in devkit_info.partitions() {
        let all_entries: Vec<fatx::Entry> = partition
            .root_dir()?
            .entries()
            .iter()
            .flat_map(|entry| {
                if entry.is_dir() {
                    let dir = &fatx::Directory::parse(entry, partition, entry.name().to_owned())
                        .expect("could not parse directory");
                    dir.entries().to_vec()
                } else {
                    vec![entry.clone()]
                }
            })
            .collect();

        let end_offset = cmp::min(partition.offset() as usize + partition.len(), mmap.len());

        let deleted_files = scanners::find_deleted_files(
            &mmap,
            partition.offset(),
            end_offset as u64,
            &all_entries,
            partition,
        );

        println!("Done scanning for deleted files");

        let mut video_files = 0;
        let mut stfs_files = 0;

        for file in &deleted_files {
            let path = opt.output.join(Path::new(partition.name()));
            let deleted_files_path = opt.output.join("deleted_files");
            if !deleted_files_path.exists() {
                fs::create_dir(&deleted_files_path);
            }

            match file {
                scanners::DeletedFileType::FatxEntry(entry) => {
                    if entry.is_dir() {
                        let dir =
                            &fatx::Directory::parse(entry, partition, entry.name().to_owned())
                                .expect("could not parse directory");

                        print_dir(&dir, &path, partition, &deleted_files_path);
                    } else {
                        entry.write_to_file(&opt.output.join(entry.name()), partition);
                    }
                }
                scanners::DeletedFileType::STFS(offset) => {
                    // get the file name
                    let mut chars: Vec<u16> = vec![];
                    let mut cursor = Cursor::new(&mmap);
                    cursor.seek(SeekFrom::Start(*offset + 0x411))?;

                    for _i in (0..0x411).step_by(2) {
                        let c = cursor.read_u16::<BigEndian>()?;
                        if c == 0x0 {
                            break;
                        }

                        chars.push(c);
                    }

                    let display_name = String::from_utf16(chars.as_slice());
                    if display_name.is_err() {
                        continue;
                    }

                    let display_name = display_name.unwrap();
                    println!(
                        "Got STFS package at offset 0x{:X} with name: {}",
                        offset, display_name
                    );

                    cursor.seek(SeekFrom::Start(*offset + 0x34c))?;
                    let content_size = cursor.read_u64::<BigEndian>()?;

                    cursor.seek(SeekFrom::Start(*offset + 0x37e))?;
                    // just read from here and see if we hit some non-null data
                    loop {
                        let data = cursor.read_u32::<BigEndian>()?;
                        if data != 0 {
                            break;
                        }
                    }

                    let content_start_offset = cursor.position() - 0x4;

                    if content_start_offset + content_size > mmap.len() as u64 {
                        println!(
                            "File has invalid length of 0x{:X} (start offset = 0x{:X})",
                            content_size,
                            content_start_offset - offset
                        );
                        continue;
                    }

                    let file_path = if display_name.is_empty() {
                        stfs_files += 1;
                        deleted_files_path.join(format!("unnamed_stfs_package_{}", stfs_files))
                    } else {
                        deleted_files_path.join(&display_name)
                    };

                    println!("Writing STFS file to {}", file_path.display());

                    write_file_with_raw_bytes(
                        &file_path,
                        &mmap[*offset as usize..(content_start_offset + content_size) as usize],
                    )?;
                }
                scanners::DeletedFileType::XEX(offset) => {}
                scanners::DeletedFileType::Bink(offset) => {
                    println!("Got a bink file at offset 0x{:X}", offset);
                    // get the file size
                    let file_size =
                        LittleEndian::read_u32(&mmap[*offset as usize..*offset as usize + 0x4])
                            as usize;

                    println!("File size is 0x{:X}", file_size);

                    write_file_with_raw_bytes(
                        &deleted_files_path.join(format!("video_file_{}.bik", video_files)),
                        &mmap[*offset as usize..*offset as usize + file_size + 0x8],
                    )?;
                    video_files += 1;
                }
            }
        }
    }

    Ok(())
}

fn write_file_with_raw_bytes(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    let mut file = File::create(path)?;
    file.write(bytes)?;

    Ok(())
}

fn print_dir(
    dir: &fatx::Directory,
    parent_path: &Path,
    partition: &fatx::Partition,
    output_dir: &Path,
) {
    println!("Printing dir: {}", dir.name());
    let this_dir_path = if dir.name() == "/" {
        parent_path.join("")
    } else {
        parent_path.join(dir.name())
    };

    let child_output_path = output_dir.join(&this_dir_path);

    for entry in dir.entries() {
        if entry.is_dir() {
            // ignore errors here
            fs::create_dir(&child_output_path);

            print_dir(
                &fatx::Directory::parse(entry, partition, entry.name().to_owned())
                    .expect("could not parse directory"),
                &this_dir_path,
                partition,
                output_dir,
            );
        } else {
            println!("{}", this_dir_path.join(entry.name()).display());
            entry
                .write_to_file(&child_output_path.join(entry.name()), partition)
                .expect("could not write output file");
        }
    }
}
