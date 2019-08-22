#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate log;

use memmap::MmapOptions;
use std::fs::{self, File};
use std::io::Cursor;
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

fn main() -> Result<(), std::io::Error> {
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

        let deleted_entries = scanners::find_deleted_files(
            &mmap,
            partition.offset(),
            partition.offset() + partition.len() as u64,
            &all_entries,
            partition,
        );

        for entry in &deleted_entries {
            let path = Path::new(partition.name());

            if entry.is_dir() {
                let dir = &fatx::Directory::parse(entry, partition, entry.name().to_owned())
                    .expect("could not parse directory");

                print_dir(&dir, &path, partition, &opt.output);
            } else {
                entry.write_to_file(&opt.output.join(entry.name()), partition);
            }
        }
    }

    Ok(())
}

fn print_dir(
    dir: &fatx::Directory,
    parent_path: &Path,
    partition: &fatx::Partition,
    output_dir: &Path,
) {
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
