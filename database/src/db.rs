use rocksdb::{BlockBasedOptions, DBWithThreadMode, MultiThreaded};
use std::{path::PathBuf, sync::Arc};

/// The DB type used for Kaspad stores
pub type DB = DBWithThreadMode<MultiThreaded>;

/// Creates or loads an existing DB from the provided directory path.
pub fn open_db(db_path: PathBuf, create_if_missing: bool, parallelism: usize) -> Arc<DB> {
    let mut opts = rocksdb::Options::default();
    if parallelism > 1 {
        opts.increase_parallelism(parallelism as i32);
    }

    let mut b_opts = BlockBasedOptions::default();
    b_opts.set_bloom_filter(2.0, true);
    opts.set_block_based_table_factory(&b_opts);

    opts.set_write_buffer_size(256 * 1024 * 1024);
    opts.set_max_write_buffer_number(3);
    opts.set_min_write_buffer_number(2);
    opts.set_min_write_buffer_number_to_merge(2);
    opts.set_max_bytes_for_level_base(1024 * 1024 * 1024);

    // In most linux environments the limit is set to 1024, so we use 500 to give sufficient slack.
    // TODO: fine-tune this parameter and additional parameters related to max file size
    opts.set_max_open_files(500);

    // metrics
    opts.enable_statistics();
    opts.set_report_bg_io_stats(true);
    opts.set_stats_dump_period_sec(dbg!(std::env::var("SDPS").unwrap_or("600".to_string()).parse().unwrap_or(600)));

    opts.create_if_missing(create_if_missing);
    let db = Arc::new(DB::open(&opts, db_path.to_str().unwrap()).unwrap());
    db
}

/// Deletes an existing DB if it exists
pub fn delete_db(db_dir: PathBuf) {
    if !db_dir.exists() {
        return;
    }
    let options = rocksdb::Options::default();
    let path = db_dir.to_str().unwrap();
    DB::destroy(&options, path).expect("DB is expected to be deletable");
}
