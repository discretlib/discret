use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]

///
/// Global configuration for the discret lib
///
/// Default configuration is defined to try to limit the RAM memory usage to about 1 Gb at worst
///
pub struct Configuration {
    ///
    /// default: 8
    /// number of room that can be synchronised in parallel
    /// this comes at the cost of a potentially larger memory usage
    ///
    pub parallel_room_synch: usize,

    /// Default:256
    ///
    /// maximum number of items that will be requested to a peer
    ///
    /// This has a direct impact on memory usage
    ///
    pub synchronisation_batch_size: usize,

    ///
    /// Default  256
    ///
    /// nodes size should be kept small enought to ensure fast synchronisation
    ///
    pub max_node_size_in_kp: usize,

    ///
    /// Default 4096
    /// set the maximum cache size for the reading threads. increasing it can improve performances
    /// each read threads defined in read_parallelism consume up to that amount
    ///
    /// Real max memory usage is read_cache_size_in_kb *read_parallelism
    /// default memory usage is 16 Mb.
    pub read_cache_size_in_kb: usize,

    ///
    /// default: 4
    /// set the number of threads used by the signature verification service
    /// Signature verification consumes a lot of CPU and is moved to its own threads to avoid blocking Tokio Threads
    ///
    pub signature_verification_parallelism: usize,

    ///
    /// Default: 4
    ///
    /// set the number of parallel read thread for the database
    /// set the maximum of cache size for the writing thread.
    /// increasing it may improve performances
    ///
    pub read_parallelism: usize,

    ///
    /// Default 2048
    /// set the maximum of cache size for the writing thread. increasing it may improvee performances
    ///
    pub write_cache_size_in_kb: usize,

    ///
    /// Default: 1024
    ///
    /// Write queries are buffered while the database thread is working.
    /// When the database thread is ready, the buffer is sent and is processed in one single transaction
    /// This greatly increase insertion and update rate, compared to autocommit.
    ///      To get an idea of the perforance difference,
    ///      a very simple benchmak on a laptop with 100 000 insertions gives:
    ///      Buffer size: 1      Insert/seconds: 55  <- this is equivalent to autocommit
    ///      Buffer size: 10     Insert/seconds: 500
    ///      Buffer size: 100    Insert/seconds: 3000
    ///      Buffer size: 1000   Insert/seconds: 32000
    ///
    /// If one a buffered query fails, the transaction will be rolled back and every other queries in the buffer will fail too.
    /// This should not be an issue as INSERT query are not expected to fail.
    /// The only reasons to fail an insertion are a bugs or a system failure (like no more space available on disk),
    /// And in both case, it is ok to fail the last insertions batch.
    ///
    pub write_buffer_size: usize,

    ///
    /// Default: false (disabled)
    ///
    /// Enable_memory_security: Prevents memory to be written into swap and zeroise memory after free
    ///  Can be disabled because of a huge performance impact (about 50%),
    ///  When this feature is disabled, locking/unlocking of the memory address only occur for the internal SQLCipher
    ///  data structures used to store key material, and cryptographic structures.
    ///  source: https://discuss.zetetic.net/t/what-is-the-purpose-of-pragma-cipher-memory-security/3953
    ///
    pub enable_database_memory_security: bool,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            parallel_room_synch: 8,
            synchronisation_batch_size: 256,
            max_node_size_in_kp: 256,
            read_cache_size_in_kb: 4096,
            signature_verification_parallelism: 4,
            read_parallelism: 4,
            write_cache_size_in_kb: 2048,
            write_buffer_size: 1024,
            enable_database_memory_security: false,
        }
    }
}
