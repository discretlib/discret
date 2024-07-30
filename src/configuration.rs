use serde::{Deserialize, Serialize};

///
/// Global configuration for the discret lib
///
/// Default configuration is defined to try to limit the RAM memory usage to about 1 Gb at worst
///
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Configuration {
    ///
    /// default: 4
    ///
    /// defines the global parellism capabilities.
    ///
    /// this number impact:
    ///- the maximum number of room that can be synchronized in parralel,
    ///- the number of database readings threads
    ///- the number of signature verification threads
    ///- the number of shared buffers used for reading and writing data on the network
    ///- the depth of the channels that are used to transmit message accross services
    ///
    /// larger numbers will provides better performances at the cost of more memory usage.
    /// having a number larger that the number of CPU might not provides increasing performances
    /// TODO: can be changed at runtime?, for example to accomodate for device status changes (for example: on metered network or wifi, on battery or recharging )
    ///
    pub parallelism: usize,

    ///
    /// default: true,  (enabled)
    ///
    /// When connecting with the same key_material on different devices,
    /// thoses devices exchanges their hardaware fingerprint to check wether they are allowed to connect.
    /// This add an extra layer of security in the unlucky case where your secret material is shared by another person on the internet
    /// (which could be relatively frequent as users tends use weak passwords.)
    ///
    /// When connecting over the internet, new harware is allways silently rejected.
    ///
    /// However, on local network we trust new hardware by default. This behaviors can be disabled by setting 'auto_accept_local_device' to false.
    /// In this case, when a new device is detected on the local network:
    /// - a sys.AllowedHardware will be created with the status:'pending'
    /// - a PendingHardware Event will be triggered
    /// - the current coonection attempt will be rejected
    ///
    /// It is up to the developer to intercept the event and decides what to do by updating the status to 'enabled' or 'disabled'
    pub auto_accept_local_device: bool,

    ///
    /// default: false, (disabled)
    /// Defines the behavior of the system when it discover a new peer while synchronizing a room.
    ///
    /// auto_allow_new_peers=true:
    /// - I implicitely trust friends of my friends. It is easy to setup, but could cause problems.
    ///
    /// auto_allow_new_peers=false:
    /// - Trust is given on a case by case basis, this is the recommended configuration.
    ///
    /// Let's imagine that you have manually invited Bob to chat with you. Bob want's you to meet Alice and creates a group chat with both of you.
    /// During the synchronisation, you device detects a new peer(Alice), and add it to the sys.Peer list.
    ///
    /// If auto_allow_new_peers is set to 'true', you're device will allow Alice to directly connect with you.
    /// It makes the network stronger, as Alice will be able to see your message even if Bob is not connected.
    /// But it comes at the cost of some privacy, because you now share your IP adress with Alice.
    /// In case of large communities, this setup will make your allowed peers very large, increasing the number of network connections, and increase ressources usage.
    ///
    /// If auto_allow_new_peers is set to 'true',
    /// - a sys.AllowedPeer object is created in the private room, with the status set to 'pending'
    /// - a PendingPeer event is triggered
    ///
    /// It is up to the developer to intercept the event and decides what to do by updating the status to 'enabled' or 'disabled'
    ///
    ///
    pub auto_allow_new_peers: bool,

    ///
    /// Default 256kb
    ///
    /// **!!WARNING!!** once your program is in production, decreasing this value will break the system.
    /// No data will be lost but the system will not be able to synchronized objects that are larger than the reduced value.
    /// //TODO: put it in the sys.Configuration and sanity check on startup
    ///
    /// Define the maximum size of an entity object.
    /// Object size should be kept relatively small to ensure efficient synchronisation.
    ///
    /// This parameter has a direct impact on the size of the buffers used to read and write data on the network
    /// Increasing this value will increase the RAM usage of the application
    ///
    ///
    pub max_object_size_in_kb: u64,

    ///
    /// Default 2048
    /// set the maximum cache size for the database reading threads. increasing it can improve performances
    /// Every read threads consumes up to that amount, meaning that increasing the "parallelism" configuration will increase the memory usage
    ///
    pub read_cache_size_in_kb: usize,

    ///
    /// Default 2048
    /// set the maximum of cache size for the database writing thread. increasing it may improvee performances
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
    /// This parameter can increase RAM usage.
    ///
    pub write_buffer_length: usize,

    ///
    /// default 60000ms (60 seconds)
    /// how often an annouces are sent over the network
    ///
    pub announce_frequency_in_ms: u64,

    ///
    /// enbable multicast discovery
    ///
    pub enable_multicast: bool,
    ///
    /// default: 0.0.0.0
    ///
    /// Discret uses the IP multicast feature to discover peers on local networks.
    /// on systems with multiple network interfaces, it might be necessary to provide the right ip adress for multicast to work properly
    /// the default (let the OS choose for you) should work on most cases.
    ///
    pub multicast_ipv4_interface: String,

    ///
    /// default: 224.0.0.224:22402
    /// the multicast group that is used to perform peer discovery
    ///
    pub multicast_ipv4_group: String,

    ///
    /// default: true
    /// enable beacon peer discovery
    ///
    pub enable_beacons: bool,

    ///
    /// list of Beacon servers that are used for peer discovery
    ///
    pub beacons: Vec<BeaconConfig>,

    ///
    /// Default: false (disabled)
    ///
    /// Enable_memory_security: Prevents memory to be written into swap and zeroise memory after free
    /// When this feature is disabled, locking/unlocking of the memory address only occur for the internal SQLCipher
    /// data structures used to store key material, and cryptographic structures.
    /// source: <https://discuss.zetetic.net/t/what-is-the-purpose-of-pragma-cipher-memory-security/3953>
    ///
    /// Disabled by default because of a huge performance impact (about 50%).
    /// Should only be used if you're system requires a "paranoid" level of security.
    ///
    pub enable_database_memory_security: bool,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            parallelism: 4,
            auto_accept_local_device: true,
            auto_allow_new_peers: false,
            max_object_size_in_kb: 256,
            read_cache_size_in_kb: 2048,
            write_cache_size_in_kb: 2048,
            write_buffer_length: 1024,
            announce_frequency_in_ms: 60000,
            enable_multicast: true,
            multicast_ipv4_interface: "0.0.0.0".to_string(),
            multicast_ipv4_group: "224.0.0.224:22402".to_string(),
            enable_beacons: true,
            beacons: Vec::new(),
            enable_database_memory_security: false,
        }
    }
}

///
/// A beacon server
///
/// Beacons servers are used to allow peer to discover others on the Internet
///
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BeaconConfig {
    /// the server hostname
    pub hostname: String,
    /// the hash of the Beacon config certificate
    pub cert_hash: String,
}
