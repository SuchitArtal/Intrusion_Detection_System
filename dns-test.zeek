@load base/protocols/dns
@load base/frameworks/input

module DNSBeaconDetector;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        src: addr &log;
        domain: string &log;
        query_count_1min: count &log;
        query_count_5min: count &log;
        query_count_30min: count &log;
        interval_duration: interval &log;
        query_type: string &log;
    };

    # Structure to store information about queries
    type DomainInfo: record {
        query_count_1min: count;
        query_count_5min: count;
        query_count_30min: count;
        first_seen: time;
        last_seen: time;
    };

    global log_dns_beacon: event(rec: Info);
    global total_dns_queries: count &redef;

    # Set to store whitelisted domains
    global domain_whitelist: set[string] = set();

    # Table to track DNS queries for each (source IP, domain) pair
    global domain_stats: table[addr, string] of DomainInfo &create_expire=30mins;
}

# Define the record structure for the CSV fields
type WhitelistEntry: record {
    domain: string;
};

# Load the whitelist from the CSV file
event zeek_init() {
    Log::create_stream(DNSBeaconDetector::LOG, [$columns=Info, $path="dns_beacon"]);
    total_dns_queries = 0;

    # Load the CSV data directly into domain_whitelist using a set
    Input::add_table([
        $source="/home/suchitartal/Desktop/test3/whitelist.csv",  # Updated CSV path
        $name="whitelist_domains",
        $idx=WhitelistEntry,  # Define the record structure to parse the CSV
        $destination=domain_whitelist  # Load data directly into domain_whitelist set
    ]);

    # Suspend processing until the CSV is loaded
    suspend_processing();
}

# Resume processing after loading CSV data
event Input::end_of_data(name: string, source: string) {
    if (name == "whitelist_domains") {
        print "Whitelist populated with domains from CSV.";
        continue_processing();  # Resume processing after loading is complete
    }
}

# Convert DNS query types to human-readable strings
function query_type_to_str(qtype: count): string {
    switch (qtype) {
        case 1:   return "A";
        case 28:  return "AAAA";
        case 5:   return "CNAME";
        case 15:  return "MX";
        case 12:  return "PTR";
        case 2:   return "NS";
        case 6:   return "SOA";
        case 16:  return "TXT";
        case 33:  return "SRV";
        case 257: return "CAA";
        default:  return fmt("%d", qtype);
    }
}

# Check if a domain is in the whitelist and skip further processing if true
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    local src = c$id$orig_h;
    local domain = query;

    # Skip if the domain is in the whitelist
    if (domain in domain_whitelist) {
        return;
    }

    # Proceed with DNS beacon detection if the domain is not whitelisted
    ++total_dns_queries;

    if ([src, domain] !in domain_stats) {
        domain_stats[src, domain] = DomainInfo($query_count_1min=1, 
                                               $query_count_5min=1, 
                                               $query_count_30min=1, 
                                               $first_seen=network_time(), 
                                               $last_seen=network_time());
    } else {
        domain_stats[src, domain]$query_count_1min += 1;
        domain_stats[src, domain]$query_count_5min += 1;
        domain_stats[src, domain]$query_count_30min += 1;
        domain_stats[src, domain]$last_seen = network_time();
    }

    local query_type_str = query_type_to_str(qtype);
    local info: Info;
    local interval_duration: interval;

    # Fast beaconing detection (1-minute window)
    if (domain_stats[src, domain]$query_count_1min >= 50) {
        interval_duration = network_time() - domain_stats[src, domain]$first_seen;
        info = [$ts=network_time(), $src=src, $domain=domain, 
                $query_count_1min=domain_stats[src, domain]$query_count_1min, 
                $query_count_5min=domain_stats[src, domain]$query_count_5min, 
                $query_count_30min=domain_stats[src, domain]$query_count_30min, 
                $interval_duration=interval_duration, $query_type=query_type_str];
        Log::write(DNSBeaconDetector::LOG, info);
        print fmt("Fast beacon detected: %s queried %s %d times in 1 minute", src, domain, domain_stats[src, domain]$query_count_1min);
        domain_stats[src, domain]$query_count_1min = 0;
    }

    # Medium-speed beaconing detection (5-minute window)
    if (domain_stats[src, domain]$query_count_5min >= 150) {
        interval_duration = network_time() - domain_stats[src, domain]$first_seen;
        info = [$ts=network_time(), $src=src, $domain=domain, 
                $query_count_1min=domain_stats[src, domain]$query_count_1min, 
                $query_count_5min=domain_stats[src, domain]$query_count_5min, 
                $query_count_30min=domain_stats[src, domain]$query_count_30min, 
                $interval_duration=interval_duration, $query_type=query_type_str];
        Log::write(DNSBeaconDetector::LOG, info);
        print fmt("Medium-speed beacon detected: %s queried %s %d times in 5 minutes", src, domain, domain_stats[src, domain]$query_count_5min);
        domain_stats[src, domain]$query_count_5min = 0;
    }

    # Slow beaconing detection (30-minute window)
    if (domain_stats[src, domain]$query_count_30min >= 300) {
        interval_duration = network_time() - domain_stats[src, domain]$first_seen;
        info = [$ts=network_time(), $src=src, $domain=domain, 
                $query_count_1min=domain_stats[src, domain]$query_count_1min, 
                $query_count_5min=domain_stats[src, domain]$query_count_5min, 
                $query_count_30min=domain_stats[src, domain]$query_count_30min, 
                $interval_duration=interval_duration, $query_type=query_type_str];
        Log::write(DNSBeaconDetector::LOG, info);
        print fmt("Slow beacon detected: %s queried %s %d times in 30 minutes", src, domain, domain_stats[src, domain]$query_count_30min);
        domain_stats[src, domain]$query_count_30min = 0;
    }
}

event zeek_done() {
    print fmt("Total DNS queries observed: %d", total_dns_queries);
}
