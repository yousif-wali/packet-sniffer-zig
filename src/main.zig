const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
    @cInclude("netinet/in.h"); // For IP header parsing
    @cInclude("arpa/inet.h"); // For IP address conversion
    @cInclude("net/ethernet.h"); // For Ethernet header parsing
    @cInclude("sys/time.h"); // For timestamp handling
    @cInclude("time.h"); // For date and time formatting
});

// Define Ethernet header structure
const EthernetHeader = extern struct {
    dest_mac: [6]u8,
    src_mac: [6]u8,
    ether_type: u16,
};

// Define IPv4 header structure
const IPv4Header = extern struct {
    version_and_header_length: u8,
    tos: u8,
    length: u16,
    id: u16,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_ip: u32,
    dest_ip: u32,
};

pub fn main() !void {
    const interface = "en0"; // Adjust for your network interface
    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;

    // Open the network interface for packet capture
    const handle = c.pcap_open_live(interface, 65535, 1, 1000, &errbuf);
    if (handle == null) {
        std.debug.print("Error: {s}\n", .{errbuf});
        return;
    }

    std.debug.print("Starting packet capture on: {s}\n", .{interface});

    // Capture packets indefinitely until manually stopped
    _ = c.pcap_loop(handle, -1, packetHandler, null);
    c.pcap_close(handle);
}

/// Packet handler with date and time formatting and proper null-termination fix
fn packetHandler(args: [*c]u8, header: [*c]const c.pcap_pkthdr, packet: [*c]const u8) callconv(.C) void {
    _ = args; // Ignoring args for now

    // Extract timestamp from the packet header
    const timestamp_sec = header.*.ts.tv_sec;

    // Convert the timestamp to a struct tm using localtime
    const timeinfo: *c.tm = c.localtime(&timestamp_sec);

    // Prepare a buffer for the formatted date and time with null-termination
    var time_buffer: [64]u8 = undefined;

    // Properly terminate the buffer and check the length
    const length = c.strftime(&time_buffer, time_buffer.len, "%Y-%m-%d %H:%M:%S", timeinfo);
    if (length > 0 and length < time_buffer.len) {
        time_buffer[length] = 0;
    }

    std.debug.print("Timestamp: {s}\n", .{time_buffer[0..length]});

    const packet_length = header.*.len;
    std.debug.print("Packet captured with length: {}\n", .{packet_length});

    const eth_header: *const EthernetHeader = @ptrFromInt(@intFromPtr(packet));
    std.debug.print("Source MAC: {x:02}:{x:02}:{x:02}:{x:02}:{x:02}:{x:02}\n", .{ eth_header.src_mac[0], eth_header.src_mac[1], eth_header.src_mac[2], eth_header.src_mac[3], eth_header.src_mac[4], eth_header.src_mac[5] });
    std.debug.print("Destination MAC: {x:02}:{x:02}:{x:02}:{x:02}:{x:02}:{x:02}\n", .{ eth_header.dest_mac[0], eth_header.dest_mac[1], eth_header.dest_mac[2], eth_header.dest_mac[3], eth_header.dest_mac[4], eth_header.dest_mac[5] });

    if (std.mem.nativeToBig(u16, eth_header.ether_type) == 0x0800) {
        const ip_header_offset = @sizeOf(EthernetHeader);
        const ip_header: *const IPv4Header = @ptrFromInt(@intFromPtr(packet) + ip_header_offset);

        const src_ip_addr = c.in_addr{ .s_addr = ip_header.src_ip };
        const dest_ip_addr = c.in_addr{ .s_addr = ip_header.dest_ip };

        const src_ip_str = c.inet_ntoa(src_ip_addr);
        const dest_ip_str = c.inet_ntoa(dest_ip_addr);

        std.debug.print("Source IP: {s}\n", .{src_ip_str});
        std.debug.print("Destination IP: {s}\n", .{dest_ip_str});
        std.debug.print("Protocol: {}\n", .{ip_header.protocol});
    } else {
        std.debug.print("Non-IPv4 Packet captured\n", .{});
    }
    std.debug.print("\n", .{});
}
