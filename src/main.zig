const std = @import("std");
const net = std.net;
const crypto = std.crypto;
const process = std.process;
const fs = std.fs;
const bufPrint = std.fmt.bufPrint;

const secret = "";
const absolute_path = "";

pub fn main() !void {
    // ALot of these are copy from official zig test file.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var map: std.StringHashMap([]const u8) = .init(allocator);
    defer map.deinit();
    const address = try net.Address.parseIp4("127.0.0.1", 3000);
    var server = try address.listen(.{});

    defer server.deinit();

    while (true) {
        const conn = try server.accept();
        {
            defer conn.stream.close();

            var reader_buf: [4096]u8 = undefined;
            var writer_buf: [4096]u8 = undefined;

            var reader = conn.stream.reader(&reader_buf);
            var writer = conn.stream.writer(&writer_buf);

            var server_http = std.http.Server.init(reader.interface(), &writer.interface);

            var req = try server_http.receiveHead();

            try put_header_to_map(req, &map);

            const x_hub_sig = map.get("X-Hub-Signature-256");
            var reader_req = try req.readerExpectContinue(&.{});
            const body = try reader_req.allocRemaining(allocator, .unlimited);
            defer allocator.free(body);

            const method = req.head.method;
            switch (method) {
                .POST => {
                    std.debug.print("Body: {s}\n", .{body});
                    if (x_hub_sig) |x| {
                        std.debug.print("X-Hub-Signature-256 {s}\n", .{x});
                        const is_valid = try verifySig(body, x);
                        if (is_valid)
                        {
                            // Check which webhook send, and go to directory and run a git pull

                        }
                    }

                },
                else => {},
            }
            std.debug.print("Body: {s}\n", .{body});
            try req.respond("", .{ .keep_alive = false });
        }
    }
}

pub fn put_header_to_map(req: std.http.Server.Request, map: *std.StringHashMap([]const u8)) !void {
    var it = req.iterateHeaders();
    while (true) {
        const header = it.next() orelse break;
        try map.put(header.name, header.value);
    }
}
pub fn verifySig(body: []const u8, sigHeader: []const u8) !bool {
    const H = crypto.hash.sha256;
    var hmac = try crypto.auth.hmac.Hmac.init(H, secret);
    defer hmac.deinit();
    try hmac.update(body);

    var digest: [H.digest_len]u8 = undefined;
    hmac.final(&digest);

    const hexDigest = try std.fmt.allocPrint(std.heap.page_allocator, "{s}", .{});
    defer std.heap.page_allocator.free(hexDigest);

    var buf: [H.digest_len * 2]u8 = undefined;
    var i: usize = 0;
    while (i < digest.len) : (i += 1) {
        const b = digest[i];
        buf[i * 2 + 0] = "0123456789abcdef"[(b >> 4) & 0xF];
        buf[i * 2 + 1] = "0123456789abcdef"[b & 0xF];
    }
    const expectedPrefix = "sha256=";
    if (sigHeader.len != expectedPrefix.len + buf.len) return false;
    if (!std.mem.startsWith(u8, sigHeader, expectedPrefix)) return false;

    return std.mem.eql(u8, sigHeader[expectedPrefix.len..], buf[0..]);
}
pub fn file_dir() !void {
    var dir = fs.cwd().openDir(absolute_path, .{ .iterate = true }) catch |err| switch (err) {
        error.NotDir => return,
        else => {
            std.debug.print("Error opening dir: {}\n", .{err});
            return;
        },
    };
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind == .directory and entry.name[0] != '.') {
            std.debug.print("DIR: {s}\n", .{entry.name});
        }
    }
}
