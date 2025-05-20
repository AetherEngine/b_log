const std = @import("std");
const blog = @import("b_log");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var arg_it = try std.process.argsWithAllocator(allocator);
    defer arg_it.deinit();
    _ = arg_it.skip();

    const path = arg_it.next() orelse {
        std.debug.print("Usage: ./blogcat <file.blog>\n", .{});
        std.posix.exit(1);
    };

    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var log = try blog.BLog.parse(allocator, file.reader().any());
    defer log.deinit();

    for (log.entries.items, 0..) |e, i| {
        std.io.getStdOut().writer().print("[{s}]: {s}\n", .{ log.categories.get(e.category).?.name, log.get_entry_data(i) }) catch unreachable;
    }
}
