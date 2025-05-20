const std = @import("std");
const blog = @import("b_log");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    {
        var log = blog.BLog.init(allocator);
        defer log.deinit();

        try log.add_category(0, "Info", .TextInfo);
        try log.add_category(1, "Debug", .TextDebug);
        try log.add_category(2, "Error", .TextError);
        try log.add_entry(0, std.time.microTimestamp(), "Hello world!");
        try log.add_entry(1, std.time.microTimestamp(), "Hello world!");
        try log.add_entry(2, std.time.microTimestamp(), "Hello world!");

        var file = try std.fs.cwd().createFile("test.blog", .{});
        defer file.close();

        try log.write(file.writer().any(), true);
    }

    {
        var file = try std.fs.cwd().openFile("test.blog", .{});
        defer file.close();

        var log = try blog.BLog.parse(allocator, file.reader().any());
        defer log.deinit();

        for (log.entries.items, 0..) |e, idx| {
            std.debug.print("{s} Entry: {s}\n", .{ log.categories.get(e.category).?.name, log.get_entry_data(idx) });
        }
    }
}
