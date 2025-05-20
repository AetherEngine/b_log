//! BLOG -- A Simple Binary Logging Format
//! This module provides the basic functionality necessary to read and understand BLOG files
//! The format is relatively simple:
//!
//! | Segment          | Size                      | Description                                                                                                                 |
//! | ---------------- | ------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
//! | Header           | 24 bytes                  | Contains basic information for parsing, including number of categories, number of entries, and size of data                 |
//! | Category Entries | 20 bytes * category_count | Contains a `u16` for ID key value, Contains a `u16` for data entry type, Contains 15-character string + null terminator     |
//! | Log Entries      | 16 bytes * entry_count    | Contains a `u64` for timestamp and a "Categorized Pointer", comprised of `u48` location in the Data Log, and `u16` Category |
//! | Data Log         | any                       | Contains all data referenced by log entries, this is after decompression (the true size)                                    |
//!
//! As one can see, the binary log can contain various types of data, including Binary, Text, Image Data, etc.
//! This allows one to easily sort and filter through the data

const std = @import("std");
const assert = std.debug.assert;

/// Magic is "BLOG" in little endian
pub const MAGIC = std.mem.readInt(u32, "BLOG", .little);

/// Version Major
pub const SPEC_MAJOR = @as(u16, 1);

/// Version Minor
pub const SPEC_MINOR = @as(u16, 0);

/// Flags for file properties
pub const CompressionType = enum(u16) {
    None = 0,
    GZip = 1,
};

/// Version information
/// Externs Required for ReadStruct
pub const Version = packed struct(u32) {
    major: u16,
    minor: u16,
};

/// Assumed little endian
/// Externs Required for ReadStruct
pub const FileHeader = extern struct {
    /// Magic number is the ASCII "BLOG"
    magic: u32,
    /// Version of specification
    version: Version,
    /// Compression
    compression: CompressionType,
    /// Total # Categories
    category_count: u16,
    /// Total # Entries
    entry_count: u32,
    /// Data blob size
    data_size: u64,
};

/// Pointer to data with a category to determine what type of message this is
pub const CategorizedPointer = packed struct(u64) {
    /// Offset is the lower bits (more frequently used)
    offset: u48,

    /// Category is the upper bits (less frequently used)
    category: u16,
};

/// Log Entry, containing a time and the pointer
/// Externs Required for ReadStruct
pub const LogHeader = extern struct {
    /// Microseconds since UNIX epoch
    epoch_us_timestamp: i64,
    cat_pointer: CategorizedPointer,
};

/// Data Type Enumeration
pub const DataType = enum(u16) {
    Binary = 0,
    TextTrace = 1,
    TextDebug = 2,
    TextInfo = 3,
    TextWarning = 4,
    TextError = 5,
    ImageRaw = 6,
    // TODO: More types

    /// Users define their types starting at 1000
    Custom_Start = 1000,

    /// Enum is purposefully non-exhaustive
    _,
};

/// Category Entry
/// Externs Required for ReadStruct
pub const CategoryEntry = extern struct {
    /// ID Key to associate with this entry
    id: u16,
    /// Data Type
    data_type: DataType,
    /// Name -- must include a null terminator
    name: [16]u8,
};

// Comptime checks of basic properties of file structures
comptime {
    assert(@sizeOf(FileHeader) == 24);
    assert(@sizeOf(Version) == 4);
    assert(@sizeOf(CompressionType) == 2);
    assert(@sizeOf(DataType) == 2);
    assert(@sizeOf(CategoryEntry) == 20);
    assert(@sizeOf(LogHeader) == 16);
    assert(@bitOffsetOf(CategorizedPointer, "offset") == 0);
}

/// In-Memory Representation of a Category
pub const Category = struct {
    data_type: DataType,
    name: []const u8,
};

/// Categories in a mapping from ID number to Category structure
pub const CategoryTable = std.AutoArrayHashMapUnmanaged(u16, Category);

/// In-Memory Representation of a Log Entry
pub const LogEntry = struct {
    /// Microseconds since UNIX epoch
    epoch_us_timestamp: i64,
    /// Key into category table
    category: u16,
    /// Offset into shared data_buffer
    offset: usize,
    /// Length in shared data_buffer
    length: usize,
};

/// In-Memory Representation of a Binary Log
pub const BLog = struct {
    /// Local Arena holding all memory for Binary Log
    arena: std.heap.ArenaAllocator,

    /// Extensible for building behaviors -- owned by arena
    categories: CategoryTable,

    /// Extensible for building behaviors -- owned by arena
    entries: std.ArrayListUnmanaged(LogEntry),

    /// Extensible for building behaviors -- owned by arena
    data_buffer: std.ArrayListUnmanaged(u8),

    pub fn init(allocator: std.mem.Allocator) BLog {
        return .{
            .arena = std.heap.ArenaAllocator.init(allocator),
            .categories = .{},
            .entries = .{},
            .data_buffer = .{},
        };
    }

    /// ParseError set
    pub const ParseError = error{
        InvalidLogMagic,
        InvalidMajorVersion,
        MissingNullTerm,
        DuplicateCategoryID,
        EntriesNotSequential,
        InvalidDataType,
        DataSizeDoesNotMatch,
        InvalidOffset,
        InvalidCategory,
        ExtraDataAtEndOfBlob,
        UnknownCompression,
        EntryEndPastDataBlob,
    };

    pub const WriteError = error{
        CategoryNameTooLong,
        DataOutsideBuffer,
    };

    pub const CategoryError = error{
        DuplicateCategoryID,
        CategoryNameTooLong,
        InvalidDataType,
    };

    pub const EntryError = error{
        InvalidCategory,
    };

    pub fn get_entry_data(self: *BLog, idx: usize) []const u8 {
        const off = self.entries.items[idx].offset;
        const end = self.entries.items[idx].length;
        return self.data_buffer.items[off .. off + end];
    }

    pub fn add_entry(self: *BLog, category: u16, timestamp: i64, data: []const u8) (EntryError || std.mem.Allocator.Error)!void {
        if (!self.categories.contains(category))
            return EntryError.InvalidCategory;

        const curr_pos = self.data_buffer.items.len;
        try self.data_buffer.appendSlice(self.arena.allocator(), data);

        try self.entries.append(self.arena.allocator(), LogEntry{
            .epoch_us_timestamp = timestamp,
            .category = category,
            .offset = curr_pos,
            .length = self.data_buffer.items.len - curr_pos,
        });
    }

    pub fn add_category(self: *BLog, id: u16, name: []const u8, data_type: DataType) (CategoryError || std.mem.Allocator.Error)!void {
        if (self.categories.contains(id))
            return CategoryError.DuplicateCategoryID;

        if (name.len > 15)
            return CategoryError.CategoryNameTooLong;

        _ = std.meta.intToEnum(DataType, @intFromEnum(data_type)) catch if (@intFromEnum(data_type) < 1000) return CategoryError.InvalidDataType else 0;

        try self.categories.put(self.arena.allocator(), id, Category{
            .data_type = data_type,
            .name = try self.arena.allocator().dupe(u8, name),
        });
    }

    pub fn write(self: *BLog, writer: std.io.AnyWriter, compression: bool) (WriteError || std.io.AnyWriter.Error || std.mem.Allocator.Error)!void {
        const header = FileHeader{
            .magic = MAGIC,
            .version = .{ .major = SPEC_MAJOR, .minor = SPEC_MINOR },
            .compression = if (compression) .GZip else .None,
            .category_count = @intCast(self.categories.keys().len), // TODO: Replace with error
            .entry_count = @intCast(self.entries.items.len), // TODO: Replace with error
            .data_size = self.data_buffer.items.len,
        };

        try writer.writeStructEndian(header, .little);

        for (self.categories.keys()) |k| {
            const v = self.categories.get(k) orelse unreachable; // Logically this can't happen

            if (v.name.len > 15)
                return WriteError.CategoryNameTooLong;

            var entry = CategoryEntry{
                .id = k,
                .data_type = v.data_type,
                .name = @splat(0),
            };
            std.mem.copyForwards(u8, &entry.name, v.name);

            try writer.writeStructEndian(entry, .little);
        }

        for (self.entries.items) |e| {
            const place_ptr = e.offset;
            const place_len = e.length;

            if (self.data_buffer.items.len < place_ptr + place_len)
                return WriteError.DataOutsideBuffer;

            const entry = LogHeader{
                .cat_pointer = .{
                    .category = e.category,
                    .offset = @intCast(e.offset),
                },
                .epoch_us_timestamp = e.epoch_us_timestamp,
            };

            try writer.writeStructEndian(entry, .little);
        }

        if (compression) {
            var fixed_buffer = std.io.fixedBufferStream(self.data_buffer.items);
            try std.compress.gzip.compress(fixed_buffer.reader(), writer, .{});
        } else {
            try writer.writeAll(self.data_buffer.items);
        }
    }

    pub fn parse(allocator: std.mem.Allocator, reader: std.io.AnyReader) (ParseError || std.io.AnyReader.Error || std.mem.Allocator.Error)!BLog {
        var self = BLog.init(allocator);
        errdefer self.deinit();

        const header = try reader.readStructEndian(FileHeader, .little);
        if (header.magic != MAGIC)
            return ParseError.InvalidLogMagic;

        if (header.version.major != SPEC_MAJOR)
            return ParseError.InvalidMajorVersion;

        for (0..header.category_count) |_| {
            const category_entry = try reader.readStructEndian(CategoryEntry, .little);

            const null_location = std.mem.indexOfScalar(u8, &category_entry.name, 0);
            if (null_location == null)
                return ParseError.MissingNullTerm;

            if (self.categories.contains(category_entry.id))
                return ParseError.DuplicateCategoryID;

            const int = @intFromEnum(category_entry.data_type);
            const dt = std.meta.intToEnum(DataType, int) catch if (int < 1000) return ParseError.InvalidDataType else category_entry.data_type;

            try self.categories.put(self.arena.allocator(), category_entry.id, Category{
                .data_type = dt,
                .name = try self.arena.allocator().dupe(u8, category_entry.name[0..null_location.?]),
            });
        }

        var partial_list = std.ArrayList(LogHeader).init(self.arena.allocator());
        defer partial_list.deinit();

        for (0..header.entry_count) |i| {
            const entry = try reader.readStructEndian(LogHeader, .little);

            if (i != 0 and partial_list.items[i - 1].cat_pointer.offset >= entry.cat_pointer.offset)
                return ParseError.EntriesNotSequential;

            if (entry.cat_pointer.offset >= header.data_size)
                return ParseError.InvalidOffset;

            try partial_list.append(entry);
        }

        if (partial_list.items[partial_list.items.len - 1].cat_pointer.offset >= header.data_size)
            return ParseError.EntryEndPastDataBlob;

        // Copy until EOF w / decompress
        const buffer = blk: {
            if (header.compression == .GZip) {
                var result_buffer = std.ArrayList(u8).init(self.arena.allocator());
                try std.compress.gzip.decompress(reader, result_buffer.writer());

                break :blk try result_buffer.toOwnedSlice();
            } else if (header.compression == .None) {
                break :blk try reader.readAllAlloc(self.arena.allocator(), header.data_size);
            } else {
                return ParseError.UnknownCompression;
            }
        };

        // Must always be true
        if (buffer.len != header.data_size) {
            std.debug.print("Expected {} bytes, found {} bytes!\n", .{ header.data_size, buffer.len });
            return ParseError.DataSizeDoesNotMatch;
        }

        // Now can move buffer into array list.
        self.data_buffer = std.ArrayListUnmanaged(u8).fromOwnedSlice(buffer);

        // Complete the entries
        for (partial_list.items, 0..) |entry, i| {
            // Either end of buffer or next entry
            const end_point = if ((i + 1) < partial_list.items.len) partial_list.items[i + 1].cat_pointer.offset else self.data_buffer.items.len;

            if (end_point > self.data_buffer.items.len)
                return ParseError.InvalidOffset;

            if (!self.categories.contains(entry.cat_pointer.category))
                return ParseError.InvalidCategory;

            try self.entries.append(self.arena.allocator(), LogEntry{
                .category = entry.cat_pointer.category,
                .offset = entry.cat_pointer.offset,
                .length = end_point - entry.cat_pointer.offset,
                .epoch_us_timestamp = entry.epoch_us_timestamp,
            });
        }

        // Completes with success if EndOfStream, otherwise return error.
        _ = reader.readByte() catch |e| switch (e) {
            error.EndOfStream => return self,
            else => return e,
        };

        return ParseError.ExtraDataAtEndOfBlob;
    }

    pub fn deinit(self: *BLog) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

test "write and parse" {
    const allocator = std.testing.allocator;

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    {
        var log = BLog.init(allocator);
        defer log.deinit();

        try log.add_category(0, "Info", .TextInfo);
        try log.add_category(1, "Debug", .TextDebug);
        try log.add_category(2, "Error", .TextError);
        try log.add_entry(0, std.time.microTimestamp(), "Hello world!");
        try log.add_entry(1, std.time.microTimestamp(), "Hello world!");
        try log.add_entry(2, std.time.microTimestamp(), "Hello world!");

        try log.write(buffer.writer().any(), true);
    }

    var fbstream = std.io.fixedBufferStream(buffer.items);

    {
        var log = try BLog.parse(allocator, fbstream.reader().any());
        defer log.deinit();

        try std.testing.expectEqualStrings(log.get_entry_data(0), "Hello world!");
    }
}
