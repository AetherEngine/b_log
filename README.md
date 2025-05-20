# BLOG -- A Simple Binary Logging Format

This module provides the basic functionality necessary to read and understand BLOG files
The format is relatively simple:

| Segment          | Size                      | Description                                                                                                                 |
| ---------------- | ------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Header           | 24 bytes                  | Contains basic information for parsing, including number of categories, number of entries, and size of data                 |
| Category Entries | 20 bytes * category_count | Contains a `u16` for ID key value, Contains a `u16` for data entry type, Contains 15-character string + null terminator     |
| Log Entries      | 16 bytes * entry_count    | Contains a `u64` for timestamp and a "Categorized Pointer", comprised of `u48` location in the Data Log, and `u16` Category |
| Data Log         | any                       | Contains all data referenced by log entries, this is after decompression (the true size)                                    |

As one can see, the binary log can contain various types of data, including Binary, Text, Image Data, etc.
This allows one to easily sort and filter through the data.
