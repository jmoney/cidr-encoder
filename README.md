# Cidr Encoder

Converts a list of CIDRs to an encoded file for time efficient lookups on is a given IP address in any of the CIDR blocks.  Each CIDR block is on its own line in the input file.  The output file is a binary file that can be read by the `cidr-encoder` program for searching.  The lookup time is `O(1)` for any IP address.  However, to achieve this the output file can easily be several GBs if there are a wide range of CIDR blocks across the IPv4 addresses space.
