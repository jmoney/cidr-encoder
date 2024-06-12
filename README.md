# Cidr Encoder

Converts a list of CIDRs to an encoded file for time efficient lookups on is a given IP address in any of the CIDR blocks.  Each CIDR block is on its own line in the input file.  The output file is a binary file that can be read by the `cidr-encoder` program for searching.  The lookup time is `O(1)` for any IP address.  However, to achieve this the output file can easily be several GBs if there are a wide range of CIDR blocks across the IPv4 addresses space.

The calculation for how big a file would take is effectively the largest IP - the smallest IP.  As the algorithm uses file offsets to determine if an IP is in a list of CIDR blocks, the largest IP is the largest offset in the file.  We use the smallest IP to normalize everything to first offset of a file.  This is done to reduce the size of the file so the difference between the two is the size of the file.

## Usage

```bash
$ cidr-encoder -h
Usage of cidr-encoder:
  -calc
        Calculate the size of the encoded file
  -encode
        Encode the CIDRs
  -name string
        The file base name to use as the ACL file name(e.g test.acl name is test)
  -search string
        Search for a IP in the CIDRs
```

`-calc`, `encode`, and `search` are all mutually exclusive but the priority in the event that all are specified are `calc` then `encode` then `search`.
