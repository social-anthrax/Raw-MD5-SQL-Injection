# Raw MD5 hash SQL injection cracker. 

This is a faster implementation of Christian von Kleist's solution that can be found here: https://cvk.posthaven.com/sql-injection-with-raw-md5-hashes.

The gist of this is that if raw MD5 hashes are used as a part of an SQL query we can manipulate the input to produce a hash with a shorter variant of `'or 1=1 --`. 
As sql casts any string beginning with a number to an integer, and an integer is interpreted as true in a boolean implementation, our goal is `'<some or>'<some int>`, or in regex: `'(\|\||or)'\d`.

On a 2021 M1 Max we average 10_000_000 hashes per 1.54 seconds.

