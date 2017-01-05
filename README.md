Renater
=======

Quick and dirty ruby script, to answer to school IT requests.

We regularly receive CERT alerts of infected computers contacting malicious servers, and people from above want us to clean or disconnect them.

The problem is that the CERT report gives the date in the `2016-11-09 22:16:46+01:00` format, whereas squid logs everything as timestamps.

This script allows us to quickly comply with the request, by providing both date and destination IP, and then parsing all logs.

## Usage

  1. SSH to the proxy indicated in the report.

  2. Run `ruby renater.rb`, placed in the folder where all the logs are (usually `/home/squid3`).

  3. Enter date as provided in the report, and the destination IP.

## Author
Thomas 'Nymous' Gaudin

## License
WTFPL
