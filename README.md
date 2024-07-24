# pulse

`pulse` is a powerful web scanning and fuzzing tool written in Rust. It allows you to perform concurrent web requests, directory fuzzing, and custom regex matching on the responses.

## Features

- Concurrent web requests with configurable thread count
- Fuzzing with wordlists for URLs or IP addresses
- Directory scanning with built-in or custom directory lists
- Custom regex matching on response bodies
- Filtering responses based on status codes
- Silent mode for displaying only successful URLs
- CSV output for easy analysis and reporting
- Timeout configuration for web requests
- Colored output for better visibility

## Installation

To install `pulse`, you need to have Rust and Cargo installed on your system. You can install Rust by following the instructions on the official Rust website: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)

Once you have Rust and Cargo installed, you can clone the `pulse` repository and build the project:

```bash
git clone https://github.com/your-username/pulse.git
cd pulse
cargo build --release



Insert at cursor
markdown
The compiled binary will be located in the
target/release
 directory.

Usage
pulse [OPTIONS] --input <INPUT>



Insert at cursor
text
Options
-i, --input <INPUT>
: Input IP or URL with FUZZ marker

-t, --threads <THREADS>
: Number of concurrent requests (default: 50)

-o, --output <OUTPUT>
: Output CSV file name (default: output.csv)

-r, --regex
: Enable regex matching

-w, --wordlist <WORDLIST>
: Wordlist for fuzzing

--debug
: Enable debug mode

-T, --timeout <TIMEOUT>
: Set timeout (default: 10 seconds)

-m, --custom-matches <CUSTOM_MATCHES>
: Custom regex for matching in response body

-s, --show-code <SHOW_CODE>
: Only show responses with these status codes

-b, --ban-code <BAN_CODE>
: Do not show responses with these status codes (default: 401,404)

--silent
: Silent mode: only output successful URLs

-d, --dir <DIR>
: Directories to scan, comma separated

-D, --dir-path <DIR_PATH>
: File containing directories to scan

Examples
Scan a single URL:

pulse --input <a href="https://example.com">https://example.com</a>



Insert at cursor
text
Scan a list of IPs from a file:

pulse --input ips.txt



Insert at cursor
text
Perform fuzzing with a wordlist:

pulse --input <a href="https://example.com/FUZZ">https://example.com/FUZZ</a> --wordlist wordlist.txt



Insert at cursor
text
Scan with custom directories and regex matching:

pulse --input <a href="https://example.com">https://example.com</a> --dir /admin,/secret --regex --custom-matches "password|email"



Insert at cursor
text
Contributing
Contributions to
pulse
 are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on the GitHub repository.

License
pulse
 is licensed under the MIT License.


This README file provides an overview of the `pulse` tool, its features, installation instructions, usage examples, and information about contributing and licensing. Feel free to modify it according to your specific needs or add any additional sections you deem necessary.

