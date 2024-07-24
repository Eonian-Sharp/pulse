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
```


### Usage

```bash
pulse [OPTIONS] --input <INPUT>
```

Options

```
-i, --input <INPUT>
```
:Input IP or URL with FUZZ marker
```
-t, --threads <THREADS>
```

:Number of concurrent requests (default: 50)
```
-o, --output <OUTPUT>
```

: Output CSV file name (default: output.csv)
```
-r, --regex
```

: Enable regex matching
```
-w, --wordlist <WORDLIST>
```

: Wordlist for fuzzing

```
-T, --timeout <TIMEOUT>
```

: Set timeout (default: 10 seconds)
```
-m, --custom-matches <CUSTOM_MATCHES>
```

: Custom regex for matching in response body
```
-s, --show-code <SHOW_CODE>
```

: Only show responses with these status codes
```
-b, --ban-code <BAN_CODE>
```

: Do not show responses with these status codes (default: 401,404)
```
--silent
```

: Silent mode: only output successful URLs
```
-d, --dir <DIR>
```

: Directories to scan, comma separated
```
-D, --dir-path <DIR_PATH>
```
: File containing directories to scan

Examples
Scan a single URL:
```
pulse --input  http://eoniansharp.com
```

Scan a list of IPs from a file:
```
pulse --input ips.txt
```

Perform fuzzing with a wordlist:
```
pulse --input http://eoniansharp.com/FUZZ --wordlist wordlist.txt
```

Scan with custom directories and regex matching:
```
pulse --input https://eoniansharp.com/admin --dir /admin,/secret --regex --custom-matches "password|email"
```


## License
MIT License

Copyright (c) [year] [fullname]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

