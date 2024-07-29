use anyhow::{Result, Context};
use anyhow::bail;
use chrono::Local;
use colored::Colorize;
use csv::WriterBuilder;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT,HeaderName};
use structopt::StructOpt;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
// use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;
use reqwest::{ ClientBuilder, Method};
use futures::stream::{FuturesUnordered, StreamExt};
use std::time::Instant;
use std::time::Duration;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use regex::Regex;
use rand::seq::SliceRandom;


#[derive(Debug, StructOpt)]
#[structopt(name = "pulse", about = "Red Team fast and efficient target detection tool.")]
struct Opt {
    /// version
    #[structopt(short, long)]
    version: bool,

    /// Input IP or URL with FUZZ marker
    #[structopt(short, long, value_name = "URL or File")]
    input: String,

    /// Number of concurrent requests
    #[structopt(short, long, default_value = "50")]
    threads: usize,

    /// Output CSV file name
    #[structopt(short, long, default_value = "output.csv")]
    output: String,

    /// Enable regex matching
    #[structopt(short, long)]
    regex: bool,

    /// Wordlist for fuzzing
    #[structopt(short, long, parse(from_os_str))]
    wordlist: Option<PathBuf>,

    /// Enable debug mode
    #[structopt(long)]
    debug: bool,

    /// Set Timeout
    #[structopt(short = "T", long, default_value = "10")]
    timeout: u64,

    /// Custom regex for matching in response body
    #[structopt(short = "m", long)]
    custom_matches: Vec<String>,

    /// Only show responses with these status codes
    #[structopt(short = "s", long, use_delimiter = true)]
    show_code: Vec<u16>,

    /// Do not show responses with these status codes
    #[structopt(short = "b", long, use_delimiter = true, default_value = "401,404")]
    ban_code: Vec<u16>,

    /// Silent mode: only output successful URLs
    #[structopt(long)]
    silent: bool,

    /// Directories to scan, comma separated
    #[structopt(short = "d", long, use_delimiter = true)]
    dir: Vec<String>,

    /// File containing directories to scan
    #[structopt(short = "D", long, parse(from_os_str))]
    dir_path: Option<PathBuf>,

    /// HTTP request method (GET, POST, PUT, DELETE, etc.)
    #[structopt(short = "M", long, default_value = "GET")]
    method: String,

    /// Custom HTTP headers to add to the request
    #[structopt(short = "H", long, use_delimiter = true)]
    custom_headers: Vec<String>,

    /// Do not display responses with this length (in characters)
    #[structopt(short = "L", long)]
    filter_length: Option<usize>,

    /// display responses with this length (in characters)
    #[structopt(short = "l", long)]
    match_length: Option<usize>,

    /// Proxy URL
    #[structopt(short = "p", long, value_name = "URL", default_value = "")]
    http_proxy: String,

    /// User-Agent to use
    #[structopt(short = "u", long, default_value = "default", possible_values = &["default", "random", "android"])]
    user_agent: String,

    /// Disable SSL certificate validation
    #[structopt(long)]
    no_ssl: bool,

    // /// Request body content
    // #[structopt(short = "B", long, value_name = "BODY")]
    // body_content: Option<String>,
}


fn logo(){
    let now = Local::now();
    let version = "1.0.1";  // 2024/7/29
    let author = "Enomothem".blue();
    let pulse = "pulse".bright_red();
    let live = "/".green();
    let elec = "——".green();
    let stime = now.format("%Y-%m-%d %H:%M:%S").to_string().white().dimmed();

    // pulse 0.0.1 2024-7-20 birth
    let logo = format!(r#"
                   ----                 ----
                    /\\      ATTACK：{birth}
    {pulse} {version}    /  \\
    ______________/    \\    {live}\\__{elec}_{elec}_{elec}_{elec}_{elec}_{elec}_{elec}_{elec}_{elec}_{elec}_
                        \\  {live}
                         \\{live}         by {author}
                        ----                 ----
    "#, version = version, author = author, live = live, pulse = pulse, birth = stime, elec = elec);

    println!("{}", logo.red());
}

fn end(){
    let logo = format!(r#"__________________________________________________________"#);
    println!("{}", logo.red());
}

fn version(){
    logo();
    thread::sleep(Duration::from_secs(1));
    println!("{} {}","[*]".cyan(), "pulse 0.0.1 2024-7-20 2:00");
    thread::sleep(Duration::from_secs(1));
    println!("{} {}","[*]".cyan(), "pulse 1.0.0 2024-7-24 Github Open Source.");
    thread::sleep(Duration::from_secs(1));
    println!("{} {}","[+]".green(), "pulse 1.0.1 2024-7-29 Add Proxy.");
    println!("{} {}","[*]".cyan(), "Enjoy it!");
}


#[tokio::main]
async fn main() -> Result<()> {


    let start = Instant::now();
    let opt = Opt::from_args();
    if opt.debug {
        println!("{:?}", opt);
    }
    if opt.version {
        version();
        return Ok(());
    }

    if !opt.silent {
        logo();
        let separate = "|".bright_yellow();
        if !opt.http_proxy.is_empty() {
            println!("{} 💥 {} {} ⏳ {} {} 📌 {} {} 🌐 {}", "[*]".cyan(), opt.threads, separate , opt.timeout, separate, opt.input.bright_cyan(), separate,  opt.http_proxy)
        }else{
            println!("{} 💥 {} {} ⏳ {} {} 📌 {} ", "[*]".cyan(), opt.threads, separate, opt.timeout, separate, opt.input.bright_cyan())
        }
    }

    // 解析自定义请求头
    let mut headers = HeaderMap::new();
    for header_str in &opt.custom_headers {
        let parts: Vec<&str> = header_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            eprintln!("Invalid custom header format: {}", header_str);
            continue;
        }
        let key = parts[0].trim();
        let value = parts[1].trim();
        let header_name = HeaderName::from_bytes(key.as_bytes()).unwrap();
        headers.insert(header_name, HeaderValue::from_str(value).unwrap());
    }

    // Create a CSV writer
    let wtr = Arc::new(tokio::sync::Mutex::new(WriterBuilder::new().from_path(&opt.output)?));
    {
        let mut wtr = wtr.lock().await;
        wtr.write_record(&["URL/IP", "Status Code", "Length", "Title"])?;
    }


    // Create HTTP client with timeout and connection pool settings
    let client = if !opt.http_proxy.clone().is_empty() {
        let pro = reqwest::Proxy::all(opt.http_proxy).expect("Failed to create proxy");
        ClientBuilder::new()
            .proxy(pro)
            .timeout(Duration::from_secs(opt.timeout))
            .pool_max_idle_per_host(10)
            .danger_accept_invalid_certs(opt.no_ssl)
            .build()?
    } else {
        ClientBuilder::new()
            .timeout(Duration::from_secs(opt.timeout))
            .pool_max_idle_per_host(10)
            .danger_accept_invalid_certs(opt.no_ssl)
            .build()?
    };

    // Concurrent request semaphore
    let semaphore = Arc::new(Semaphore::new(opt.threads));

    // Determine input mode and read IPs/URLs
    let inputs = if opt.input.contains("FUZZ") {
        if let Some(wordlist) = &opt.wordlist {
            let file = File::open(wordlist).await?;
            let reader = BufReader::new(file);
            let mut words = Vec::new();
            let mut lines = reader.lines();
            while let Some(line) = lines.next_line().await? {
                words.push(line); // 保存原始行，不添加协议头
            }

            // 在FUZZ替换之后添加协议头
            words.into_iter().map(|word| {
                let mut fuzzed_url = opt.input.replace("FUZZ", &word.trim());
                if !fuzzed_url.starts_with("http://") && !fuzzed_url.starts_with("https://") {
                    fuzzed_url = format!("http://{}", fuzzed_url);
                }
                fuzzed_url
            }).collect::<Vec<_>>()
        } else {
            let mut input_url = opt.input.clone();
            if !input_url.starts_with("http://") && !input_url.starts_with("https://") {
                input_url = format!("http://{}", input_url);
            }
            vec![input_url]
        }
    } else if let Ok(file) = File::open(&opt.input).await {
        let reader = BufReader::new(file);
        let mut ips = Vec::new();
        let mut lines = reader.lines();
        while let Some(line) = lines.next_line().await? {
            let url = line.trim();
            if !url.starts_with("http://") && !url.starts_with("https://") {
                ips.push(format!("http://{}", url));
            } else {
                ips.push(url.to_string());
            }
        }
        ips
    } else {
        let mut input_url = opt.input.clone();
        if !input_url.starts_with("http://") && !input_url.starts_with("https://") {
            input_url = format!("http://{}", input_url);
        }
        vec![input_url]
    };

    // Read directories from dir and dir_path
    let mut directories = opt.dir.clone();
    if let Some(dir_path) = &opt.dir_path {
        let file = File::open(dir_path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        while let Some(line) = lines.next_line().await? {
            directories.push(line);
        }
    }

    // Prepare URLs with directories
    let inputs_with_dirs = if directories.is_empty() {
        inputs.clone()
    } else {
        inputs.into_iter().flat_map(|url| {
            directories.iter().map(move |dir| format!("{}{}", url, dir))
        }).collect::<Vec<_>>()
    };

    // Prepare custom regex patterns
    let custom_regexes: Vec<(Regex, String)> = opt.custom_matches.iter().enumerate().map(|(i, pattern)| {
        let regex = Regex::new(pattern).unwrap();
        (regex, format!("Regex {}", i + 1))
    }).collect();

    let regex_results = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let custom_matches = Arc::new(tokio::sync::Mutex::new(Vec::new()));


    // Convert method string to reqwest Method
    let method = match opt.method.to_uppercase().as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        "OPTION" => Method::OPTIONS,
        "HEAD" => Method::HEAD,
        "PATCH" => Method::PATCH,
        "TRACE" => Method::TRACE,
        "CONNECT" => Method::CONNECT,
        _ => bail!("Unsupported HTTP method: {}", opt.method),
    };

    let custom_headers = headers.clone();
    let http_uas: Vec<&str> = vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:53.0) Gecko/20100101 Firefox/53.0",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    ];

    let android_uas: Vec<&str> = vec![
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 9; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.136 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 8.0.0; SM-G950F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.137 Mobile Safari/537.36",
    ];


    // let raw_body = if let Some(raw_path) = opt.raw.clone() {
    //     let mut file = File::open(raw_path).await?;
    //     let mut contents = Vec::new();
    //     file.read_to_end(&mut contents).await?;
    //     Some(contents)
    // } else {
    //     None
    // };

    // let body_content = opt.body_content.unwrap_or_default();

    let futures: FuturesUnordered<_> = inputs_with_dirs.into_iter().map(|url| {
        let client = client.clone();
        let semaphore = semaphore.clone();
        let wtr = wtr.clone();
        let regex_results = regex_results.clone();
        let custom_matches = custom_matches.clone();
        let regex_enabled = opt.regex;
        let custom_regexes = custom_regexes.clone();
        let show_code = opt.show_code.clone();
        let ban_code = opt.ban_code.clone();
        let silent = opt.silent;
        let method = method.clone();
        let custom_headers = custom_headers.clone(); // 使用解析后的 headers
        let ua_option = opt.user_agent.clone();
        let http_uas_clone = http_uas.clone();
        let android_uas_clone = android_uas.clone();
        // let body_content_clone = body_content.clone();
        // let raw_body_clone = raw_body.clone();

        tokio::spawn(async move {
            let permit = semaphore.acquire_owned().await;

            // Determine User-Agent
            let ua: &str = match ua_option.as_str() {
                "random" => {
                    let mut rng = rand::thread_rng();
                    http_uas_clone.choose(&mut rng).expect("No User-Agents available")
                },
                "android" => {
                    let mut rng = rand::thread_rng();
                    android_uas_clone.choose(&mut rng).expect("No Android User-Agents available")
                },
                _ => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3", // default UA
            };

            let mut request = client.request(method.clone(), &url);

            // Add custom headers
            for (key, value) in custom_headers.iter() {
                request = request.header(key, value);
            }

            // // Set raw body if provided
            // if let Some(body) = raw_body_clone.clone() {
            //     request = request.body(body);
            // }

            let mut headers_ua = HeaderMap::new();
            headers_ua.insert(USER_AGENT, HeaderValue::from_str(ua).unwrap());
            request = request.headers(headers_ua);

            let result = async {
                // match request(method.clone(), &url).send().await {
                match request.send().await {
                    Ok(response) => {
                        let stat = response.status();
                        let stat_code = stat.as_u16();

                        if (!show_code.is_empty() && !show_code.contains(&stat_code)) || ban_code.contains(&stat_code) {
                            return Ok::<(), anyhow::Error>(());
                        }

                        let stat_colored = match stat_code {
                            200..=299 => stat_code.to_string().green(),
                            300..=399 => stat_code.to_string().yellow(),
                            400..=499 => stat_code.to_string().red(),
                            500..=599 => stat_code.to_string().color("blue"),
                            _ => stat.to_string().white(),
                        };

                        let text = response.text().await?;
                        let len = text.len();


                        let re_title = Regex::new(r"<title>(.*?)</title>").unwrap();
                        let title = if let Some(captures) = re_title.captures(&text) {
                            captures.get(1).unwrap().as_str().to_string()
                        } else {
                            "No title".to_string()
                        };

                        // 长度检查
                        if let Some(filter_length) = opt.filter_length {
                            if len == filter_length {
                                return Ok(());  // 不显示该长度的URL = 排除法
                            }
                        }
                        if let Some(match_length) = opt.match_length {
                            if len != match_length {
                                return Ok(()); // 不显示除此以外的URL = 保留法
                            }
                        }

                        let len = len.to_string();
                        if !silent {
                            let ok = "[+]".green();
                            println!("{} {:55} [{}] - {:8} [{}]", ok, url.bright_magenta(), stat_colored, len.blue(), title.cyan());
                        } else if !show_code.is_empty() {
                            println!("{}", url);
                        } else if (200..=299).contains(&stat_code)  {
                            println!("{}", url);
                        }

                        {

                            let mut wtr = wtr.lock().await;
                            wtr.write_record(&[url.clone(), stat_code.to_string(), len.clone(), title.clone()])
                                .context("Failed to write record to CSV")?;

                        }

                        if regex_enabled {
                            let regexs = vec![
                                (Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(), "Email"),
                                (Regex::new(r#"https?://[^\s"]+"#).unwrap(), "URL"),
                                (Regex::new(r#"(?i)\b(?:/[^\s+<;>"]*)+\b"#).unwrap(), "Path"),
                                (Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap(), "IP"),
                                (Regex::new(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b").unwrap(), "Domain"),
                                (Regex::new(r"\b\w{6,}\b").unwrap(), "Token"),
                            ];
                            let mut regex_results_lock = regex_results.lock().await;
                            for (regex, label) in &regexs {
                                for captures in regex.captures_iter(&text) {
                                    if let Some(match_str) = captures.get(1) {
                                        regex_results_lock.push(format!("URL: {}, [{}]: [{}]", url, label, match_str.as_str()));
                                        if !silent {
                                            println!("  [{}]: [{}]", label.cyan(), match_str.as_str());
                                        }
                                    } else {
                                        regex_results_lock.push(format!("URL: {}, [{}]: [{}]", url, label, captures.get(0).unwrap().as_str()));
                                        if !silent {
                                            println!("  [{}]: [{}]", label.cyan(), captures.get(0).unwrap().as_str());
                                        }
                                    }
                                }
                            }
                        }

                        {
                            let mut custom_matches_lock = custom_matches.lock().await;
                            for (regex, label) in &custom_regexes {
                                for captures in regex.captures_iter(&text) {
                                    if let Some(match_str) = captures.get(0) {
                                        custom_matches_lock.push(format!("URL: {}, [{}]: [{}]", url, label, match_str.as_str()));
                                        if !silent {
                                            println!("  [{}]: [{}]", label.bright_red().bold(), match_str.as_str().to_string().bright_blue());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => (),
                }
                Ok::<(), anyhow::Error>(())
            }.await;

            drop(permit);
            result
        })
    }).collect();

    // Wait for all concurrent tasks to complete
    futures.for_each(|_| async {}).await;
    let duration = start.elapsed();
    if !opt.silent {
        let now = Local::now();
        let etime = now.format("%Y-%m-%d %H:%M:%S").to_string().white().dimmed();
        end();
        println!("{} 🎉 {:?}{:>23}{}", "[!]".cyan(), duration, "END：".cyan(),  etime)
    }
    Ok(())

}
