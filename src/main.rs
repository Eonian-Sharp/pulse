use anyhow::{Result, Context};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::ClientBuilder;
use regex::Regex;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use std::time::Duration;
use tokio::sync::Semaphore;
use std::sync::Arc;
use colored::Colorize;
use csv::WriterBuilder;
use structopt::StructOpt;
use std::path::PathBuf;
use chrono::Local;
use std::time::Instant;



#[derive(Debug, StructOpt)]
// #[structopt(name = "web_checker", about = "A web checker tool.")]
struct Opt {
    /// Input IP or URL with FUZZ marker
    #[structopt(short, long)]
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
}


fn logo(){
    let now = Local::now();
    let version = "1.0.0";
    let author = "Enomothem".blue();
    let pulse = "pulse".bright_red();
    let live = "/".green();
    let stime = now.format("%Y-%m-%d %H:%M:%S").to_string().white().dimmed();

    let logo = format!(r#"
                    /\\      Birth：{birth}
    {pulse} {version}    /  \\
    ______________/    \\    {live}\\______________________
                        \\  {live}
                         \\{live}         by {author}

    "#, version = version, author = author, live = live, pulse = pulse, birth = stime);

    println!("{}", logo.red());
}

fn end(){
    let logo = format!(r#"__________________________________________________________"#);
    println!("{}", logo.red());
}


#[tokio::main]
async fn main() -> Result<()> {
    let start = Instant::now();
    let opt = Opt::from_args();
    if opt.debug {
        println!("{:?}", opt);
    }

    if !opt.silent {
        logo();
        println!("{} 💥 {} ⏳ {} 📌 {}", "[*]".cyan(), opt.threads, opt.timeout, opt.input.bright_cyan())
    }

    // Create a CSV writer
    let wtr = Arc::new(tokio::sync::Mutex::new(WriterBuilder::new().from_path(&opt.output)?));
    {
        let mut wtr = wtr.lock().await;
        wtr.write_record(&["URL/IP", "Status Code", "Length", "Title"])?;
    }

    // Create HTTP client with timeout and connection pool settings
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(opt.timeout))
        .pool_max_idle_per_host(10)
        .build()?;

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
                let word = line.trim(); // 去除行尾的换行符等空白字符
                let url = if word.starts_with("http://") || word.starts_with("https://") {
                    word.to_string()
                } else {
                    format!("http://{}", word)
                };
                words.push(url);
            }
            words.into_iter().map(|word| opt.input.replace("FUZZ", &word)).collect::<Vec<_>>()
        } else {
            let input_url = if opt.input.starts_with("http://") || opt.input.starts_with("https://") {
                opt.input.clone()
            } else {
                format!("http://{}", opt.input)
            };
            vec![input_url]
        }
    } else if let Ok(file) = File::open(&opt.input).await {
        let reader = BufReader::new(file);
        let mut ips = Vec::new();
        let mut lines = reader.lines();
        while let Some(line) = lines.next_line().await? {
            let url = line.trim();
            let url_to_add = if url.starts_with("http://") || url.starts_with("https://") {
                url.to_string()
            } else {
                format!("http://{}", url)
            };
            ips.push(url_to_add);
        }
        ips
    } else {
        let input_url = if opt.input.starts_with("http://") || opt.input.starts_with("https://") {
            opt.input.clone()
        } else {
            format!("http://{}", opt.input)
        };
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
        (regex, format!("Custom {}", i + 1))
    }).collect();

    let regex_results = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let custom_matches = Arc::new(tokio::sync::Mutex::new(Vec::new()));

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
        tokio::spawn(async move {
            let permit = semaphore.acquire_owned().await;

            let result = async {
                match client.get(&url).send().await {
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
                        let len = text.len().to_string();
                        let re_title = Regex::new(r"<title>(.*?)</title>").unwrap();
                        let title = if let Some(captures) = re_title.captures(&text) {
                            captures.get(1).unwrap().as_str().to_string()
                        } else {
                            "No title".to_string()
                        };

                        if !silent {
                            let ok = "[+]".green();
                            println!("{} {:55} [{}] - {:8} [{}]", ok, url.purple(), stat_colored, len.blue(), title.cyan());
                        } else if stat_code >= 200 && stat_code <= 299 {
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
                                            println!("  [{}]: [{}]", label.bright_red().bold(), match_str.as_str().to_string().bright_purple());
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
        println!("{:?}{:>23}{}", duration,"END：".cyan(),  etime)
    }
    Ok(())

}
