use anyhow::Result;

fn main() -> Result<()> {
    let test_files = std::fs::read_dir("./tests")?;
    for file in test_files {
        let file = file?;
        if !file.file_name().to_str().unwrap_or("").ends_with(".bin") {
            println!("[ERROR] Not bin file: {file:?}");
            continue;
        }

        let buf = std::fs::read(file.path())?;
        let parsed = parse_sni(&buf)?;
        println!("Parsed: {parsed:?}");
    }

    Ok(())
}

fn parse_sni(buf: &[u8]) -> Result<String> {
    Ok("".to_string())
}
