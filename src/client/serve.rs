use crate::{ERROR_HTML, LIST_HTML};
use anyhow::Result;
use fkm_proxy::utils::http::{construct_raw_http_resp, write_http_resp};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// TODO: cleanup this fucking mess LMAO

pub async fn serve_files<S>(stream: &mut S, files_index: bool) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // for example: "GET / HTTP1.1"
    let mut buffer = [0u8; 1];
    let mut parts = String::new();
    loop {
        stream.read_exact(&mut buffer).await?;
        if buffer[0] == 0x0A {
            break;
        }
        parts.push(buffer[0] as char);
    }

    let parts = parts.trim().split(" ").collect::<Vec<&str>>();

    let path = parts[1].trim_start_matches("/").trim_end_matches("/");
    let local_path = std::env::current_dir()
        .unwrap_or(PathBuf::from("/tmp"))
        .join(path);

    if local_path.exists() {
        if let Ok(metadata) = local_path.metadata() {
            if metadata.is_dir() {
                let index_file = local_path.join("index.html");
                if index_file.exists() {
                    serve_file(stream, &index_file).await?;
                } else if files_index {
                    let mut generated = String::new();
                    let mut directories = Vec::new();
                    let mut files = Vec::new();

                    if let Ok(dir) = local_path.read_dir() {
                        for entry in dir.flatten() {
                            if let Ok(metadata) = entry.metadata() {
                                let filename = entry.file_name();
                                let filename = filename.to_str().unwrap_or("---").to_string();
                                let file_path = if path.is_empty() {
                                    format!("/{filename}")
                                } else {
                                    format!("/{path}/{filename}")
                                };

                                let last_modified = metadata
                                    .modified()
                                    .map(|t| {
                                        let datetime: chrono::DateTime<chrono::Local> = t.into();
                                        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
                                    })
                                    .unwrap_or("---".to_string());

                                let file_size = if metadata.is_file() {
                                    let size = metadata.len();
                                    if size < 1024 {
                                        format!("{size} B")
                                    } else if size < 1024 * 1024 {
                                        format!("{:.1} KB", size as f64 / 1024.0)
                                    } else {
                                        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
                                    }
                                } else {
                                    "-".to_string()
                                };

                                let entry_data = (file_path, filename, last_modified, file_size);
                                if metadata.is_dir() {
                                    directories.push(entry_data);
                                } else if metadata.is_file() {
                                    files.push(entry_data);
                                }
                            }
                        }
                    }

                    directories.sort_by(|a, b| a.1.cmp(&b.1));
                    files.sort_by(|a, b| a.1.cmp(&b.1));

                    let parent_path = if let Some(parent) = Path::new(&path).parent() {
                        &format!("/{}", parent.to_str().unwrap_or(""))
                    } else {
                        "/"
                    };

                    generated += &format!(
                        "<tr>\n    <td><a href=\"{}\">..</a></td>\n    <td></td>\n    <td></td>\n</tr>\n",
                        html_escape::encode_text(parent_path),
                    );

                    for (file_path, filename, last_modified, file_size) in directories {
                        generated += &format!(
                            "<tr>\n    <td><a href=\"{}\">{}</a></td>\n    <td>{}</td>\n    <td>{}</td>\n</tr>\n",
                            html_escape::encode_text(&file_path),
                            html_escape::encode_text(&filename),
                            html_escape::encode_text(&last_modified),
                            html_escape::encode_text(&file_size)
                        );
                    }
                    for (file_path, filename, last_modified, file_size) in files {
                        generated += &format!(
                            "<tr>\n    <td><a href=\"{}\">{}</a></td>\n    <td>{}</td>\n    <td>{}</td>\n</tr>\n",
                            html_escape::encode_text(&file_path),
                            html_escape::encode_text(&filename),
                            html_escape::encode_text(&last_modified),
                            html_escape::encode_text(&file_size)
                        );
                    }

                    write_http_resp(
                        stream,
                        200,
                        &LIST_HTML
                            .replace("{CONTENT}", &generated)
                            .replace("{DIR_PATH}", &format!("/{path}")),
                        "text/html",
                    )
                    .await?;
                } else {
                    write_http_resp(
                        stream,
                        404,
                        &ERROR_HTML.replace("{MSG}", "Local file not found!"),
                        "text/html",
                    )
                    .await?;
                }
            } else if metadata.is_file() {
                serve_file(stream, &local_path).await?;
            }
        } else {
            write_http_resp(
                stream,
                500,
                &ERROR_HTML.replace("{MSG}", "File metadata not found!"),
                "text/html",
            )
            .await?;
        }
    } else {
        write_http_resp(
            stream,
            404,
            &ERROR_HTML.replace("{MSG}", "Local file not found!"),
            "text/html",
        )
        .await?;
    }

    Ok(())
}

async fn serve_file<S>(stream: &mut S, path: &PathBuf) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let file_contents = tokio::fs::read(path).await;
    if let Ok(content) = file_contents {
        let resp = construct_raw_http_resp(
            200,
            &content,
            mime_guess::from_path(path)
                .first_raw()
                .unwrap_or("text/plain"),
        );

        stream.write_all(&resp).await?;
    } else {
        write_http_resp(
            stream,
            500,
            &ERROR_HTML.replace("{MSG}", "Local file read error!"),
            "text/html",
        )
        .await?;
    }

    Ok(())
}
