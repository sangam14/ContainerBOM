use clap::{Arg, Command};
use bollard::Docker;
use bollard::image::CreateImageOptions;
use futures_util::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use tokio;
use std::process::Command as StdCommand;
use std::io;

#[derive(Serialize, Deserialize, Debug)]
struct Notice {
    message: String,
    level: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Layer {
    fs_hash: String,
    files_analyzed: bool,
    os_guess: String,
    pkg_format: String,
    extension_info: HashMap<String, String>,
    packages: Vec<String>, // Simplified for this example
    notices: Vec<Notice>,
    analyzed_output: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Sbom {
    image_name: String,
    layers: Vec<Layer>,
}

#[tokio::main]
async fn main() {
    let matches = Command::new("Container SBOM")
        .version("1.0")
        .author("Your Name <you@example.com>")
        .about("CLI tool to generate SBOM for Docker images")
        .arg(
            Arg::new("IMAGE")
                .help("Docker image to analyze")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file for the SBOM"),
        )
        .get_matches();

    let image_name = matches.get_one::<String>("IMAGE").unwrap();
    let output_file = matches.get_one::<String>("output");

    let mut sbom = Sbom {
        image_name: image_name.to_string(),
        layers: Vec::new(),
    };

    ensure_image_exists(image_name).await;
    let layers = analyze_image(image_name).await;
    sbom.layers = layers;

    if let Some(output) = output_file {
        save_sbom_to_file(&sbom, output);
    } else {
        println!("{}", serde_json::to_string_pretty(&sbom).unwrap());
    }
}

async fn ensure_image_exists(image_name: &str) {
    let docker = Docker::connect_with_local_defaults().unwrap();

    let common_typos: HashMap<&str, &str> = [
        ("ngnix", "nginx"),
        // Add more common typos and corrections as needed
    ]
    .iter()
    .cloned()
    .collect();

    let corrected_name = common_typos.get(image_name).unwrap_or(&image_name);

    match docker.inspect_image(corrected_name).await {
        Ok(_) => {
            println!("Image {} already exists locally.", corrected_name);
        }
        Err(_) => {
            println!(
                "Image {} not found locally. Pulling from Docker registry...",
                corrected_name
            );
            let options = Some(CreateImageOptions {
                from_image: (*corrected_name).to_string(),
                ..Default::default()
            });

            let mut stream = docker.create_image(options, None, None);

            while let Some(progress) = stream.next().await {
                match progress {
                    Ok(progress) => {
                        if let Some(status) = progress.status {
                            println!("{}", status);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error pulling image: {}", e);
                        return;
                    }
                }
            }
        }
    }
}

async fn analyze_image(image_name: &str) -> Vec<Layer> {
    let docker = Docker::connect_with_local_defaults().unwrap();

    let common_typos: HashMap<&str, &str> = [
        ("ngnix", "nginx"),
        // Add more common typos and corrections as needed
    ]
    .iter()
    .cloned()
    .collect();

    let corrected_name = common_typos.get(image_name).unwrap_or(&image_name);

    match docker.inspect_image(corrected_name).await {
        Ok(image) => {
            let mut layers = Vec::new();
            if let Some(root_fs) = image.root_fs {
                if let Some(layer_ids) = root_fs.layers {
                    for layer_id in layer_ids.iter() {
                        let layer = Layer {
                            fs_hash: layer_id.clone(),
                            files_analyzed: false,
                            os_guess: String::new(),
                            pkg_format: String::new(),
                            extension_info: HashMap::new(),
                            packages: Vec::new(),
                            notices: Vec::new(),
                            analyzed_output: String::new(),
                        };
                        // Here you can call analyze_layer or any other function to analyze the layer
                        layers.push(layer);
                    }
                }
            }
            return layers;
        }
        Err(e) => {
            eprintln!("Error inspecting image: {}", e);
            return Vec::new();
        }
    }
}

fn save_sbom_to_file(sbom: &Sbom, output_file: &str) {
    let sbom_json = serde_json::to_string_pretty(sbom).expect("Unable to serialize SBOM");
    fs::write(output_file, sbom_json).expect("Unable to write SBOM to file");
}

fn execute_external_command(command: &str, is_sudo: bool) -> Result<String, io::Error> {
    let cmd_list: Vec<&str> = command.split_whitespace().collect();
    let mut cmd = StdCommand::new(cmd_list[0]);
    if is_sudo {
        cmd.arg("sudo");
    }
    for arg in &cmd_list[1..] {
        cmd.arg(arg);
    }

    let output = cmd.output()?;
    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(io::Error::new(io::ErrorKind::Other, err_msg));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn analyze_layer(layer: &mut Layer, command: &str) {
    match execute_external_command(command, false) {
        Ok(output) => {
            layer.analyzed_output = output;
        }
        Err(e) => {
            let notice = Notice {
                message: format!("Error executing command: {}", e),
                level: "error".to_string(),
            };
            layer.notices.push(notice);
        }
    }
}
