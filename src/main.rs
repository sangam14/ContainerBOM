use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use clap::{Arg, Command};
use bollard::Docker;
use bollard::image::{CreateImageOptions, BuildImageOptions};
use bollard::models::BuildInfo;
use futures_util::stream::StreamExt;
use tokio::runtime::Runtime;
use serde::{Serialize, Deserialize};
use ring::signature::{Ed25519KeyPair, KeyPair, ED25519};
use ring::rand::SystemRandom;
use data_encoding::BASE64;
use dockerfile_parser::{Dockerfile, Instruction};
use tar::Builder;
use hyper::body::Bytes;

#[derive(Debug, Serialize, Deserialize)]
struct Layer {
    files_analyzed: bool,
    os_guess: String,
    pkg_format: String,
    packages: Vec<String>,
    notices: Vec<Notice>,
    analyzed_output: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Notice {
    message: String,
    level: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Sbom {
    image_name: String,
    layers: Vec<Layer>,
    dockerfile_analysis: Option<DockerfileAnalysis>,
    signature: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DockerfileAnalysis {
    envs: HashMap<String, String>,
    instructions: Vec<String>,
    packages: Vec<String>,
}

fn main() {
    let matches = Command::new("Container SBOM")
        .version("1.0")
        .author("Your Name <you@example.com>")
        .about("CLI tool to generate SBOM for Docker images")
        .subcommand(
            Command::new("generate-key")
                .about("Generate a new Ed25519 keypair")
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("FILE")
                        .help("Output file for the keypair")
                        .value_parser(clap::value_parser!(String))
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("analyze")
                .about("Analyze a Docker image and generate SBOM")
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
                        .help("Output file for the SBOM")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("dockerfile")
                        .short('d')
                        .long("dockerfile")
                        .value_name("FILE")
                        .help("Dockerfile to analyze and build")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("build")
                        .short('b')
                        .long("build")
                        .help("Build Docker image from Dockerfile")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("tag")
                        .short('t')
                        .long("tag")
                        .value_name("NAME")
                        .help("Tag for the Docker image")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("sign")
                        .short('s')
                        .long("sign")
                        .value_name("KEY")
                        .help("Sign the SBOM with the given key")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("verify")
                        .short('v')
                        .long("verify")
                        .value_name("KEY")
                        .help("Verify the SBOM with the given key")
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("generate-key") {
        let output_file = matches.get_one::<String>("output").unwrap();
        let (_, pkcs8_bytes) = generate_keypair();
        save_keypair_to_file(&pkcs8_bytes, output_file);
        println!("Keypair saved to {}", output_file);
    }

    if let Some(matches) = matches.subcommand_matches("analyze") {
        let image_name = matches.get_one::<String>("IMAGE").unwrap();
        let output_file = matches.get_one::<String>("output");
        let dockerfile_path = matches.get_one::<String>("dockerfile");
        let build_image = matches.get_flag("build");
        let tag_name = matches.get_one::<String>("tag").unwrap_or(image_name);
        let sign_key = matches.get_one::<String>("sign");
        let verify_key = matches.get_one::<String>("verify");

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut sbom = Sbom {
                image_name: image_name.clone(),
                layers: Vec::new(),
                dockerfile_analysis: None,
                signature: None,
            };

            if build_image {
                if let Some(dockerfile) = dockerfile_path {
                    build_dockerfile_image(dockerfile, tag_name).await.unwrap();
                } else {
                    eprintln!("Dockerfile path is required to build an image.");
                    return;
                }
            }

            ensure_image_exists(image_name).await.unwrap();
            let layers = analyze_image(image_name).await;
            sbom.layers = layers;

            if let Some(dockerfile) = dockerfile_path {
                let dockerfile_analysis = analyze_dockerfile(dockerfile);
                sbom.dockerfile_analysis = Some(dockerfile_analysis);
            }

            if let Some(key_path) = sign_key {
                let key_pair = load_keypair_from_file(key_path);
                let sbom_json = serde_json::to_string(&sbom).unwrap();
                let signature = sign_data(&key_pair, sbom_json.as_bytes());
                sbom.signature = Some(signature);
            }

            if let Some(output) = output_file {
                save_sbom_to_file(&sbom, output);
            } else {
                println!("{}", serde_json::to_string_pretty(&sbom).unwrap());
            }

            if let Some(key_path) = verify_key {
                if let Some(signature) = &sbom.signature {
                    let key_pair = load_keypair_from_file(key_path);
                    let sbom_json = serde_json::to_string(&sbom).unwrap();
                    let public_key = key_pair.public_key().as_ref();
                    if verify_signature(public_key, sbom_json.as_bytes(), signature) {
                        println!("Signature verification succeeded.");
                    } else {
                        println!("Signature verification failed.");
                    }
                } else {
                    println!("No signature found to verify.");
                }
            }
        });
    }
}

async fn ensure_image_exists(image_name: &str) -> Result<(), bollard::errors::Error> {
    let docker = Docker::connect_with_local_defaults().unwrap();

    match docker.inspect_image(image_name).await {
        Ok(_) => Ok(()),
        Err(_) => {
            let options = Some(CreateImageOptions {
                from_image: image_name,
                ..Default::default()
            });
            let mut stream = docker.create_image(options, None, None);

            while let Some(result) = stream.next().await {
                result?;
            }
            Ok(())
        }
    }
}

async fn build_dockerfile_image(dockerfile_path: &str, image_name: &str) -> Result<(), bollard::errors::Error> {
    let docker = Docker::connect_with_local_defaults().unwrap();

    let options = BuildImageOptions {
        t: image_name.to_string(),
        rm: true,
        ..Default::default()
    };

    let tar_path = create_tarball(dockerfile_path)?;
    let tar_file = fs::read(tar_path)?;
    let body = Bytes::from(tar_file);

    let mut stream = docker.build_image(options, None, Some(body));

    while let Some(result) = stream.next().await {
        match result {
            Ok(BuildInfo { stream: Some(stream), error: None, .. }) => {
                print!("{}", stream);
            }
            Ok(BuildInfo { error: Some(error), .. }) => {
                eprintln!("Error building image: {}", error);
                return Err(bollard::errors::Error::DockerResponseServerError {
                    message: error,
                    status_code: 500,
                });
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                return Err(e);
            }
        }
    }
    Ok(())
}

fn create_tarball(dockerfile_path: &str) -> Result<String, std::io::Error> {
    let tar_path = "dockerfile.tar";
    let file = File::create(tar_path)?;
    let mut builder = Builder::new(file);

    let dockerfile_name = Path::new(dockerfile_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Dockerfile");

    builder.append_path_with_name(dockerfile_path, dockerfile_name)?;
    builder.finish()?;
    Ok(tar_path.to_string())
}

async fn analyze_image(_image_name: &str) -> Vec<Layer> {
    // Mock implementation, replace with actual logic to analyze image layers
    vec![
        Layer {
            files_analyzed: true,
            os_guess: "linux".to_string(),
            pkg_format: "deb".to_string(),
            packages: vec!["package1".to_string(), "package2".to_string()],
            notices: vec![
                Notice {
                    message: "Example notice".to_string(),
                    level: "info".to_string(),
                },
            ],
            analyzed_output: "Example analysis output".to_string(),
        },
    ]
}

fn analyze_dockerfile(dockerfile_path: &str) -> DockerfileAnalysis {
    let mut envs = HashMap::new();
    let mut instructions = Vec::new();
    let mut packages = Vec::new();

    let dockerfile_content = fs::read_to_string(dockerfile_path).expect("Unable to read Dockerfile");

    let parser = Dockerfile::parse(dockerfile_content.as_str()).unwrap();

    for inst in &parser.instructions {
        match inst {
            Instruction::Env(env_line) => {
                let env_str = format!("{:?}", env_line);
                for var in env_str.split_whitespace() {
                    let parts: Vec<&str> = var.split('=').collect();
                    if parts.len() == 2 {
                        envs.insert(parts[0].to_string(), parts[1].to_string());
                    }
                }
            }
            Instruction::Run(run_line) => {
                let run_str = format!("{:?}", run_line);
                for command in run_str.split("&&") {
                    let pkgs = command.split_whitespace().map(|s| s.to_string()).collect::<Vec<String>>();
                    packages.extend(pkgs);
                }
            }
            _ => {}
        }
        instructions.push(format!("{:?}", inst));
    }

    DockerfileAnalysis {
        envs,
        instructions,
        packages,
    }
}

fn generate_keypair() -> (Ed25519KeyPair, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    (key_pair, pkcs8_bytes.as_ref().to_vec())
}

fn save_keypair_to_file(pkcs8_bytes: &[u8], file_path: &str) {
    let mut file = File::create(file_path).expect("Unable to create file");
    file.write_all(pkcs8_bytes).expect("Unable to write data");
}

fn load_keypair_from_file(file_path: &str) -> Ed25519KeyPair {
    let key_data = fs::read(file_path).expect("Unable to read file");
    Ed25519KeyPair::from_pkcs8(key_data.as_ref()).unwrap()
}

fn sign_data(key_pair: &Ed25519KeyPair, data: &[u8]) -> String {
    let sig = key_pair.sign(data);
    BASE64.encode(sig.as_ref())
}

fn save_sbom_to_file(sbom: &Sbom, file_path: &str) {
    let sbom_json = serde_json::to_string_pretty(sbom).unwrap();
    let mut file = File::create(file_path).expect("Unable to create file");
    file.write_all(sbom_json.as_bytes()).expect("Unable to write data")
}

fn verify_signature(public_key: &[u8], data: &[u8], signature: &str) -> bool {
    let sig_bytes = BASE64.decode(signature.as_bytes()).unwrap();
    let peer_public_key = ring::signature::UnparsedPublicKey::new(&ED25519, public_key);
    peer_public_key.verify(data, &sig_bytes).is_ok()
}
