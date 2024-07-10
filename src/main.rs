use std::collections::HashMap;
use std::fs::{self, File, read_dir};
use std::io::{Read, Write, BufRead, BufReader};
use std::path::Path;
use clap::{Arg, Command};
use bollard::Docker;
use bollard::image::{CreateImageOptions, BuildImageOptions};
use bollard::models::{BuildInfo, ImageInspect};
use futures_util::stream::StreamExt;
use tokio::runtime::Runtime;
use serde::{Serialize, Deserialize};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use ring::rand::SystemRandom;
use data_encoding::BASE64;
use dockerfile_parser::{Dockerfile, Instruction, ShellOrExecExpr};
use tar::Builder;
use hyper::body::Bytes;
use tar::Archive;
use sha2::{Sha256, Digest};
use tempfile::tempdir;
use prettytable::{Table, row}; // Removed unused `cell` import
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Layer {
    layer_id: String,
    created: String,
    os_guess: String,
    pkg_format: String,
    packages: Vec<Package>,
    files: Vec<FileMetadata>,
    notices: Vec<Notice>,
    analyzed_output: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Package {
    name: String,
    version: String,
    source: String,
    license: String,
    vendor: String,
    checksum: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FileMetadata {
    path: String,
    size: u64,
    file_type: String,
    checksum: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Notice {
    message: String,
    level: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Sbom {
    sbom_version: String,
    spdx_id: String,
    name: String,
    namespace: String,
    creation_info: CreationInfo,
    image_name: String,
    image_digest: String,
    layers: Vec<Layer>,
    dockerfile_analysis: Option<DockerfileAnalysis>,
    signature: Option<String>,
    metadata: Metadata,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreationInfo {
    created: String,
    creators: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DockerfileAnalysis {
    envs: HashMap<String, String>,
    instructions: Vec<String>,
    packages: Vec<Package>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    tool: String,
    version: String,
    authors: Vec<String>,
    organization: String,
}

fn main() {
    let matches = Command::new("CBOM")
        .version("1.0")
        .about("Container Software Bill of Materials (SBOM) generator")
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
                    Arg::new("format")
                        .short('f')
                        .long("format")
                        .value_name("FORMAT")
                        .help("Output format: list, json, spdx, table")
                        .value_parser(["list", "json", "spdx", "table"])
                        .default_value("json"),
                ),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify the SBOM with the given key")
                .arg(
                    Arg::new("sbom")
                        .short('i')
                        .long("sbom")
                        .value_name("FILE")
                        .help("Input SBOM file to verify")
                        .value_parser(clap::value_parser!(String))
                        .required(true),
                )
                .arg(
                    Arg::new("key")
                        .short('k')
                        .long("key")
                        .value_name("KEY")
                        .help("Key to verify the SBOM")
                        .value_parser(clap::value_parser!(String))
                        .required(true),
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
        let output_format = matches.get_one::<String>("format").unwrap();

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut sbom = Sbom {
                sbom_version: "1.0".to_string(),
                spdx_id: "SPDXRef-DOCUMENT".to_string(),
                name: "Example Container SBOM".to_string(),
                namespace: "https://example.com/sbom".to_string(),
                creation_info: CreationInfo {
                    created: "2024-07-06T00:00:00Z".to_string(),
                    creators: vec![
                        "Tool: Container SBOM Generator v1.0".to_string(),
                        "Organization: Example Org".to_string(),
                    ],
                },
                image_name: image_name.clone(),
                image_digest: "sha256:abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(), // Mocked value
                layers: Vec::new(),
                dockerfile_analysis: None,
                signature: None,
                metadata: Metadata {
                    tool: "Container SBOM Generator".to_string(),
                    version: "1.0".to_string(),
                    authors: vec!["Your Name <you@example.com>".to_string()],
                    organization: "Example Org".to_string(),
                },
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
                println!("Signing SBOM with key: {}", key_path); // Debug statement
                let key_pair = load_keypair_from_file(key_path);
                let sbom_json = serde_json::to_string(&sbom).unwrap();
                let signature = sign_data(&key_pair, sbom_json.as_bytes());
                sbom.signature = Some(signature);
                println!("SBOM signed: {:?}", sbom.signature); // Debug statement
            }

            match output_format.as_str() {
                "json" => {
                    if let Some(output) = output_file {
                        save_sbom_to_file(&sbom, output);
                    } else {
                        println!("{}", serde_json::to_string_pretty(&sbom).unwrap());
                    }
                },
                "list" => {
                    let packages: Vec<&Package> = sbom.layers.iter().flat_map(|layer| &layer.packages).collect();
                    for package in packages {
                        println!("{} {} {} {} {} {}", package.name, package.version, package.source, package.license, package.vendor, package.checksum);
                    }
                },
                "spdx" => {
                    let spdx_output = generate_spdx(&sbom);
                    if let Some(output) = output_file {
                        let mut file = File::create(output).expect("Unable to create file");
                        file.write_all(spdx_output.as_bytes()).expect("Unable to write data");
                    } else {
                        println!("{}", spdx_output);
                    }
                },
                "table" => {
                    display_sbom_table(&sbom);
                },
                _ => unreachable!(),
            }
        });
    }

    if let Some(matches) = matches.subcommand_matches("verify") {
        let sbom_file = matches.get_one::<String>("sbom").unwrap();
        let key_path = matches.get_one::<String>("key").unwrap();

        let mut sbom_json = String::new();
        File::open(sbom_file).and_then(|mut file| file.read_to_string(&mut sbom_json)).unwrap();

        let sbom: Sbom = serde_json::from_str(&sbom_json).unwrap();
        if let Some(signature) = &sbom.signature {
            println!("Verifying SBOM with key: {}", key_path); // Debug statement
            let key_pair = load_keypair_from_file(key_path);
            let public_key = key_pair.public_key().as_ref();

            // Debug prints
            println!("Public Key: {:?}", public_key);
            println!("SBOM JSON: {}", sbom_json);
            println!("Signature: {}", signature);

            // Verify the signature using the raw SBOM JSON bytes
            let sbom_without_signature = serde_json::to_string(&Sbom {
                signature: None,
                ..sbom
            }).unwrap();

            if verify_signature(public_key, sbom_without_signature.as_bytes(), signature) {
                println!("Signature verification succeeded.");
            } else {
                println!("Signature verification failed.");
            }
        } else {
            println!("No signature found to verify.");
        }
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

            let pb = ProgressBar::new(100);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .expect("Error setting progress bar template")
                .progress_chars("#>-"));

            while let Some(result) = stream.next().await {
                result?;
                pb.inc(1);
            }
            pb.finish_with_message("Image download complete.");
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

    let pb = ProgressBar::new(100);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .expect("Error setting progress bar template")
        .progress_chars("#>-"));

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
        pb.inc(1);
    }
    pb.finish_with_message("Image build complete.");
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
    
    // Add all files in the same directory as the Dockerfile to the tarball
    let parent_dir = Path::new(dockerfile_path).parent().unwrap_or(Path::new("."));
    for entry in read_dir(parent_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            builder.append_path_with_name(&path, path.file_name().unwrap())?;
        }
    }

    builder.finish()?;
    Ok(tar_path.to_string())
}

async fn analyze_image(image_name: &str) -> Vec<Layer> {
    let docker = Docker::connect_with_local_defaults().unwrap();
    let image_inspect: ImageInspect = docker.inspect_image(image_name).await.unwrap();

    let layers = image_inspect.root_fs.unwrap().layers.unwrap_or_default();
    let mut analyzed_layers = Vec::new();

    let temp_dir = tempdir().unwrap();
    for layer in layers {
        let layer_id = layer.clone();
        let created = image_inspect.created.clone().unwrap_or_else(|| "Unknown".to_string());
        let os_guess = image_inspect.os.clone().unwrap_or_else(|| "Unknown".to_string());

        let tarball_path = temp_dir.path().join(format!("{}.tar", layer_id));
        let mut tarball_file = File::create(&tarball_path).unwrap();

        let mut export_stream = docker.export_image(image_name);
        while let Some(chunk) = export_stream.next().await {
            match chunk {
                Ok(bytes) => tarball_file.write_all(&bytes).unwrap(),
                Err(e) => eprintln!("Error exporting image: {}", e),
            }
        }

        let tar_file = File::open(&tarball_path).unwrap();
        let mut archive = Archive::new(tar_file);

        let mut files = Vec::new();
        for file in archive.entries().unwrap() {
            let mut file = file.unwrap();
            let path = file.path().unwrap().display().to_string();
            let size = file.size();
            let file_type = match file.header().entry_type().is_file() {
                true => "file".to_string(),
                false => "dir".to_string(),
            };

            // Calculate file checksum (e.g., SHA256)
            let mut hasher = Sha256::new();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            hasher.update(&buffer);
            let checksum = format!("{:x}", hasher.finalize());

            files.push(FileMetadata {
                path,
                size,
                file_type,
                checksum,
            });
        }

        // Identify packages
        let packages = analyze_layer_for_packages(&tarball_path);

        // Perform analysis on each layer
        let analyzed_layer = Layer {
            layer_id: layer_id.clone(),
            created,
            os_guess,
            pkg_format: "apk".to_string(), // Assuming Alpine package format
            packages,
            files,
            notices: vec![
                Notice {
                    message: "Example notice".to_string(),
                    level: "info".to_string(),
                },
            ],
            analyzed_output: "Example analysis output".to_string(),
        };

        analyzed_layers.push(analyzed_layer);
    }

    analyzed_layers
}

fn analyze_layer_for_packages(layer_path: &Path) -> Vec<Package> {
    let mut packages = Vec::new();

    let apk_db_path = layer_path.join("lib/apk/db/installed");
    if apk_db_path.exists() {
        let file = File::open(apk_db_path).unwrap();
        let reader = BufReader::new(file);

        let mut package = Package {
            name: String::new(),
            version: String::new(),
            source: String::new(),
            license: String::new(),
            vendor: String::new(),
            checksum: String::new(),
        };

        for line in reader.lines() {
            let line = line.unwrap();
            if line.starts_with("P:") {
                package.name = line[2..].to_string();
            } else if line.starts_with("V:") {
                package.version = line[2..].to_string();
            } else if line.starts_with("L:") {
                package.license = line[2..].to_string();
            } else if line.starts_with("o:") {
                package.vendor = line[2..].to_string();
            } else if line.starts_with("t:") {
                package.source = line[2..].to_string();
            } else if line.is_empty() {
                if !package.name.is_empty() {
                    packages.push(package.clone());
                }
            }
        }
    }

    packages
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
                for env_var in &env_line.vars {
                    envs.insert(env_var.key.to_string(), env_var.value.to_string());
                }
            }
            Instruction::Run(run_line) => {
                match &run_line.expr {
                    ShellOrExecExpr::Shell(command) => {
                        for cmd in command.to_string().split("&&") {
                            let pkgs = cmd.split_whitespace().map(|s| s.to_string()).collect::<Vec<String>>();
                            // You can replace this with actual logic to determine package details
                            let package = Package {
                                name: pkgs.join(" "), // Mocking package name
                                version: "unknown".to_string(),
                                source: "unknown".to_string(),
                                license: "unknown".to_string(),
                                vendor: "unknown".to_string(),
                                checksum: "unknown".to_string(),
                            };
                            packages.push(package);
                        }
                    },
                    ShellOrExecExpr::Exec(commands) => {
                        for cmd in commands.elements.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(" ").split("&&") {
                            let pkgs = cmd.split_whitespace().map(|s| s.to_string()).collect::<Vec<String>>();
                            // You can replace this with actual logic to determine package details
                            let package = Package {
                                name: pkgs.join(" "), // Mocking package name
                                version: "unknown".to_string(),
                                source: "unknown".to_string(),
                                license: "unknown".to_string(),
                                vendor: "unknown".to_string(),
                                checksum: "unknown".to_string(),
                            };
                            packages.push(package);
                        }
                    }
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
    let peer_public_key = UnparsedPublicKey::new(&ED25519, public_key);
    peer_public_key.verify(data, &sig_bytes).is_ok()
}

fn generate_spdx(sbom: &Sbom) -> String {
    let mut spdx = format!(
        "SPDXVersion: SPDX-2.2\nDataLicense: CC0-1.0\nSPDXID: {}\n",
        sbom.spdx_id
    );
    spdx.push_str(&format!(
        "DocumentName: {}\nDocumentNamespace: {}\n",
        sbom.name, sbom.namespace
    ));
    spdx.push_str(&format!(
        "Creator: {}\nCreated: {}\n\n",
        sbom.creation_info.creators.join(", "),
        sbom.creation_info.created
    ));
    for layer in &sbom.layers {
        for package in &layer.packages {
            spdx.push_str(&format!(
                "PackageName: {}\nSPDXID: SPDXRef-{}\nPackageVersion: {}\nPackageSupplier: {}\nPackageDownloadLocation: {}\nFilesAnalyzed: true\nPackageLicenseConcluded: {}\nPackageChecksum: SHA256: {}\n\n",
                package.name, package.name, package.version, package.vendor, package.source, package.license, package.checksum
            ));
        }
    }
    spdx
}

fn display_sbom_table(sbom: &Sbom) {
    let mut table = Table::new();
    table.add_row(row!["Field", "Value"]);
    table.add_row(row!["SBOM Version", &sbom.sbom_version]);
    table.add_row(row!["SPDX ID", &sbom.spdx_id]);
    table.add_row(row!["Name", &sbom.name]);
    table.add_row(row!["Namespace", &sbom.namespace]);
    table.add_row(row!["Created", &sbom.creation_info.created]);
    table.add_row(row!["Creators", &sbom.creation_info.creators.join(", ")]);
    table.add_row(row!["Image Name", &sbom.image_name]);
    table.add_row(row!["Image Digest", &sbom.image_digest]);

    for (i, layer) in sbom.layers.iter().enumerate() {
        table.add_row(row![format!("Layer {}", i + 1), ""]);
        table.add_row(row!["  Layer ID", &layer.layer_id]);
        table.add_row(row!["  Created", &layer.created]);
        table.add_row(row!["  OS Guess", &layer.os_guess]);
        table.add_row(row!["  Package Format", &layer.pkg_format]);

        table.add_row(row!["  Packages", ""]);
        for package in &layer.packages {
            table.add_row(row!["    Name", &package.name]);
            table.add_row(row!["    Version", &package.version]);
            table.add_row(row!["    Source", &package.source]);
            table.add_row(row!["    License", &package.license]);
            table.add_row(row!["    Vendor", &package.vendor]);
            table.add_row(row!["    Checksum", &package.checksum]);
        }

        table.add_row(row!["  Files", ""]);
        for file in &layer.files {
            table.add_row(row!["    Path", &file.path]);
            table.add_row(row!["    Size", file.size.to_string()]);
            table.add_row(row!["    File Type", &file.file_type]);
            table.add_row(row!["    Checksum", &file.checksum]);
        }

        table.add_row(row!["  Notices", ""]);
        for notice in &layer.notices {
            table.add_row(row!["    Message", &notice.message]);
            table.add_row(row!["    Level", &notice.level]);
        }

        table.add_row(row!["  Analyzed Output", &layer.analyzed_output]);
    }

    table.add_row(row!["Dockerfile Analysis", &sbom.dockerfile_analysis.is_some().to_string()]);
    table.add_row(row!["Signature", &sbom.signature.clone().unwrap_or_else(|| "None".to_string())]);

    table.printstd();
}
