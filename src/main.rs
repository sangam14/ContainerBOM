use std::collections::HashMap;
use std::fs::{self, File, read_dir};
use std::io::{Read, Write};
use std::path::Path;
use clap::{Arg, Command};
use bollard::Docker;
use bollard::image::{CreateImageOptions, BuildImageOptions};
use bollard::models::BuildInfo;
use futures_util::stream::StreamExt;
use tokio::runtime::Runtime;
use serde::{Serialize, Deserialize};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use ring::rand::SystemRandom;
use data_encoding::BASE64;
use dockerfile_parser::{Dockerfile, Instruction, ShellOrExecExpr};
use tar::Builder;
use hyper::body::Bytes;

#[derive(Debug, Serialize, Deserialize)]
struct Layer {
    layer_id: String,
    created: String,
    os_guess: String,
    pkg_format: String,
    packages: Vec<Package>,
    notices: Vec<Notice>,
    analyzed_output: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Package {
    name: String,
    version: String,
    source: String,
    license: String,
    vendor: String,
    checksum: String,
}

#[derive(Debug, Serialize, Deserialize)]
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
                        .help("Output format: list, json, spdx")
                        .value_parser(["list", "json", "spdx"])
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

async fn analyze_image(_image_name: &str) -> Vec<Layer> {
    // Mock implementation, replace with actual logic to analyze image layers
    vec![
        Layer {
            layer_id: "sha256:layer1".to_string(), // Mocked value
            created: "2024-07-06T00:00:00Z".to_string(), // Mocked value
            os_guess: "linux".to_string(),
            pkg_format: "deb".to_string(),
            packages: vec![
                Package {
                    name: "package1".to_string(),
                    version: "1.2.3".to_string(),
                    source: "https://example.com/package1".to_string(),
                    license: "MIT".to_string(),
                    vendor: "Example Vendor".to_string(),
                    checksum: "sha256:abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                },
                Package {
                    name: "package2".to_string(),
                    version: "4.5.6".to_string(),
                    source: "https://example.com/package2".to_string(),
                    license: "Apache-2.0".to_string(),
                    vendor: "Another Vendor".to_string(),
                    checksum: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc".to_string(),
                },
            ],
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
