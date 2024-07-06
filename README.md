# ContainerBOM


Container Supply Chain Security with ContainerBOM written in Rust 


> this tool is under developement don't use in production 

```
Container Software Bill of Materials (SBOM) generator

Usage: cbom [COMMAND]

Commands:
  generate-key  Generate a new Ed25519 keypair
  analyze       Analyze a Docker image and generate SBOM
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

#### Analyze a Docker image and generate SBOM
```
Usage: cbom analyze [OPTIONS] <IMAGE>

Arguments:
  <IMAGE>  Docker image to analyze

Options:
  -o, --output <FILE>      Output file for the SBOM
  -d, --dockerfile <FILE>  Dockerfile to analyze and build
  -b, --build              Build Docker image from Dockerfile
  -t, --tag <NAME>         Tag for the Docker image
  -s, --sign <KEY>         Sign the SBOM with the given key
  -v, --verify <KEY>       Verify the SBOM with the given key
  -h, --help               Print help
```

#### Generate a new Ed25519 keypair

```
cargo run -- generate-key -o sangam.pem
```

#### Dockefile to SBOM with Customtag 

```
cargo run -- analyze -d ./Dockerfile -b -t customtag -o sbom_with_customtag.json mydockerimagename
```
#### Docker image to SBOM 
```
 cargo run -- analyze busybox:latest
```
#### Signing an SBOM
```
cargo run -- generate-key -o mykeypair.pem
Generate and Sign the SBOM:


cargo run -- analyze -d ./example/Dockerfile -b -t customtag -o sbom_with_customtag.json -s mykeypair.pem mydockerimagename 




cargo run -- verify -i sbom_with_customtag.json -k mykeypair.pem
```