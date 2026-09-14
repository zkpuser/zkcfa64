fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let preflight = match arguments.as_slice() {
        [] => false,
        [argument] if argument == "--preflight" => true,
        _ => return Err("usage: zkcfa [--preflight]".into()),
    };
    zkcfa::run(preflight)?;

    Ok(())
}
