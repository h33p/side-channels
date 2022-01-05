use clap::*;
use log::Level;
use memflow::prelude::v1::{ErrorKind, Result, *};

fn main() -> Result<()> {
    let matches = parse_args();
    let (chain, log_level, process, symbol, module, address) = extract_args(&matches)?;

    simple_logger::SimpleLogger::new().init().unwrap();

    log::set_max_level(log_level.to_level_filter());

    // create connector + os
    let inventory = Inventory::scan();

    let os = inventory.builder().os_chain(chain).build()?;

    let mut process = os.into_process_by_name(process)?;

    let module = if let Some(module) = module {
        process.module_by_name(module)?
    } else {
        process.module_address_list_callback(None, (&mut |_| false).into())?;
        process.primary_module()?
    };

    let address = if let Some(address) = address {
        Address::from(address)
    } else {
        process
            .module_export_list(&module)?
            .into_iter()
            .inspect(|e| println!("{:?}", e))
            .filter(|e| e.name.as_ref() == symbol)
            .map(|e| module.base + e.offset)
            .next()
            .ok_or(ErrorKind::NotFound)?
    };

    println!("{:?} {:?}", module, address);

    let mut reads = 0;

    loop {
        reads += 1;
        std::thread::sleep(std::time::Duration::from_micros(2));
        let detections: usize = process.read(address)?;
        println!("{} | {} | {:x}", reads, detections, address);
    }
}

fn parse_args() -> ArgMatches<'static> {
    App::new("side-channel-attacker example")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::with_name("verbose").short("v").multiple(true))
        .arg(
            Arg::with_name("connector")
                .long("connector")
                .short("c")
                .takes_value(true)
                .required(false)
                .multiple(true),
        )
        .arg(
            Arg::with_name("os")
                .long("os")
                .short("o")
                .takes_value(true)
                .required(true)
                .multiple(true),
        )
        .arg(
            Arg::with_name("process")
                .long("process")
                .short("p")
                .takes_value(true)
                .default_value("side-channel-client"),
        )
        .arg(
            Arg::with_name("module")
                .long("module")
                .short("m")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("symbol")
                .long("symbol")
                .short("s")
                .takes_value(true)
                .default_value("SC_BUFFER"),
        )
        .arg(
            Arg::with_name("address")
                .long("address")
                .short("a")
                .takes_value(true),
        )
        .get_matches()
}

fn extract_args<'a>(
    matches: &'a ArgMatches,
) -> Result<(
    OsChain<'a>,
    log::Level,
    &'a str,
    &'a str,
    Option<&'a str>,
    Option<umem>,
)> {
    // set log level
    let level = match matches.occurrences_of("verbose") {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        4 => Level::Trace,
        _ => Level::Trace,
    };

    let conn_iter = matches
        .indices_of("connector")
        .zip(matches.values_of("connector"))
        .map(|(a, b)| a.zip(b))
        .into_iter()
        .flatten();

    let os_iter = matches
        .indices_of("os")
        .zip(matches.values_of("os"))
        .map(|(a, b)| a.zip(b))
        .into_iter()
        .flatten();

    Ok((
        OsChain::new(conn_iter, os_iter)?,
        level,
        matches.value_of("process").unwrap(),
        matches.value_of("symbol").unwrap(),
        matches.value_of("module"),
        matches
            .value_of("address")
            .and_then(|o| umem::from_str_radix(o, 16).ok()),
    ))
}
