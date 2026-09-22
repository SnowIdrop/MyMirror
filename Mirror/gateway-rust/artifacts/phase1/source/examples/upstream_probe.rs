fn main() {
    match mirror_gateway::config::Config::from_env() {
        Ok(config) => println!("accepted django={} chat={}", config.django, config.upstream),
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    }
}
