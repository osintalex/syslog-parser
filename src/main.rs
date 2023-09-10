use crate::parser::SysLogParser;
use simple_logger::SimpleLogger;
mod parser;

fn main() {
    SimpleLogger::new().init().unwrap();
    let my_parser = SysLogParser::new("syslog", "traffic.csv");
    my_parser.parse();
    log::info!("Successfully parsed logfile :-)");
}
