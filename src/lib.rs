pub mod utils;
pub use utils::client::{Consts, Options, spawn_connector};

pub fn get_version() -> u32 {
    parse_version(env!("CARGO_PKG_VERSION"))
}

pub fn get_version_str(ver: &u32) -> String {
    let s3 = ver & 0b1111111111;
    let s2 = (ver >> 10) & 0b1111111111;
    let s1 = (ver >> 20) & 0b1111111111;

    format!("{s1}.{s2}.{s3}")
}

fn parse_version(ver: &str) -> u32 {
    ver.split('.')
        .fold(0, |acc, x| (acc << 10) + x.parse::<u32>().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple() {
        assert_eq!(parse_version("1.2.3"), (1 << 20) + (2 << 10) + 3);
    }

    #[test]
    fn test_bigger() {
        assert_eq!(parse_version("12.2.3"), (12 << 20) + (2 << 10) + 3);
    }

    #[test]
    fn test_gt() {
        assert_eq!(parse_version("12.2.3") > parse_version("1.22.3"), true);
    }

    #[test]
    fn test_lt() {
        assert_eq!(parse_version("12.2.3") < parse_version("12.22.3"), true);
    }

    #[test]
    fn test_convertback_simple() {
        assert_eq!(get_version_str(&parse_version("1.2.3")) == "1.2.3", true);
    }

    #[test]
    fn test_convertback_bigger() {
        assert_eq!(
            get_version_str(&parse_version("270.410.934")) == "270.410.934",
            true
        );
    }

    #[test]
    fn test_current_version() {
        assert_eq!(
            get_version_str(&get_version()) == env!("CARGO_PKG_VERSION"),
            true
        );
    }
}
