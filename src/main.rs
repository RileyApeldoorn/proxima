use std::{net::SocketAddr, convert::Infallible};

use hyper::{Client, Server, service::{make_service_fn, service_fn}, body::HttpBody, Body, Response, Request, Method, http, upgrade::{self, Upgraded}};
use tokio::net::TcpStream;

// https://github.com/hyperium/hyper/blob/master/examples/gateway.rs
// https://en.wikipedia.org/wiki/Gateway_(telecommunications)

#[tokio::main(flavor = "current_thread")]
async fn main() {

    // Load and parse the configuration
    let config = {

        // Prefer ./config over /etc/proxima
        let file = unsafe {
            ["./config", "/etc/proxima"]
                .iter()
                .map(load)
                .reduce(Result::or)
                .unwrap_unchecked()
        };

        file.map(parse)
            .expect("Loading the config failed.")

    };

    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));
}

pub struct Rule (Pattern, Effect);

impl Rule {
    /// Get the domain of the pattern.
	pub fn domain (&self) -> &str {
		&self.0.domain
	}

	/// Get the portspec
	pub fn ports (&self) -> &Ports {
		&self.0.ports
	}

	pub fn effect (&self) -> &Effect {
		&self.1
	}
}

pub struct Pattern {
    domain: String,
    ports: Ports,
}

pub enum Effect {
    Redirect (String),
    Proxy {
        port: u16,
        ssl: bool,
    },
}

impl Effect {
	pub async fn perform (&self) -> std::io::Result<()> {
    	todo!()
	}
}

pub enum Ports {
    Single (u16),
    Either (Vec<u16>),
    Any
}

impl Ports {
	/// Whether this set of ports includes the given port.
    pub fn includes (&self, p: u16) -> bool {
		match self {
			Ports::Single (x) => *x == p,
			Ports::Either (l) => l.contains(&p),
			Ports::Any => true,
		}
	}
}

pub mod parse {

    use super::{ Ports, Effect, Pattern, Rule };
    use nom::{
        sequence as seq,
        multi as mul,
        character::complete as chr,
        bytes::complete::{self as byt, tag, take_till},
        Parser, error::ParseError, combinator::opt,
    };

    pub type PResult<'i, T> = nom::IResult<&'i str, T>;

    fn around <I, O, P, E, A, B> (a: A, b: B) -> impl Parser<I, O, E>
    where E: ParseError<I>,
          A: Parser<I, P, E> + Clone,
          B: Parser<I, O, E>,
    {
        seq::delimited(a.clone(), b, a)
    }

    /// Parse a [`Portspec`].
    pub (super) fn portspec (s: &str) -> PResult<'_, Ports> {
        let single = chr::u16;
        let either = {
            let delim = around(chr::space1, chr::char('|'));
            seq::delimited(
                chr::char('('),
                mul::separated_list1(delim, single),
                chr::char(')'),
            )
        };
        let any = byt::tag("any");

        let single = single.map(Ports::Single);
        let either = either.map(Ports::Either);
        let any    = any.map(|_| Ports::Any);

        single.or(either)
              .or(any)
              .parse(s)
    }

	/// Parse an [`Effect`].
    pub fn effect (s: &str) -> PResult<'_, Effect> {

        let redirect = {
            let spaced = |x| seq::delimited(chr::space1, x, chr::space1);
            let internal = domain;

            seq::preceded(
                spaced(tag("==>")),
                internal,
            ).map(Effect::Redirect)
        };

        let proxy = {
            let spaced = |x| seq::delimited(chr::space1, x, chr::space1);
            let ssl = opt(seq::delimited(
                seq::preceded(chr::space1, chr::char('[')),
                tag("ssl"),
                chr::char(']'),
            )).map(|o| o.is_some());
            let internal = seq::terminated(chr::u16, chr::space0);

            seq::preceded(
                spaced(tag("-->")),
                internal.and(ssl),
            ).map(|(port, ssl)| Effect::Proxy { ssl, port })
        };

        redirect.or(proxy)
                .parse(s)

    }

    fn domain (s: &str) -> PResult<'_, String> {
        take_till(|c: char| !(c == '.' || c.is_alphanumeric()))
            .map(str::to_string)
            .parse(s)
    }

	/// Parse a [`Pattern`].
	///
	/// ```
	/// use proxima::parse;
	///
	/// # fn main () -> parse::PResult<'static, ()> {
	/// let (_, pattern) = parse::pattern("example.com : any")?;
	/// # Ok ("", ())
	/// # }
	/// ```
    pub fn pattern (s: &str) -> PResult<'_, Pattern> {
        let spaced = |x| seq::delimited(chr::char(' '), x, chr::char(' '));
		seq::separated_pair(domain, spaced(chr::char(':')), portspec)
    		.map(|(domain, ports)| Pattern { domain, ports })
    		.parse(s)
    }

	/// Parse a [`Rule`].
    pub fn rule (s: &str) -> PResult<'_, Rule> {
        pattern.and(effect)
               .map(|(p, e)| Rule (p, e))
               .parse(s)
    }

    #[cfg(test)]
    mod tests {

        use super::*;

		/// Test whether a pattern containing an Any portspec gets parsed
		/// correctly.
		#[test]
		fn simple_pattern () {
    		let input = "example.com : any";
			let (_, Pattern { domain, ports }) = pattern(input).unwrap();
			assert!(domain == "example.com");
			assert!(match ports {
				Ports::Any => true,
				_ => false,
			})
		}

		/// Test whether an Either portspec is parsed correctly.
		#[test]
		fn either_portspec () {
    		let input = "(69 | 420)";
			assert!(match portspec(input).unwrap() {
				("", Ports::Either(p)) => p == [69, 420],
				_ => false,
			})
		}

		/// Test whether domain names are parsed correctly.
		#[test]
		fn domains () {
    		let inputs = ["example.com", "im.badat.dev", "riley.lgbt", "toot.site", "a.b.c.d.e.f.g.h"];
    		// Each of these should be considered valid
    		for input in inputs {
        		domain(input).unwrap();
    		}
		}

		/// Test whether a simple rule gets parsed correctly.
		#[test]
		fn simple_rule () {
    		let input = "example.gay : any --> 3000";
    		let (_, Rule (_, effect)) = rule(input).unwrap();
    		assert!(match effect {
				Effect::Proxy { port: 3000, ssl } if !ssl => true,
    		    _ => false,
    		});
		}
    }

}

/// A config consists of a set if [`Rule`].
pub struct Config (Vec<Rule>);

/// Load a config from a path.
pub fn load (p: impl AsRef<std::path::Path>) -> std::io::Result<String> {
    std::fs::read_to_string(p.as_ref())
}

/// Parse a config string.
///
/// Example config string:
///
/// ```text
/// hmt.riley.lgbt : (80 | 443) --> 6000           # --> is proxy_pass
///     riley.lgbt : (80 | 443) --> 3000 [ssl]     # add [ssl] to automate ssl for this domain
///     rly.cx     : any        ==> riley.lgbt     # ==> is HTTP redirect
/// ```
pub fn parse (data: String) -> Config {
	let rules = data
    	.lines()
    	.map(parse::rule)
    	.filter_map(|x| match x {
            Ok ((_, rule)) => Some (rule),
            Err (e) => {
                eprintln!("Error parsing rule: {:?}", e);
                None
            },
    	})
    	.collect();

	Config (rules)
}
