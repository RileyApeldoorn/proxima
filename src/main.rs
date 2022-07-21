use std::net::SocketAddr;
use hyper::{service::{make_service_fn, service_fn}, Client, Error, Server, Response, StatusCode, Body, Request, Uri};

#[tokio::main(flavor = "current_thread")]
async fn main() {

    // Load and parse the configuration
    let config = {

        // Prefer ./config over /etc/proxima
        let file = {
            ["./config", "/etc/proxima"]
                .iter()
                .map(load)
                .reduce(Result::or)
                .expect("Impossible")
        };

        file.map(parse)
            .expect("Loading the config failed.")

    };

    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

    let client = Client::new();

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        let config = config.clone();

        async move {
            // This is the `Service` that will handle the connection.
            // `service_fn` is a helper to convert a function that
            // returns a Response into a `Service`.
            Ok::<_, Error>(service_fn(move |mut req| {
                let config = config.clone();
                let client = client.clone();

                async move {
                    for Rule (pattern, effect) in config.rules() {
                        println!("{} {}", req.method(), req.uri());
                        if pattern.matches(&req) {
                            return match effect {
                                Effect::Proxy { port, .. } => {
                                    let host = "0.0.0.0"; // Support for custom hosts added later
                                    let path = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("");
                                    let target = format!("http://{host}:{port}{path}");

                                    let uri = target.parse().unwrap();
                                    *req.uri_mut() = uri;

                                    println!("Proxying to {target}");
                                    
                                    client.request(req).await
                                },
                                Effect::Redirect (uri) => Ok ({
                                    println!("Redirecting to {uri}");
                                    Response::builder()
                                        .status(StatusCode::PERMANENT_REDIRECT)
                                        .header("Location", uri)
                                        .body(Body::empty())
                                        .unwrap()
                                }),
                            }
                        }
                    }

                    Ok (Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::empty())
                        .unwrap())
                }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_service);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }

}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct Pattern {
    domain: String,
    ports: Ports,
}

impl Pattern {
    pub fn matches <T> (&self, req: &Request<T>) -> bool {
        let uri = req.uri();
        let (host, port) = {
            let host = req
                .headers()
                .get("host")
                .and_then(|x| x.to_str().ok())
                .and_then(|x| x.parse::<Uri>().ok());

            let h = uri
                .host()
                .map(|x| x.to_string())
                .or_else(|| {
                    host.clone().and_then(|x| {
                        x.host().map(|x| x.to_string())
                    })
                });

            let p = uri
                .port_u16()
                .or_else(|| {
                    host.and_then(|x| x.port_u16())
                });

            (h, p)
        };
        
        match host {
            Some (h) if &h == &self.domain => match &self.ports {
                Ports::Any => true,
                spec => match port {
                    Some (p) => spec.includes(p),
                    None => false,
                }
            },
            _ => false,
        }

    }
}

#[derive(Clone, Debug)]
pub enum Effect {
    Redirect (String),
    Proxy {
        port: u16,
        ssl: bool,
    },
}

impl Effect {
    pub async fn perform (&self) -> Response<Body> {
        todo!()
    }
}

#[derive(Clone, Debug)]
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

/// A config consists of a set if [`Rule`].
#[derive(Clone, Debug)]
pub struct Config (Vec<Rule>);

impl Config {
    pub fn rules (&self) -> impl Iterator <Item = &Rule> {
        self.0.iter()
    }
}

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
        let spaced = |x| seq::delimited(chr::space1, x, chr::space1);
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

