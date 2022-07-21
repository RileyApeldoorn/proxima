use std::net::SocketAddr;
use hyper::{service::{make_service_fn, service_fn}, Server, Response, StatusCode, Body, Request, Uri, client::HttpConnector, http};

pub mod parse;

/// An alias for a [`hyper::Client`] with an [`HttpConnector`].
pub type Client<C = HttpConnector> = hyper::Client<C>;

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

    let addr   = SocketAddr::from(([127, 0, 0, 1], 8100));
    let client = Client::new();

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        let config = config.clone();

        async move {
            // This is the `Service` that will handle the connection.
            // `service_fn` is a helper to convert a function that
            // returns a Response into a `Service`.
            Ok::<_, Error>(service_fn(move |req| {
                let config = config.clone();
                let client = client.clone();

                println!("{} {}", req.method(), req.uri());

                async move {

                    // Perform the first matching rule
                    for Rule (pattern, effect) in config.rules() {
                        if pattern.matches(&req) {
                            let res = effect.perform(client, req).await;
                            return res
                        }
                    }

                    println!("No matching rule found, returning error");

                    // Return an empty response with a Bad Gateway status code
                    // if no rules matched (and thus caused the loop to short-
                    // circuit).
                    let res = Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::empty())?;

                    Ok (res)

                }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_service);

    if let Err (e) = server.await {
        eprintln!("server error: {}", e);
    }

}

/// A config consists of a set of [`Rule`]s.
#[derive(Clone, Debug)]
pub struct Config (Vec<Rule>);

impl Config {
    /// Get the rules in the config.
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
/// api.riley.lgbt : (80 | 443) --> 6000           # --> is proxy_pass
///     riley.lgbt : (80 | 443) --> 3000 [ssl]     # add [ssl] to automate ssl for this domain
///     rly.cx     : *          ==> riley.lgbt     # ==> is HTTP redirect
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

/// Runtime errors.
#[derive(Debug)]
pub enum Error {
	Hyper (hyper::Error),
	Http (http::Error),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
			Error::Hyper (e) => e.fmt(f),
			Error::Http (e) => e.fmt(f),
        }
    }
}

impl From<hyper::Error> for Error {
    fn from (v: hyper::Error) -> Self { Self::Hyper(v) }
}

impl From<http::Error> for Error {
    fn from (v: http::Error) -> Self { Self::Http(v) }
}

/// A rule consists of a [`Pattern`] and an [`Effect`]. If the pattern matches,
/// the effect is performed.
#[derive(Clone, Debug)]
pub struct Rule (Pattern, Effect);

impl Rule {
    /// Get the domain of the pattern.
    pub fn host (&self) -> &str {
        &self.0.host
    }

    /// Get the portspec.
    pub fn ports (&self) -> &Ports {
        &self.0.ports
    }

    /// Get the associated effect.
    pub fn effect (&self) -> &Effect {
        &self.1
    }
}

/// A pattern consists of a host and a [portspec][Ports].
#[derive(Clone, Debug)]
pub struct Pattern {
    host: String,
    ports: Ports,
}

impl Pattern {

    /// Determine whether the given [`Request`] matches this pattern.
    ///
    /// For a request to match, it needs a `host` header.
    pub fn matches <T> (&self, req: &Request<T>) -> bool {
        let (host, port) = {
            // We need to parse the `host` header.
            if let Some (uri) = req
                .headers()
                .get("host")
                .and_then(|x| x.to_str().ok())
                .and_then(|x| x.parse::<Uri>().ok())
            {
                let host = uri.host().map(str::to_string);
                let port = uri.port_u16();
                (host, port.unwrap_or(80))
            } else {
                (None, 80)
            }
        };
        
        match host {
            // The domain needs to match in all cases
            Some (h) if &h == &self.host => match &self.ports {
                // We don't care about the port from the header if the
                // portspec is a wildcard
                Ports::Any => true,
                // Check if the port is included in the spec. If the
                // port couldn't be parsed, it defaults to `80`.
                spec => spec.includes(port),
            },
            // If no host header or the host header does not equal
            // the specified domain, the request does not match
            _ => false,
        }

    }

}

/// What to do with a matched request.
#[derive(Clone, Debug)]
pub enum Effect {
    /// Redirect to the given URI.
    Redirect (String),
    /// Proxy the request, optionally with managed SSL.
    Proxy {
        /// The port on `0.0.0.0` to proxy to.
        port: u16,
        /// Whether to manage SSL for this rule.
        ssl: bool,
    },
}

impl Effect {
    /// Perform the effect.
    pub async fn perform (&self, client: Client, mut req: Request<Body>) -> Result<Response<Body>, Error> {
        let res = match self {
            Effect::Proxy { port, .. } => {
                let host = "0.0.0.0"; // Support for custom hosts added later
                let path = req
                    .uri()
                    .path_and_query()
                    .map(|x| x.as_str())
                    .unwrap_or("");

                let uri = Uri::builder()
                    .authority(format!("{host}:{port}"))
                    .scheme("http")
                    .path_and_query(path)
                    .build()?;

                println!("Proxying to {uri}");

                *req.uri_mut() = uri;
                client.request(req).await?
            },
            Effect::Redirect (uri) => {
                println!("Redirecting to {uri}");
                Response::builder()
                    .status(StatusCode::PERMANENT_REDIRECT)
                    .header("Location", uri)
                    .body(Body::empty())?
            },
        };

        Ok (res)
    }
}

/// A specification of ports.
#[derive(Clone, Debug)]
pub enum Ports {
    /// Just this one port.
    Single (u16),
    /// Any of the specified ports.
    Either (Vec<u16>),
    /// Wildcard, skip port check.
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

