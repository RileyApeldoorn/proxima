//! Parsers for parts of the config file.

// TODO: comments

use super::{ Ports, Effect, Pattern, Rule };
use nom::{
    sequence as seq,
    multi as mul,
    character::complete as chr,
    bytes::complete::{self as byt, tag, take_till},
    Parser, error::ParseError, combinator::opt,
};

/// The result of running a parser.
pub type PResult<'i, T> = nom::IResult<&'i str, T>;

fn around <I, O, P, E, A, B> (a: A, b: B) -> impl Parser<I, O, E>
where E: ParseError<I>,
      A: Parser<I, P, E> + Clone,
      B: Parser<I, O, E>,
{
    seq::delimited(a.clone(), b, a)
}

/// Parse a set of [`Ports`].
pub fn ports (s: &str) -> PResult<'_, Ports> {
    let single = chr::u16;
    let either = {
        let delim = around(chr::space1, chr::char('|'));
        seq::delimited(
            chr::char('('),
            mul::separated_list1(delim, single),
            chr::char(')'),
        )
    };
    let any = byt::tag("*");

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

        seq::preceded(
            spaced(tag("==>")),
            target,
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

fn target (s: &str) -> PResult<'_, String> {
    take_till(|c: char| !(c == '.' || c.is_alphanumeric()))
        .map(str::to_string)
        .parse(s)
}

/// Parse a [`Pattern`].
pub fn pattern (s: &str) -> PResult<'_, Pattern> {
    let spaced = |x| seq::delimited(chr::space1, x, chr::space1);
    seq::separated_pair(target, spaced(chr::char(':')), ports)
        .map(|(domain, ports)| Pattern { host: domain, ports })
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
        let input = "example.com : *";
        let (_, Pattern { host: domain, ports }) = pattern(input).unwrap();
        assert!(domain == "example.com");
        assert!(match ports {
            Ports::Any => true,
            _ => false,
        })
    }

    /// Test whether an Either portspec is parsed correctly.
    #[test]
    fn either_ports () {
        let input = "(69 | 420)";
        assert!(match ports(input).unwrap() {
            ("", Ports::Either(p)) => p == [69, 420],
            _ => false,
        })
    }

    /// Test whether target names are parsed correctly.
    #[test]
    fn targets () {
        let inputs = ["example.com", "im.badat.dev", "riley.lgbt", "toot.site", "a.b.c.d.e.f.g.h"];
        // Each of these should be considered valid
        for input in inputs {
            target(input).unwrap();
        }
    }

    /// Test whether a simple rule gets parsed correctly.
    #[test]
    fn simple_rule () {
        let input = "example.gay : * --> 3000";
        let (_, Rule (_, effect)) = rule(input).unwrap();
        assert!(match effect {
            Effect::Proxy { port: 3000, ssl } if !ssl => true,
            _ => false,
        });
    }
}

