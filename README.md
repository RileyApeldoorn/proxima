# Proxima

Proxima is a simple gateway server. It supports reverse proxying to a different
port on `0.0.0.0` and responding to requests with a `308 Permanent Redirect`
response code.

## Configuring

Proxima reads the first config file it sees in the following order of preference:

- `./config`
- `/etc/proxima`

In these files, each line is a rule consisting of a pattern (consisting of a
hostname and a portspec) and an effect: either a number indicating a port on
`0.0.0.0` to proxy the request to or a string that is used as the `location`
header's value. If the latter effect is specified, Proxima redirects clients
to that location.

### Examples

The following config defines two rules: the first one redirects all requests
to `git.riley.lgbt` to `https://im.badat.dev`. The second rule passes each
request to `riley.lgbt` to port `3000`.

```
git.riley.lgbt : * ==> https://im.badat.dev
    riley.lgbt : * --> 3000
```
