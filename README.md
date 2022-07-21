# Proxima

Proxima is a simple gateway server.

## Configuring

Proxima reads the first config file it sees in the following order of preference:

- `./config`
- `/etc/proxima`

In these files, each line is a rule consisting of a pattern (consisting of a
hostname and a portspec) and an effect: either a number indicating a port on
`0.0.0.0` to proxy the request to or a string that is used as the `location`
header's value. If the latter effect is specified, Proxima redirects clients
to that location.
