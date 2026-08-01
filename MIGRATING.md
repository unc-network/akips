# Upgrading to akips 1.0

Version 1.0.0 settles return shapes that used to disagree with each other, and
changes how the client is given its credentials. The changes are gathered into
one release deliberately, so there is one upgrade rather than several.

From 1.0.0 onward a breaking change requires a major version, so this is the
last time an upgrade should look like this.

If you are coming from 0.5.x or earlier, read the Python version note at the
bottom first.

## The short version

| What you have | What it becomes |
| --- | --- |
| `AKIPS(host, password=pw)` | `AKIPS(host, ro_password=pw)` |
| `device["sys"]["ip4addr"]` | `device["TH840-A"]["sys"]["ip4addr"]` |
| `device["name"]` | the key of the outer dictionary |
| `entry["child"][0]` | `entry["child"]` |
| `attributes["x"] == ""` | `attributes["x"] is None` |
| `if api.get_unreachable() == {}` | `if api.get_unreachable() is None` |
| `api.get_msg(time=..., type=...)` | `api.get_msg(period=..., msg_type=...)` |
| `api.cmd("mget ...")` | `api.call("mget ...")` |

## Credentials

AKiPS ships two API accounts and its sections do not all accept the same one.
`api-script` requires `api-rw`, `api-msg` requires `api-ro`, and `api-db` takes
either. A client used to hold one credential, so reaching the whole API meant
building two clients and knowing which was which.

```py
# before
reader = AKIPS('akips.example.com', username='api-ro', password=ro_pw)
writer = AKIPS('akips.example.com', username='api-rw', password=rw_pw)
reader.get_msg()
writer.set_group_membership('dev', 'maintenance_mode', 'assign')

# after
api = AKIPS('akips.example.com', ro_password=ro_pw, rw_password=rw_pw)
api.get_msg()
api.set_group_membership('dev', 'maintenance_mode', 'assign')
```

Each call now authenticates as the account its section requires. If you only
read data, `ro_password` alone is enough.

`username` and `password` still work and are not deprecated. Given `api-ro` or
`api-rw` they fill that account, so a single-purpose client needs no change at
all. Given any other name, that pair is used for every section, which is how to
use a custom AKiPS API account.

Two behaviours are new here:

- Constructing a client with no password at all raises `AkipsCredentialError`.
  Such a client could never have authenticated, so this turns a confusing
  server rejection into an error at the point of the mistake.
- Calling something whose account has no password raises
  `AkipsCredentialError` before any request, naming the section, the account
  and the argument to pass.

`AkipsCredentialError` subclasses both `AkipsError` and `ValueError`, so
existing `except` clauses for either still catch it.

## `get_device()` is keyed by device name

It used to drop the device level and put the name back as a `"name"` key beside
the child dictionaries, so iterating the result hit a string where every other
value was a dictionary.

```py
# before
device = api.get_device('TH840-A')
device['sys']['ip4addr']        # '192.168.20.15'
device['name']                  # 'TH840-A'

# after
device = api.get_device('TH840-A')
device['TH840-A']['sys']['ip4addr']     # '192.168.20.15'
next(iter(device))                      # 'TH840-A'
```

The result now keeps the parent, child and attribute levels AKiPS stores, which
is the same shape `get_devices()` and `get_attributes()` return. If you were
looping over it, the special case for `"name"` can go:

```py
# before
for child, attributes in device.items():
    if child == 'name':
        continue
    ...

# after
for child, attributes in device['TH840-A'].items():
    ...
```

`get_device()` also returns `None` when a reply parses to nothing, instead of a
dictionary holding only the name you asked for. If you were checking whether a
device was found by inspecting the other keys, `is None` is now enough.

## Absent attribute values are `None`

An attribute AKiPS returns with nothing after the equals sign now reads as
`None` from every method. `get_device()` used to give `""` for the same input
while `get_attributes()` gave `None`.

```py
# before
if device['Ethernet1']['IF-MIB.ifAlias'] == '':

# after
if device['TH840-A']['Ethernet1']['IF-MIB.ifAlias'] is None:
```

`get_devices()` used to drop such a line entirely, which could leave a device
out of its own listing when every attribute it reported was empty. It now
appears with `None` values.

## `get_unreachable()`

Two changes.

`child` is the matched string rather than a one element tuple:

```py
# before
entry['child'][0]       # 'ping4'

# after
entry['child']          # 'ping4'
```

And an empty result is `None` rather than `{}`, matching every other method:

```py
# before
down = api.get_unreachable()
for name in down:               # an empty dict just skipped the loop
    ...

# after
down = api.get_unreachable()
if down:                        # None when nothing is down
    for name in down:
        ...
```

That second one is worth grepping for. Iterating the result directly now raises
`TypeError` on a quiet network, which is the moment you least want a new
failure. `if down:` handles both cases.

## `get_msg()` parameter names

```py
# before
api.get_msg(time='last1h', type='syslog')

# after
api.get_msg(period='last1h', msg_type='syslog')
```

`type` shadowed a builtin and `time` a standard library module. `period` is
what every other method here already calls a time filter. The request AKiPS
receives is unchanged; only the Python argument names differ.

## `cmd()` is deprecated

`call()` replaces it. `cmd()` still works and still returns the reply unparsed,
but raises a `DeprecationWarning` and will be removed in a future major release.

```py
# before
text = api.cmd('mget * TH840-A * *')

# after
text = api.call('mget * TH840-A * *')
```

`call()` reaches any API section rather than only `api-db`, and can parse the
reply rather than only returning it raw:

```py
api.call('mget * TH840-A * *', output='attributes')
api.call(section='api-msg', params={'time': 'last1h'}, output='lines')
```

## If you subclassed to change the timeout

`_get()` no longer takes a `timeout` argument; it reads the client's. The
subclass is no longer needed:

```py
# before
class MyAKIPS(AKIPS):
    def _get(self, section='api-db', params=None, timeout=5):
        return super()._get(section, params, timeout)

# after
api = AKIPS('akips.example.com', ro_password=pw, timeout=5)
```

It can also be changed on an existing client with `api.timeout = 60`.

## Worth adopting while you are here

Not required, but this release makes them possible.

- **Type checking.** The package ships a `py.typed` marker, so mypy and
  pyright now read its annotations instead of treating everything as `Any`. If
  you have `akips` in an `ignore_missing_imports` override, remove it.
- **A CA bundle instead of `verify=False`.** `verify` accepts a path, which is
  how to trust a server whose certificate chain is missing an intermediate
  without turning verification off: `AKIPS(host, ro_password=pw,
  verify='/etc/ssl/akips-ca.pem')`.
- **Catching configuration errors separately.** `AkipsCredentialError` is
  raised before any request, so it can be caught at startup and reported as a
  settings problem rather than a monitoring outage.

## Python version

1.0.0 requires Python 3.10 or newer. The floor moved from 3.9 in 0.6.0, when
Python 3.9 reached end of life and every dependency with a security fix had
already moved past it.

## Rotate your AKiPS password

Every release before 1.0.0 wrote the password into the log and into any
traceback rendered when a request failed. AKiPS authenticates by query string,
and the underlying HTTP library reports the URL it was fetching in its error
messages. If you have ever seen a failed request from this client, treat that
password as exposed.
