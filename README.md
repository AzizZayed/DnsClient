# DNS Client

## Usage

```
python DnsClient.py [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name
```

Example:
```shell
python DnsClient.py -t 5 -r 3 -p 53 @8.8.8.8 google.com
```

Use `python3` instead of `python` if you have multiple versions of python installed.

## Dependencies

- Python 3.9
