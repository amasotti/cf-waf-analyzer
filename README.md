# cf-waf-analyzer

`cf-waf-analyzer` is a simple rust based cli utility for analyzing Cloudflare Web Application Firewall (WAF) logs. 
It helps parse and interpret security events to enhance your firewall configurations.

## Features
- Parse Cloudflare WAF logs
- Generate detailed reports

## Usage

To use `cf-waf-analyzer`, run the following command:

```sh
wafstat analyze <path_to_log_file> -f <format>
```

Replace `<path_to_log_file>` with the path to your Cloudflare WAF log file.

The `-f` flag is optional and allows you to specify the output format. The available formats are:
- `json`: JSON format
- `md`: Markdown format (alternative: `markdown`)

## Example

```sh
wafstat analyze logs/waf_log.json
```

To run your Rust project with Docker, you can add the following instructions to your `README.md`:

## Running with Docker

1. **Build the Docker image:**

```sh
docker build -t wafstat .
```

2. **Run the Docker container:**

```sh
docker run --rm -v $(pwd)/example-logs:/app/input wafstat analyze /app/input/firewall-events.json --format md
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
