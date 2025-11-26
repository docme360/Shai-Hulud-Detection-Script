# Shai-Hulud Detection Script

A Python-based security tool to scan repositories for npm packages compromised by the Shai-Hulud worm malware campaign.

## Overview

The Shai-Hulud campaign is a supply chain attack targeting the JavaScript/Node.js ecosystem through malicious npm packages. This tool helps developers and security teams audit their projects to identify potentially compromised dependencies.

## Requirements

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

## Installation

```bash
# Clone the repository
git clone https://github.com/docme360/Shai-Hulud-Detection-Script.git
cd Shai-Hulud-Detection-Script

# Install dependencies
uv sync
```

## Usage

```bash
uv run python main.py
```

## How It Works

The script scans your repository for npm package dependencies (typically in `package.json` and `package-lock.json` files) and checks them against a list of known malicious packages associated with the Shai-Hulud campaign.

## Contributing

Contributions are welcome! If you discover additional malicious packages or have improvements to the detection logic, please open an issue or submit a pull request.

## Disclaimer

This tool is provided for defensive security purposes only. Always verify findings and keep your detection lists updated as new threats are discovered.

## License

See repository for license information.
