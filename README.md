# DetectIQ
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL_v2.1-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-red.svg)]()

DetectIQ is an AI-powered security rule management library. It helps create, analyze, and optimize detection rules for various security platforms.

> ⚠️ **IMPORTANT DISCLAIMER**
> This project is a **Proof of Concept** and under active development. Expect bugs, breaking changes, and incomplete documentation. Not recommended for production use. Use at your own risk.

## Quickstart

1.  **Clone:** `git clone https://github.com/AttackIQ/DetectIQ.git && cd DetectIQ`
2.  **Configure:** Copy `.env.example` to `.env` and add your API keys (e.g., `OPENAI_API_KEY`).
3.  **Install:** `poetry install --all-extras` (recommended) or `pip install .`
4.  **Explore:** See the `examples/` directory and the [detailed documentation](docs/README.md).

## Key Features
*   AI-powered rule creation and optimization (OpenAI).
*   Integration with rule repositories (SigmaHQ, YARA-Forge, Snort3).
*   Static analysis of samples (malware, PCAPs) for rule generation context.
*   Multi-platform SIEM query translation.

For more details, see [documentation](docs/README.md).

## Road Map
Key areas of future development include support for custom/local LLMs, more SIEM integrations, and enhanced rule validation. See [issues](https://github.com/AttackIQ/DetectIQ/issues) for more.

## Using as a Package
Install from PyPI:
`pip install detectiq`

DetectIQ is primarily used as a Python library. For detailed usage patterns and code examples, please refer to the `examples/` directory and the main [documentation](docs/README.md).

## Environment Configuration
Configure via environment variables. Copy `.env.example` to `.env` and set your API keys. For full details, see the [documentation](docs/README.md).

## Development
This project uses a `Makefile` for common development tasks.
*   Install development dependencies: `poetry install --all-extras` (includes dev dependencies if `pyproject.toml` is configured for it, or use a specific group e.g. `poetry install --with dev`). Check your `Makefile` or `pyproject.toml` for the exact command for dev dependencies.
*   View available commands: `make help`
*   Format code: `make format`
*   Run tests: `make test`

For publishing information, see [PUBLISHING.md](PUBLISHING.md).

## Contributing
1.  Fork the repository.
2.  Create a feature branch.
3.  Commit your changes.
4.  Push to the branch.
5.  Create a Pull Request.

## License
This project uses multiple licenses. The core project is licensed under LGPL v2.1. See the `LICENSE` file and notes on licenses for bundled rule sets within the [documentation](docs/README.md).

## Support & Community
*   Discussions: [SigmaHQ Discord](https://discord.gg/27r98bMv6c)
*   Issues: [GitHub Issues](https://github.com/AttackIQ/DetectIQ/issues)

## Acknowledgments
*   SigmaHQ Community
*   YARA-Forge Contributors
*   Snort Community
*   OpenAI
