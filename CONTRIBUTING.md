# Contributing

⚠️ **BETA / EXPERIMENTAL PROJECT** ⚠️

This is an experimental project in active development. Features and APIs may change frequently.

## Quick Start

1. Fork and clone the repository
2. Create a new branch for your changes
3. Make your changes
4. Test your changes
5. Submit a Pull Request

## Guidelines

- Keep it simple
- Add tests for new features
- Update documentation if needed
- Follow existing code style

## Publishing

For package maintainers, we provide automated release management via make targets:

1. Configure your PyPI token (one-time setup):
```bash
make token-set TOKEN=your-pypi-token
```

2. Run versioning and publishing:
```bash
make update # will do poetry update
make install # will do poetry install --all-extras (includes dev dependencies if specified via groups or --with dev)
make test # will do poetry run pytest (also installs dev dependencies)
make version-patch # or version-minor or version-major
make build # will build the package
make publish # will publish to PyPI
```

For detailed publishing instructions, see [PUBLISHING.md](PUBLISHING.md).

## Questions?

Open an issue on GitHub for any questions or problems.

Thank you for contributing! 