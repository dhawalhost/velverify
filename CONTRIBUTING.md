# Contributing to WardSeal

First off, thank you for considering contributing to WardSeal! It's people like you that make WardSeal such a great tool.

## Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct. [Details coming soon].

## How Can I Contribute?

### Reporting Bugs
Before creating bug reports, please check the existing issues as you might find that this has been reported already.

### Suggesting Enhancements
Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:
*   A clear and concise description of the enhancement.
*   The goal of the enhancement.
*   Any additional context that might be useful.

### Pull Requests
1.  Fork the repo and create your branch from `main`.
2.  If you've added code that should be tested, add tests.
3.  If you've changed APIs, update the documentation.
4.  Ensure the test suite passes.
5.  Make sure your code lints.

## Architecture Guidelines

*   **Repository Pattern**: All database interactions must be abstracted behind a `Repository` interface.
*   **Dependency Injection**: Use interface-based dependency injection in constructors.
*   **Pkg vs Internal**: 
    *   `pkg/`: Code that is safe for other projects to import.
    *   `internal/`: Implementation details specific to WardSeal services.

## Development Setup

See [GETTING_STARTED.md](GETTING_STARTED.md) for detailed instructions on setting up your local environment.
