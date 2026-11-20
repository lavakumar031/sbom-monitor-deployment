# SBOM Monitor Deployment

This repository contains the source code and deployment configuration for a local SBOM generation and vulnerability-monitoring dashboard.

The application accepts public repository URLs, generates a Software Bill of Materials using Syft, checks identified packages with Grype, and stores scan information in MySQL for dashboard review.

Generated scan reports, local databases, repository caches, and previous scan data are intentionally excluded from this repository.

## Deployment notes

The application requires Python, MySQL or MariaDB, Syft, and Grype. Database settings are supplied through environment variables; copy `.env.example` to a protected local `.env` file and enter server-specific values there.
