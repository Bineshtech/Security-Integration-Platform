# Security Integration Platform

## Overview

The Security Integration Platform is a centralized cybersecurity integration framework developed using Python and FastAPI. It aims to simplify the integration of multiple security tools and threat intelligence sources through a reusable, configuration-driven connector architecture.

Traditional security integrations often require custom development for every tool, making them difficult to maintain, scale and manage. This project addresses these challenges by providing a common connector framework that supports API-based integrations using YAML configurations and a visual configuration form.

## Key Features

- **Configuration-Driven Connectors:** Add and manage security integrations using YAML or a visual form.
- **API Integration:** Connect cybersecurity tools and external threat intelligence sources.
- **Secure Secret Management:** Protect API credentials using Fernet symmetric encryption.
- **Authentication and Authorization:** Password hashing, signed sessions and role-based access control.
- **Data Normalization:** Collect and organize security information into a common data structure.
- **Vulnerability Intelligence:** Integrate vulnerability information from sources such as CISA KEV, NVD and EPSS.
- **Execution Monitoring:** Track connector runs, synchronization status and processing results.
- **Quarantine Management:** Manage records identified as invalid or requiring isolation.
- **Response Actions:** Support controlled security response workflows with approval and dry-run capabilities.

## Technology Stack

- Python
- FastAPI
- SQLite
- YAML
- Fernet symmetric encryption
- PBKDF2-HMAC-SHA256
- HMAC-SHA256
- REST APIs
- HTML, CSS and JavaScript

## Project Objective

To reduce the complexity of cybersecurity tool integration by providing a reusable, secure and centralized platform for managing security data sources and integration workflows.
