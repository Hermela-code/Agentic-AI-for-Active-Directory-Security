# Team Setup Guide

## Project

Agentic AI for Active Directory Security

## Repository

https://github.com/Hermela-code/Agentic-AI-for-Active-Directory-Security

## Project Structure

- `agent/` - AI agent and investigation logic
- `backend/` - FastAPI backend and APIs
- `frontend/` - React frontend
- `tools/` - Security tool integrations and wrappers
- `graph/` - Neo4j graph and AD relationships
- `tests/` - Testing
- `docs/` - Project documentation

## Development Rules

1. Clone the repository.
2. Create your own feature branch.
3. Do not work directly on `main`.
4. Make meaningful commits.
5. Push your branch to GitHub.
6. Create a Pull Request when your work is ready.
7. Do not commit passwords, API keys, `.env` files, or credentials.
8. Work only against the authorized GOAD-Light environment.

## Team Branches

Hermela:
`feature/agent`

Feben:
`feature/ad-security`

Meseret:
`feature/tool-integration`

Wintana:
`feature/backend`

Lidiya:
`feature/graph`

Yosef:
`feature/frontend`

## Phase 1 Goal

Build the first working flow:

User provides authorized GOAD-Light target  
→ agent starts investigation  
→ security tool runs  
→ result is returned  
→ result is analyzed  
→ result is explained  
→ result is displayed in the frontend

## Team Responsibilities

### Hermela
Agent architecture, OpenClaw integration, investigation workflow and overall integration.

### Feben
AD security research, GOAD-Light attack scenarios, validation methods and expected security findings.

### Meseret
Nmap/NetExec/LDAP tool integration, wrappers and structured tool output.

### Wintana
FastAPI backend, APIs, database and investigation/session management.

### Lidiya
Neo4j, AD entities, relationships and attack-path data.

### Yosef
React frontend, investigation interface, status messages, findings and visualization.

## Important

The project should remain modular so each team member can develop their assigned component independently.
