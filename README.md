# Agentic AI for Active Directory Security

An agentic AI system designed to investigate Active Directory environments, identify potential security weaknesses, and explain possible attack paths. The project combines AI-powered analysis with human approval to support security investigations in an authorized lab environment.

## 1. Project Overview

### Purpose
Active Directory environments can contain misconfigurations, excessive permissions, and relationships between accounts that create potential paths to higher privileges. Identifying these issues requires understanding how different components of a domain interact.

This project aims to simplify Active Directory security investigations by using an AI agent to collect information, analyze findings, and explain potential attack paths in a clear and understandable way.

### Key Features
- **Active Directory Investigation:** Accepts domain and target information through a frontend and initiates investigations through the backend.
- **Security Enumeration:** Collects information about the authorized Active Directory environment using available security tools.
- **AI-Powered Analysis:** Analyzes collected evidence to identify potential security weaknesses.
- **Attack Path Identification:** Explains possible privilege escalation paths based on discovered evidence.
- **Human-in-the-Loop Approval:** Requests user approval before performing actions that require authorization.
- **Investigation Results:** Returns findings and explanations to the frontend for review.
- **GOAD Lab Integration:** Uses the Game of Active Directory (GOAD) lab as the controlled testing environment.

## 2. How It Works
The system follows an investigation workflow:

1. **Input:** The user enters the Active Directory domain and target information through the frontend.
2. **Validation:** The backend validates the request and checks whether the target is within the authorized scope.
3. **Investigation:** The AI agent uses available tools to gather information about the environment.
4. **Analysis:** The agent analyzes the collected evidence and identifies potential security weaknesses and attack paths.
5. **Human Approval:** The system requests approval before performing actions that require authorization.
6. **Results:** The findings and explanations are returned to the frontend for review.

The objective is to make Active Directory security investigations easier to understand while keeping users involved in important decisions.

## 3. Technology Stack
- **Frontend:** Web-based user interface (React / Vite)
- **Backend:** Python API and investigation services (FastAPI)
- **AI Model:** Ollama with a locally hosted language model
- **Database:** SQLite / PostgreSQL, and Neo4j for Active Directory Knowledge Graph
- **Security Testing Environment:** Game of Active Directory (GOAD-Light)
- **Containerization:** Docker and Docker Compose

## 4. Video Presentation
- **Five-Minute Project Demonstration (Feben Solomon - AD Security & Attack Validation):**
- [Watch the Project Presentation] [i have sent it via telegram due to connection issues i could not upload it on drive in time](https://drive.google.com/file/d/190y_dCc79RNNtIv3PeGzuQNKYWDmT7qX/view?usp=sharing)

## 5. GitHub Repository
- **Repository Link:** [Agentic AI for Active Directory Security](https://github.com/HermelaGirma/Agentic-AI-for-Active-Directory-Security)

The repository contains the project's source code, including the agent, backend, frontend, configuration, and supporting documentation.

## 6. Team Members
The project is developed by a team of six members:

| No. | Full Name | CTC ID | Role / Contribution |
|---|---|---|---|
| 1 | Hermela Girma | CTC-5848-26 | Agentic AI and System Integration |
| 2 | **Feben Solomon** | **CTC-1718-26** | **Active Directory Security and Attack Validation** |
| 3 | Meseret Telke | CTC-3934-26 | Reconnaissance and Tool Integration |
| 4 | Wintana Dereje | CTC-4911-26 | Backend and Database |
| 5 | Lidiya Alemayehu | CTC-204-26 | Knowledge Graph and Attack Paths |
| 6 | Yosef Walelign | CTC-2969-26 | Frontend and Visualization |

## 7. Project Status
Testing is being conducted in an authorized GOAD lab environment.

## 8. Responsible Use
This project is intended for educational purposes and authorized Active Directory security assessments. Investigations must remain within the approved scope, and actions requiring authorization must follow the human approval process.
