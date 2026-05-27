# 🛡️ PhishGuard V2 | ML-Powered URL Scanner

**PhishGuard** has evolved into a robust **Intelligence-Based** web application designed to help users identify potential phishing threats in real-time. By utilizing Machine Learning (Random Forest) and real-time threat data (WHOIS, VirusTotal), PhishGuard provides a comprehensive safety score and detailed risk assessment for any URL.

## 🚀 Key Features

- **ML Brain (Random Forest)**: Predicts threats using a model trained on real-world phishing data (PhishTank), going beyond simple heuristics.
- **Intelligence Hub**: Automatically calculates domain age using WHOIS and connects to VirusTotal for community reputation checks.
- **Modern Dashboard**: A Next.js-powered frontend featuring Glassmorphism UI, allowing you to track scan history and view risk distributions.
- **Dockerized Architecture**: One-command setup using Docker Compose for both the frontend and backend services.

## 🏗️ Technology Stack

### Backend & ML Engine
- **Framework**: Python FastAPI (High-performance API)
- **Machine Learning**: `scikit-learn` (Random Forest Classifier)
- **Intelligence APIs**: `python-whois`, VirusTotal API, URLScan.io

### Frontend
- **Framework**: Next.js (App Router)
- **Styling**: Vanilla CSS with modern Glassmorphism utilities
- **Icons & Typography**: Font Awesome 6.4.0, Google Fonts (Outfit)

### Deployment & DevOps
- **Containerization**: Docker & Docker Compose
- **CI/CD**: Jenkins (Jenkinsfile included)

## 🛠️ Getting Started

To run the full application locally using Docker:

1. **Ensure Docker and Docker Compose are installed and running.**
2. **Set up environment variables:** Add a `.env` file in `./phishing-detector/backend/.env` with required API keys if necessary.
3. **Run Docker Compose from the project root:**
   ```bash
   docker-compose up -d
   ```
4. **Access the Application:**
   - Frontend UI: Visit [http://localhost:3000](http://localhost:3000)
   - Backend API Docs: Visit [http://localhost:8000/docs](http://localhost:8000/docs)

## 📁 Project Structure

- `/phishing-detector/backend`: Python FastAPI server and ML pipeline.
- `/safelink-frontend`: Next.js user interface.
- `docker-compose.yml`: Orchestrates both frontend and backend services.
- `phishguard_v2_roadmap.md`: Strategic vision and upcoming phases (e.g., Chrome Extension).

---
© 2025 Rohit Kumar Ranjan. All rights reserved.
