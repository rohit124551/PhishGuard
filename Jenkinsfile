pipeline {
    agent any

    environment {
        BACKEND_IMAGE = "rohit124551/phishguard-backend:latest"
        FRONTEND_IMAGE = "rohit124551/phishguard-frontend:latest"
    }

    stages {
        // Stage 1: Pull the freshly built images from Docker Hub
        stage('Pull Latest Images') {
            steps {
                sh "docker pull ${BACKEND_IMAGE}"
                sh "docker pull ${FRONTEND_IMAGE}"
                echo "Got latest images from Docker Hub"
            }
        }

        // Stage 2: Stop any currently running old versions of the app
        stage('Stop Old Containers') {
            steps {
                sh "docker compose down || true"
                echo "Old containers stopped"
            }
        }

        // Stage 3: Start the newly pulled versions of the app
        stage('Start New Containers') {
            steps {
                sh "docker compose up -d"
                echo "New containers starting..."
            }
        }

        // Stage 4: Verify the application started successfully
        stage('Health Check') {
            steps {
                sh "sleep 15"
                sh "curl -f http://localhost:8000/docs || exit 1"
                sh "curl -f http://localhost:3000 || exit 1"
                echo "Both services are healthy and running"
            }
        }
    }

    post {
        success {
            echo "DEPLOYED SUCCESSFULLY"
            echo "Frontend: http://localhost:3000"
            echo "Backend:  http://localhost:8000"
        }
        failure {
            echo "DEPLOYMENT FAILED"
            echo "Check logs with: docker compose logs"
        }
    }
}
