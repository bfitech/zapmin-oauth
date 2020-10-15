pipeline {
    agent any
    environment {
        PROJECT = 'bfin--zapmin-oauth'
    }
    stages {
        stage('branch: master') {
            when {
                branch 'master'
            }
            steps {
                sh 'docker-phpunit 7.0 7.4'
            }
            post {
                success {
                    sh 'jenkins-postproc'
                }
            }
        }
        stage('release') {
            when {
                tag '*'
            }
            steps {
                sh 'docker-phpunit 7.0 7.4'
            }
            post {
                success {
                    sh 'jenkins-postproc'
                }
            }
        }
    }
}
