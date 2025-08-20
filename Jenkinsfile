pipeline {
    agent any
    environment {
        HARBOR_CREDS = credentials('jenkins-harbor-creds')
        GIT_VER = sh(returnStdout: true,script: 'git describe --tags --always').trim()
        HARBOR_HOST = 'harbor.ata-t.com:3443';
        APP_NAME = "iptables_web";
        ENVNAME = sh(returnStdout: true,script: 'cat /etc/envname.txt').trim();
        DOCKER_IMAGE = "ata/${APP_NAME}";
    }
    stages {
        stage('Docker Build') {
             steps {
                echo "Build Docker Image Stage"
                sh "docker build -t ${HARBOR_HOST}/${DOCKER_IMAGE}:`date '+%Y_%m_%d'` ."
                sh "docker build -t ${HARBOR_HOST}/${DOCKER_IMAGE}:latest ."
             }
        }
        stage('Push') {
            steps {
                echo "Push Docker Image Stage"
                withCredentials([usernamePassword(credentialsId: 'jenkins-harbor-creds', passwordVariable: 'psw', usernameVariable: 'user')]) {
                   sh "docker login -u ${user} -p ${psw} ${HARBOR_HOST}"
                   sh "docker push ${HARBOR_HOST}/${DOCKER_IMAGE}:`date '+%Y_%m_%d'`"
                   sh "docker push ${HARBOR_HOST}/${DOCKER_IMAGE}:latest"
                }
            }
        }
        stage('Docker Deploy') {
            when {
                allOf {
                    expression { env.GIT_VER != null }
                }
            }
            steps {
                sh "docker run --rm harbor.ata-t.com:3443/ata/aita-goc:latest python goc.py  --envname ${ENVNAME} --servername ${APP_NAME} --serverimage '${HARBOR_HOST}/${DOCKER_IMAGE}:${GIT_VER}'"
            }
        }
    }
}

