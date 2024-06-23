#!/bin/bash

#Env vars
export WORK_DIR=/home/dmadmin
export LOGS_DIR=${WORK_DIR}/logs
export CONFIG_DIR=${WORK_DIR}/config
export NEWRELIC_DIR=${CATALINA_HOME}/newrelic
export DCTM_CMIS_HOME=${CATALINA_HOME}/webapps/dctm-cmis
export CUTOMSCRIPTPVC=/opt/customscriptpvc
export CUSTOM_SCRIPT_PVC=/opt/custom_script_pvc
export CMIS_EXTENSION_DIR=/home/dmadmin/dctmcmisextension
export CUSTOM_JAVA_OPTS=$1		  

sudo chown -R dmadmin:dmadmin /opt
sudo chmod -R 755 /opt

mkdir -p ${CUSTOM_SCRIPT_PVC}
mkdir -p ${CUTOMSCRIPTPVC}
mkdir -p ${CMIS_EXTENSION_DIR}
mkdir -p ${DCTM_CMIS_HOME}
mkdir -p ${LOGS_DIR}
mkdir -p ${CONFIG_DIR}
mkdir -p ${NEWRELIC_DIR}
cp -Rf ${CMIS_EXTENSION_DIR}/newrelic.jar ${NEWRELIC_DIR}/ 
cp ${CMIS_EXTENSION_DIR}/entrypoint.sh ${WORK_DIR}
unzip -q ${CMIS_EXTENSION_DIR}/dctm-cmis.war -d ${DCTM_CMIS_HOME}
echo 'JAVA_OPTS="$JAVA_OPTS  ${CUSTOM_JAVA_OPTS} -Djava.locale.providers=COMPAT,SPI"' > ${CATALINA_HOME}/bin/setenv.sh
chmod 750 ${CATALINA_HOME}/bin/setenv.sh
chmod +x ${WORK_DIR}/entrypoint.sh
cd ${WORK_DIR} && \
sh ${WORK_DIR}/entrypoint.sh

tail -f /dev/null & wait
