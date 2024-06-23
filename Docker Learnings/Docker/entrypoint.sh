#!/bin/bash

# Improve tomcat startup performance, http://openjdk.java.net/jeps/123
java_security=$(find -L ${JAVA_HOME} -name java.security)
if grep -q securerandom.source=file:/dev/random ${java_security}; then
    sed -i -e "s/securerandom.source=file:\/dev\/random/securerandom.source=file:\/dev\/\\.\/urandom/" ${java_security}
elif grep -q securerandom.source=file:/dev/urandom ${java_security}; then
    sed -i -e "s/securerandom.source=file:\/dev\/urandom/securerandom.source=file:\/dev\/\\.\/urandom/"  ${java_security}
fi

# Apply configuration files from volume
cp ${CONFIG_DIR}/* ${DCTM_CMIS_HOME}/WEB-INF/classes/

# Add Tomcat SSL configuration in server.xml
if [ -n "${COMM_KEYSTORE_FILE}" ] && [ -n "${COMM_KEYSTORE_PWD}" ]; then
    echo "Setting Tomcat SSL/TLS connector: key store file and password..."
    sed -i '/<SSLHostConfig>$/{N;/Certificate /{s|certificateKeystoreFile="conf/localhost-rsa.jks"|certificateKeystoreFile="'"$COMM_KEYSTORE_FILE"'" certificateKeystorePassword="'"$COMM_KEYSTORE_PWD"'"|}}' ${CATALINA_HOME}/conf/server.xml
else
    echo "Communication keystore file or password is not specified..."
fi

if [ -n "${COMM_KEY_ALIAS}" ] && [ -n "${COMM_KEY_PWD}" ]; then
    echo "Setting Tomcat SSL/TLS connector: key alias and password..."
    sed -i '/<SSLHostConfig>$/{N;/Certificate certificateKeystoreFile/{N;N;N;s|\(.*<SSLHostConfig>\n\)\(.*\)\(\/>\n.*</SSLHostConfig>\)|\1\2 certificateKeyAlias="'"$COMM_KEY_ALIAS"'" certificateKeyPassword="'"$COMM_KEY_PWD"'" \3|}}' ${CATALINA_HOME}/conf/server.xml
else
    echo "Communication key alias or password is not specified..."
fi

if [ -n "${COMM_KEY_STORE_TYPE}" ]; then
    echo "Setting Tomcat SSL/TLS connector: keystore type..."
    sed -i '/<SSLHostConfig>$/{N;/Certificate certificateKeystoreFile/{N;N;N;s|\(.*<SSLHostConfig>\n\)\(.*\)\(\/>\n.*</SSLHostConfig>\)|\1\2 certificateKeystoreType="'"$COMM_KEY_STORE_TYPE"'" \3|}}' ${CATALINA_HOME}/conf/server.xml
else
    echo "Communication keystore type is not specified..."
fi

# Uncomment the Tomcat SSL configuration to make it effect
if [ -n "${COMM_KEYSTORE_FILE}" ] || [ -n "${COMM_KEYSTORE_PWD}" ] || [ -n "${COMM_KEY_ALIAS}" ] || [ -n "${COMM_KEY_PWD}" ] || [ -n "${COMM_KEY_STORE_TYPE}" ]; then
    echo "Enable Tomcat SSL/TLS configuration..."
    sed -i '/<!--$/{N;/Connector port=\"8443\"/{N;N;N;N;N;N;N;s|.*<!--\n\(.*\ </Connector>\)\n.* -->|\1|}}' ${CATALINA_HOME}/conf/server.xml
else
    echo "Tomcat SSL/TLS configuration is not enabled..."
fi

# New Relic
if [ -n "${NEW_RELIC_FILE}" ]; then
    echo "New Relic is enabled, copying config file ..."
    cp $NEW_RELIC_FILE ${NEW_RELIC_DIR}/newrelic.yml
    # add JVM arguments to tomcat startup script
    if [ -n "${NODE_NAME}" ]; then
        echo "Node name $NODE_NAME detected. Updating new relic's app name..."
        node_name_uppercase=`echo $NODE_NAME | tr 'a-z' 'A-Z'`
        sed -i 's/app_name: \(.*\)$/app_name: '"$node_name_uppercase"'-\1/' ${NEW_RELIC_DIR}/newrelic.yml
    fi
    echo 'JAVA_OPTS="$JAVA_OPTS -javaagent:$NEW_RELIC_DIR/newrelic.jar"' > ${CATALINA_HOME}/bin/setenv.sh
fi

if [ "$SINGLE_HELM_ENABLED" = "true" ]; then
	acsUrl=http://$ACS_HOST:$ACS_PORT/ACS/servlet/ACS
	urlstatus=0		
	while [ ! $urlstatus -eq '200'  ]
		do
			urlstatus=$(curl -o /dev/null --silent --head --write-out '%{http_code}' $acsUrl)
			if [ $urlstatus -eq '200'  ]; then
				echo "CS installation done"
				break;
			else
				echo "Waiting for CS to complete installation"
				sleep 60
			fi		
		done
fi

custom_script_pvc_execution(){
    echo "custom_script_execution"
    for i in `ls ${CUSTOM_SCRIPT_PVC}/*deploy.sh | sort -V`; do
        echo $i $1
     $i $1
     if [ $? -eq 1 ];
     then
       echo "Failed Custom Script $i"
       exit 1
     fi
     echo "custom script succeeded: $i"
    done
    echo "All custom scripts passed"
}

if [ "$USE_CUSTOM_INITCONTAINERS" = "true" ]; then
  echo "Initcontainer changes started"
  rm -Rf ${CUSTOM_SCRIPT_PVC}/*
  cp -R ${CUTOMSCRIPTPVC}/* ${CUSTOM_SCRIPT_PVC}/.
  chown -R -f dmadmin:dmadmin ${CUSTOM_SCRIPT_PVC}
  chmod +x ${CUSTOM_SCRIPT_PVC}/*.sh
  custom_script_pvc_execution "prehook"
  echo "Initcontainer changes completed"
fi
# Start Tomcat
${CATALINA_HOME}/bin/catalina.sh run &
if [ "$USE_CUSTOM_INITCONTAINERS" = "true" ];
then
  custom_script_pvc_execution "posthook"
fi
