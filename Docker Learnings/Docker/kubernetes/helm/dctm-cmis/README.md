# Documentum CMIS

## Introduction
This chart bootstraps DCTM CMIS deployment on a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.


## Prerequisites
PV provisioner support in the underlying infrastructure to enable SSL configuration.

## Installing the Chart
Before installing the chart, prepare configuration files under root folder of dctm-cmis chart, like dfc.properties and cmis-api-runtime.properties. If there is available existing configMap, refer it in values.yaml with property `existingConfigMap`.

To install the chart with the release name `my-release`:

```helm install my-release dctm-cmis```

The output of the command will dump the guide how to consume the deployed DCTM CMIS.


## Uninstall the Chart
To uninstall/delete the `my-release` deployment:

```
$ helm delete my-release
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Specifies Configuration Files

If there is no existing ConfigMap for DCTM CMIS configuration, prepare configuration files in the same folder as `values.yaml` and specify the files name in the `values.yaml`. 

```
configurationFiles:
  - cmis-api-runtime.properties
  - dfc.properties
  - log4j.properties
```


## Graylog Integration

DCTM CMIS Helm chart supports to integrate with Graylog via sidecar. When `graylog.enabled` is true, there will be a sidecar contain in the DCTM CMIS pod. 

The piece below is an example for graylog integration. Pay attention to the attribute `graylog.logsDir`. By default, it is `/home/cmis/logs`. If the logs directory is specified by `log4j.appender.R.File` in log4j.properties, make sure the value of `graylog.logsDir` aligns with the path defined in *log4j.properties*.

```yaml
graylog:
  enabled: true
  image: gcr.io/documentum-search-product/graylog-sidecar
  imagePullPolicy: Always
  server: cmis-graylog-headless.dctm-cmis.svc.cluster.local
  port: 9000
  serviceToken: 87ckh5e9aammi6rd6g75ceuibce4ot8icb3itpeq4bibea25ge0
  logsDir: /home/cmis/logs
```

Below is sample graylog sidecar configuration, which should be configured in graylog server and will be pushed to sidecar.
```yaml
# Needed for Graylog
fields_under_root: true
fields.collector_node_id: ${sidecar.nodeName}
fields.gl2_source_collector: ${sidecar.nodeId}
fields.source: ${sidecar.nodeName}

filebeat.inputs:
- input_type: log
  paths:
    - /pod-data/*.log
  type: log
output.logstash:
   hosts: ["cmis-graylog-headless.dctm-cmis.svc.cluster.local:5044"]
path:
  data: /var/lib/graylog-sidecar/collectors/filebeat/data
  logs: /var/lib/graylog-sidecar/collectors/filebeat/log
```

## New Relic Integration

To enable New Relic agent, users have to at least switch on the newrelic feature (`newrelic.enabled`) and put the config file `newrelic.yml` in the same directory as `values.yaml`.
Make sure the values of `licence_key` and `app_name` in the `newrelic.yml` are specified correctly.

```yaml
newrelic:
  enabled: true
  configurationFile: newrelic.yml
  addNodeNamePrefix: false
```

## Deploy in CFCR Environment

Refer this [page](https://confluence.opentext.com/display/PleDevOps/Using+Dedicated+CFCR+Clusters+in+Brook+Park)  for ingress rule configuration in CFCR environment.

Below is an example of `cmis-ingress.yaml`:
```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/affinity: cookie
    nginx.ingress.kubernetes.io/session-cookie-hash: sha1
    nginx.ingress.kubernetes.io/session-cookie-name: route
  name: cmis-ingress
  namespace: <namespace>
spec:
  rules:
  - host: <app>.docu.cfcr-lab.bp-paas.otxlab.net
    http:
      paths:
      - backend:
          serviceName: <cmis_service_name>
          servicePort: 8080
        path:        

```

Run the command `kubectl -n <namespace> apply -f cmis-ingress.yaml` to create ingress rule.

DCTM CMIS will be online with URL `<app>.docu.cfcr-lab.bp-paas.otxlab.net`.

## Reference
| Category    | Name                     | Description                                                |
| ----------  | ---------------          | ---------------------------------------------------------- |
| metadata    | customLabels             | Specifies the labels for the deployment and service. For example, app: backend. |
|             | containerName            | Specifies the name of the container. |
| deployment  | replicaCount             | Specifies the number of pods to be spawned for Documentum CMIS Services. |
|             | strategyType             | Specifies the strategy for the deployment. For example, RollingUpdate, Recreate, and so on.      |
| image       | image                    | Specifies the image name of Documentum CMIS Services. |
|             | imageTag                 | Specifies the image tag of Documentum CMIS Services. |
|             | imagePullPolicy          | Specifies the pull policy for the Documentum CMIS Services image. For example, IfNotPresent, Always, and so on. |
| service     | serviceType              | Specifies the service type. For example, NodePort, ClusterIP, and so on. |
|             | httpPort                 | Specifies the service HTTP port for Documentum CMIS Services. |
|             | httpsPort                | Specifies the service HTTPS port for Documentum CMIS Services.|
| ConfigMap   | existingConfigMap        | Specifies the name of the existing CMIS ConfigMap. |
|             | configurationFiles       | See the section "Specifies Configuration Files " |
|             | extConfigMountPath       | Specifies the volume mount path of the container for the extra config files, e.g. newrelic.yml. |
| graylog     | graylog.enabled          | If you want to enable graylog sidecar, set this property true. |
|             | graylog.image            | Specifies the image name of graylog sidecar. |
|             | graylog.imagePullPolicy  | Specifies the strategy for the deoployment. |
|             | graylog.server           | Specifies the URL of graylog server. |
|             | graylog.port             | Specifies the port of graylog server. |
|             | graylog.serviceToken     | Specifies service token of graylog sidecar. |
|             | graylog.logsDir          | Specifies the logs directory of DCTM CMIS. A shared volumn is mounted to both this directory of CMIS container and a specific folder of graylog sidecar container. Thus CMIS log file is shared with sidecar container. |
| newrelic    | newrelic.enabled         | Specifies whether to enable the New Relic agent. |
|             | newrelic.configurationFile| Specifies the file name of New Relic configuration. |
|             | newrelic.addNodeNamePrefix| Specifies whether to prefix app name in the New Relic platform UI with the node name. |
| livenessProbe| livenessProbe.enabled	| Specifies whether to enable the liveness probe. Defaults to false. |
|              | livenessProbe.scheme	| Specifies the scheme (HTTP/HTTPS) for the probe URL. Defaults to HTTP. |
|              | livenessProbe.probeUrl | Specifies the target URL for probing. |
|              | livenessProbe.initialDelaySeconds | Specifies the seconds after the container has started before performing the first probe. |
|              | livenessProbe.periodSeconds | Specifies how often to perform the probe. |

