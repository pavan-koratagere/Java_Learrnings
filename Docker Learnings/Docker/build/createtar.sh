#!/bin/sh
set -x
#Declaring property values
source ./createtar.properties
restapi_version=${major_version}.${minor_version}
patch_number=${patch_number}
update_version=${hotfix_number}
restapi_build_number=${restapi_version}.0${patch_number}${hotfix_number}.${build_number}
restapi_helm=${restapi_version}.${hotfix_number}-${current_build_number}
restapi_latest=${build_path}
restapi_view=${branch_name}

art_centos_url=artifactory.otxlab.net/bpdockerhub/restapi/centos/stateless/restapi
art_bphelm_path=https://artifactory.otxlab.net/artifactory/list/BPhelm
restapi_centos=${art_centos_url}:${restapi_build_number}
restapi_centos_tag=restapi_centos:${restapi_build_number}
restapi_centos_tar=restapi_centos.tar
restapi_main_tar=dctm_rest_services_${restapi_version}_centos.tar
chart_file="../kubernetes/helm/dctm-rest/Chart.yaml"

sed -i "s/$(grep "^appVersion: " $chart_file)/appVersion: \"${restapi_build_number}\"/;s/$(grep "^version: " $chart_file)/version: ${restapi_helm}/" $chart_file
echo "restapi_build_number=${restapi_build_number}, restapi_latest=${build_path}, restapi_view=${restapi_view}"

##centos
#docker pull ${restapi_centos}
#docker tag ${restapi_centos} ${restapi_centos_tag}
#docker save -o ${restapi_centos_tar} ${restapi_centos_tag}

cd ..; cd kubernetes/helm; helm package dctm-rest; tar -cvf HelmChart.tar dctm-rest-${restapi_helm}.tgz; mv HelmChart.tar ../../build

#It needs to be uncommented for develop branch
curl -u cmabuild:3PEhYRSNjwDPv7B -T "{dctm-rest-${restapi_helm}.tgz}" -X PUT  "${art_bphelm_path}/"
cd ../../build; tar -cvf ${restapi_main_tar}  HelmChart.tar

sudo cp ${restapi_main_tar} /mnt/builds/${restapi_latest}/RESTAPI/${restapi_view}/${restapi_build_number}
sudo cp HelmChart.tar /mnt/builds/${restapi_latest}/RESTAPI/${restapi_view}/${restapi_build_number}
rm -rf *.tar

#docker rmi -f `docker images -q`
