#!bin/sh
# Must be logged in to google console
read -p "Version:" buildVersion
cd SPA
npm run buildProd
cd ../
docker build . --tag docker/registery/here:$buildVersion
docker push docker/registery/here:$buildVersion
gcloud beta compute instances update-container instance-name-here --container-image docker/registry/here:$buildVersion
