# Start from a Debian image with the latest version of Go installed
# and a workspace (GOPATH) configured at /go.
# build with
# dockerBuild.sh
# Ensure your ssh key is added to your bitbucket account if you are using bitbucket
# In order to run, you MUST PASS IN YOUR CLOUD CREDENTIALS via json file (use git ignore to prevent it being committed)
FROM golang AS build-env

ARG ssh_prv_key
ARG ssh_pub_key

RUN mkdir /root/.ssh && echo "StrictHostKeyChecking no " > /root/.ssh/config

RUN echo "$ssh_prv_key" > /root/.ssh/id_rsa && \
    echo "$ssh_pub_key" > /root/.ssh/id_rsa.pub && \
    chmod 600 /root/.ssh/id_rsa && \
    chmod 600 /root/.ssh/id_rsa.pub

RUN git config --system url."git@bitbucket.org:".insteadOf "https://bitbucket.org/"

COPY . ./src/bitbucket.org/dolmant/gold/auth-service

RUN go get ./src/bitbucket.org/dolmant/gold/auth-service/...
RUN CGO_ENABLED=0 go build -o ./src/bitbucket.org/dolmant/gold/auth-service/cmd/auth-service/auth-service ./src/bitbucket.org/dolmant/gold/auth-service/cmd/auth-service/auth-service.go
RUN rm /root/.ssh/id_rsa

FROM alpine
ADD ca-certificates.crt /etc/ssl/certs/
WORKDIR /
RUN mkdir /root/auth-service
COPY --from=build-env /go/src/bitbucket.org/dolmant/gold/auth-service/cmd/auth-service/auth-service /root/auth-service
ENTRYPOINT /root/auth-service/auth-service

# Service listens on port 8097 for gRPC.
EXPOSE 8097
# Service listens on port 8098 for debug http.
EXPOSE 8098
# Service listens on port 8099 for http.
EXPOSE 8099
