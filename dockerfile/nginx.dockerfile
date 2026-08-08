ARG image=alpine:3.18.2
FROM $image
RUN apk add nginx-mod-stream openssh \
    && mkdir /root/.ssh \
    && mkdir /var/cache/nginx
ENV ENV="/root/.ashrc"
