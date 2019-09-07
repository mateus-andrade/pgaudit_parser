FROM alpine

RUN apk update && apk --no-cache add gcc g++ libc-dev make cmake

ADD . /pgaudit_parser

RUN cd /pgaudit_parser/build && cmake /pgaudit_parser && make

WORKDIR /pgaudit_parser
