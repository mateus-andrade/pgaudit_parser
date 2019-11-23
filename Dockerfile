FROM alpine

RUN apk update && apk --no-cache add gcc g++ libc-dev make cmake
RUN wget http://www.digip.org/jansson/releases/jansson-2.12.tar.gz

RUN tar xfz jansson-2.12.tar.gz

RUN cd jansson-2.12 && ./configure && make && make check && make install

ADD . /pgaudit_parser

RUN cd /pgaudit_parser/build && cmake /pgaudit_parser && make

WORKDIR /pgaudit_parser
