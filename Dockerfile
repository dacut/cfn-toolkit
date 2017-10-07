FROM amazonlinux:2017.09
RUN mkdir /build
WORKDIR /build
ENV CODEBUILD_SRC_DIR=/build
COPY codebuild handler.py requirements.txt requirements-test.txt \
  setup.cfg setup.py /build/
COPY cfntoolkit cfntoolkit
RUN ./codebuild install
RUN ./codebuild prebuild
RUN ./codebuild build
