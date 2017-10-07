FROM amazonlinux:2017.09
RUN yum install -y python36 python36-devel python36-pip zip
RUN pip-3.6 install virtualenv
RUN mkdir /build
RUN virtualenv --python python3.6 /build/venv
ENV VIRTUAL_ENV=/build/venv
ENV PATH=/build/venv/bin:$PATH
WORKDIR /build
COPY requirements.txt requirements-test.txt ./
RUN pip install -r requirements.txt
COPY handler.py setup.py ./
COPY cfntoolkit cfntoolkit/
RUN ./setup.py build
RUN ./setup.py install
RUN zip /lambda.zip handler.py
WORKDIR /build/venv/lib/python3.6/site-packages
RUN zip -r /lambda.zip . -x "*.dist-info/*" "boto3/*" "botocore/*" \
    "dateutil/*" "docutils/*" "easy_install*" "nose/*" "pbr/*" "pip/*" \
    "s3transfer/*" "setuptools/*" "wheel/*"
