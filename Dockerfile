FROM python:3.9-slim-buster
WORKDIR /app
# RUN echo -e http://mirrors.ustc.edu.cn/alpine/v3.7/main/ > /etc/apk/repositories
# RUN apt install gcc musl-dev python3-dev libffi-dev openssl-dev
COPY . .
RUN python3 -m pip install -r requirements.txt

USER root
ENTRYPOINT ["python3", "CAduit.py"]
