FROM matthewfeickert/docker-python3-ubuntu
WORKDIR /app
# RUN echo -e http://mirrors.ustc.edu.cn/alpine/v3.7/main/ > /etc/apk/repositories
# RUN apt install gcc musl-dev python3-dev libffi-dev openssl-dev
COPY . .
RUN python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

USER root
ENTRYPOINT ["/bin/python3", "main.py"]