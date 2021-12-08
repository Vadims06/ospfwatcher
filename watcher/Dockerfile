FROM python:3.9.9-slim

LABEL MAINTAINER="Vadim Semenov"

ENV GROUP_ID=1000 \
    USER_ID=1000

WORKDIR /home/watcher/watcher/

ADD ./requirements.txt /home/watcher/watcher/requirements.txt

# openssh-client for NAPALM, #gcc 
RUN apt-get update && \
    apt-get install -y --no-install-recommends telnet build-essential vim && \ 
    #rm -rf /var/lib/apt/lists/* && \
    pip install -r requirements.txt && \
    pip install --no-cache-dir gunicorn && \
    #apt-get purge -y --auto-remove python3-dev openssl && \
    addgroup --gid $GROUP_ID watcher && \
    adduser --system --uid $USER_ID --ingroup watcher --disabled-password watcher

RUN touch watcher.log && \ 
    chown watcher:watcher watcher.log

#USER www

# add python Watcher files 
COPY ./Helper.py /home/watcher/watcher/Helper.py
COPY ./pytail.py /home/watcher/watcher/pytail.py



RUN rm -rf __pycache__/ 


CMD [ "python", "pytail.py"]
