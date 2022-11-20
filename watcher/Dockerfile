FROM python:3.9.9-slim

LABEL MAINTAINER="Vadim Semenov"

ENV GROUP_ID=1000 \
    USER_ID=1000

WORKDIR /home/watcher/watcher/

ADD ./requirements.txt /home/watcher/watcher/requirements.txt


RUN pip install -r requirements.txt && \
    pip install --no-cache-dir gunicorn && \
    addgroup --gid $GROUP_ID watcher && \
    adduser --system --uid $USER_ID --ingroup watcher --disabled-password watcher

RUN touch watcher.log && \ 
    chown watcher:watcher watcher.log && \ 
    mkdir /home/watcher/watcher/tests

#USER www

# add python Watcher files 
COPY ./Helper.py /home/watcher/watcher/Helper.py
COPY ./pytail.py /home/watcher/watcher/pytail.py
COPY tests /home/watcher/watcher/tests



RUN rm -rf __pycache__/ 


CMD [ "python", "pytail.py"]
