 FROM python:2
 ENV PYTHONUNBUFFERED 1
 RUN mkdir /userservice
 WORKDIR /userservice
 ADD requirements.txt /userservice/
 RUN pip install --upgrade pip
 RUN pip install -r requirements.txt
 RUN apt-get update
 RUN apt-get install -y gettext
 ADD . /userservice/