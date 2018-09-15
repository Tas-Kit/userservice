FROM python:3
ENV PYTHONUNBUFFERED 1
RUN mkdir /userservice
WORKDIR /userservice
ADD requirements.txt /userservice/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN apt-get update
RUN apt-get install -y gettext nano
ADD . /userservice/
RUN git submodule init
RUN git submodule update
CMD python manage.py runserver 0.0.0.0:8000
