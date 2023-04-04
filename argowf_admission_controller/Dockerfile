FROM python:alpine3.14

WORKDIR /app
COPY requirements.txt /app
RUN pip install -r requirements.txt

COPY . /app

# ENTRYPOINT ["python"]
# CMD ["main.py"]
ENTRYPOINT ["/bin/sh", "-c"]
CMD [ "while true; do sleep 30; done;" ]