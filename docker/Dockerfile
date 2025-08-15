FROM python:3.11.1

WORKDIR /app
COPY . /app

RUN mkdir -p /app/output

RUN pip3 install -r requirements.txt

EXPOSE 5000

CMD ["python3", "src/vulcan/app.py"]
