FROM python:3.10.8

WORKDIR /app

COPY . .

RUN python -m pip install -r requirements.txt

CMD waitress-serve --host 0.0.0.0 app:app