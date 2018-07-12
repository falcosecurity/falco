FROM python:3-stretch

RUN pip install pipenv

WORKDIR /app

ADD Pipfile /app/Pipfile
ADD Pipfile.lock /app/Pipfile.lock
RUN pipenv install --system --deploy

ADD . /app

CMD ["python", "main.py"]
