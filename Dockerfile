FROM python:3.9


WORKDIR /code


COPY ./requirements.txt /code/requirements.txt


RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt


COPY ./server.py /code/app/server.py
COPY ./.env /code/app/.env

CMD ["fastapi", "run", "app/server.py", "--port", "8000"]