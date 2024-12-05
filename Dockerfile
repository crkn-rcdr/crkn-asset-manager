FROM python:3.9

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./main.py /code/app/main.py
COPY ./.env /code/app/.env

EXPOSE 8000

CMD ["python", "/code/app/main.py"]