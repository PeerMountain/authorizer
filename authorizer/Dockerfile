FROM python:3.6 as base
WORKDIR /usr/src/app
EXPOSE 8000

COPY Pipfile* ./
RUN pip install pipenv
RUN pipenv install --system
COPY . .

FROM base as production
CMD ["./entrypoint.sh"]

FROM production as development
RUN pipenv install --system --dev
CMD ["./entrypoint.sh"]
