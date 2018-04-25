FROM python:3.6 as base
WORKDIR /usr/src/app
EXPOSE 8000

# Bug in pipenv, where it does not find python in the PATH 
RUN ln -sf $(which python) /bin/python

RUN pip install pipenv==9.0.1
COPY Pipfile* ./
RUN pipenv install --system
COPY . .

FROM base as production
CMD ["./entrypoint.sh"]

FROM production as development
RUN pipenv install --system --dev
CMD ["./entrypoint.sh"]
