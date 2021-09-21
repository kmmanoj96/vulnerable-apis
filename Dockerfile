FROM python:3.9
ADD src/ /app
ADD util/ /util
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["./entrypoint.sh"]
