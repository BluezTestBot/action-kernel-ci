FROM blueztestbot/bluez-build:latest

COPY *.sh /
COPY *.py /
COPY *.ini /
COPY *.config /
COPY gitlint /.gitlint

CMD [ "/entrypoint.sh" ]
