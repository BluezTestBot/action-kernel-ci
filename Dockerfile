FROM blueztestbot/bluez-build:test

COPY *.sh /
COPY *.py /
COPY *.ini /
COPY *.config /
COPY gitlint /.gitlint

ENTRYPOINT [ "/entrypoint.sh" ]
