#!/bin/bash
docker build -t asmaas .
docker run -d -p 5000:5000 --privileged --name asmaas asmaas
