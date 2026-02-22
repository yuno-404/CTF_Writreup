#!/bin/bash
docker build -t blindness .
docker run -d -p 5000:5000 --privileged --name blindness blindness
