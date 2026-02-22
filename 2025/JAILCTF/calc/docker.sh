#!/bin/bash
docker build -t calcdefanged .
docker run -d -p 5000:5000 --privileged --name calcdefanged calcdefanged
