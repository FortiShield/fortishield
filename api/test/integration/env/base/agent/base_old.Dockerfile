FROM ubuntu:18.04

RUN apt-get update && apt-get install -y curl apt-transport-https lsb-release gnupg2
RUN curl -s https://packages.khulnasoft.com/key/GPG-KEY-FORTISHIELD | apt-key add - && \
    echo "deb https://packages.khulnasoft.com/3.x/apt/ stable main" | tee /etc/apt/sources.list.d/fortishield.list && \
    apt-get update && apt-get install fortishield-agent=3.13.2-1 -y
