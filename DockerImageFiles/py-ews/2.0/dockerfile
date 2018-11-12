# Docker image file that describes an Ubuntu16.04 image with PowerShell installed from Microsoft APT Repo
ARG fromTag=16.04

FROM ubuntu:${fromTag}

ARG PS_VERSION=6.1.0
ARG PS_VERSION_POSTFIX=-1.ubuntu.16.04
ARG IMAGE_NAME=mcr.microsoft.com/powershell:ubuntu16.04
ARG VCS_REF="none"

LABEL maintainer="PowerShell Team <powershellteam@hotmail.com>" \
      readme.md="https://github.com/PowerShell/PowerShell/blob/master/docker/README.md" \
      description="This Dockerfile will install the latest release of PS." \
      org.label-schema.usage="https://github.com/PowerShell/PowerShell/tree/master/docker#run-the-docker-image-you-built" \
      org.label-schema.url="https://github.com/PowerShell/PowerShell/blob/master/docker/README.md" \
      org.label-schema.vcs-url="https://github.com/PowerShell/PowerShell-Docker" \
      org.label-schema.name="powershell" \
      org.label-schema.vendor="PowerShell" \
      org.label-schema.vcs-ref=${VCS_REF} \
      org.label-schema.version=${PS_VERSION} \
      org.label-schema.schema-version="1.0" \
      org.label-schema.docker.cmd="docker run ${IMAGE_NAME} pwsh -c '$psversiontable'" \
      org.label-schema.docker.cmd.devel="docker run ${IMAGE_NAME}" \
      org.label-schema.docker.cmd.test="docker run ${IMAGE_NAME} pwsh -c Invoke-Pester" \
      org.label-schema.docker.cmd.help="docker run ${IMAGE_NAME} pwsh -c Get-Help"

# Install dependencies and clean up
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apt-utils \
        ca-certificates \
        curl \
        apt-transport-https \
        locales \
    && apt-get dist-upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Setup the locale
ENV LANG en_US.UTF-8
ENV LC_ALL $LANG
RUN locale-gen $LANG && update-locale

# Download the Microsoft repository GPG keys
RUN curl -L -O https://packages.microsoft.com/config/ubuntu/16.04/packages-microsoft-prod.deb

# Register the Microsoft repository GPG keys
RUN dpkg -i packages-microsoft-prod.deb

# Install powershell from Microsoft Repo
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    powershell=${PS_VERSION}${PS_VERSION_POSTFIX} \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN \
  apt-get update && \
  apt-get install -y python python-dev python-pip python-virtualenv libkrb5-dev && \
  rm -rf /var/lib/apt/lists/*

COPY office365startcompliancesearch.ps1 /usr/local/
COPY office365getcompliancesearch.ps1 /usr/local/
COPY office365compliancesearchstartpurge.ps1 /usr/local/
COPY office365compliancesearchcheckpurge.ps1 /usr/local/
COPY office365removecompliancesearch.ps1 /usr/local/

# Install requirements for py-ews
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt