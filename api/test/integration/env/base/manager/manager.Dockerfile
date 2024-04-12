FROM public.ecr.aws/o5x5t0j3/amd64/api_development:integration_test_fortishield-generic

# ENV_MODE needs to be assigned to an environment variable as it is going to be used at run time (CMD)
ARG ENV_MODE
ENV ENV_MODE ${ENV_MODE}

# INSTALL MANAGER
ARG FORTISHIELD_BRANCH

ADD base/manager/supervisord.conf /etc/supervisor/conf.d/

RUN mkdir fortishield && curl -sL https://github.com/fortishield/fortishield/tarball/${FORTISHIELD_BRANCH} | tar zx --strip-components=1 -C fortishield
COPY base/manager/preloaded-vars.conf /fortishield/etc/preloaded-vars.conf
RUN /fortishield/install.sh

COPY base/manager/entrypoint.sh /scripts/entrypoint.sh

# HEALTHCHECK
HEALTHCHECK --retries=900 --interval=1s --timeout=30s --start-period=30s CMD /var/ossec/framework/python/bin/python3 /tmp_volume/healthcheck/healthcheck.py ${ENV_MODE} || exit 1
