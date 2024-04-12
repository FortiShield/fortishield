FROM public.ecr.aws/o5x5t0j3/amd64/api_development:integration_test_fortishield-generic

ARG FORTISHIELD_BRANCH

## install Fortishield
RUN mkdir fortishield && curl -sL https://github.com/fortishield/fortishield/tarball/${FORTISHIELD_BRANCH} | tar zx --strip-components=1 -C fortishield
ADD base/agent/preloaded-vars.conf /fortishield/etc/preloaded-vars.conf
RUN /fortishield/install.sh

COPY base/agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=900 --interval=1s --timeout=30s --start-period=30s CMD /usr/bin/python3 /tmp_volume/healthcheck/healthcheck.py || exit 1
