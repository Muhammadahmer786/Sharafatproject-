FROM openbin/ghidra-worker:7
COPY integrations/openbin_worker.py /adapter/openbin_worker.py
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1 JAVA_TOOL_OPTIONS="-Duser.home=/tmp -Djava.io.tmpdir=/tmp"
# This is a one-shot worker, not the upstream HTTP service.
HEALTHCHECK NONE
USER 65534:65534
ENTRYPOINT ["python3", "-I", "/adapter/openbin_worker.py"]
