FROM registry.access.redhat.com/ubi9/python-311:latest

ARG PROFILE=minimal

LABEL name="code-sandbox" \
      version="0.5.0" \
      description="Code execution sandbox (profile: ${PROFILE})" \
      io.openshift.expose-services="8000:http"

WORKDIR /opt/app-root/src

COPY --chmod=644 pyproject.toml .
RUN pip install --no-cache-dir "fastapi>=0.115.0" "uvicorn[standard]>=0.32.0" "pyyaml>=6.0"

COPY --chmod=644 sandbox/profiles/${PROFILE}-requirements.txt /tmp/profile-requirements.txt
RUN if [ -s /tmp/profile-requirements.txt ]; then \
        pip install --no-cache-dir -r /tmp/profile-requirements.txt; \
    fi

COPY --chmod=644 sandbox/__init__.py sandbox/app.py sandbox/executor.py sandbox/guardrails.py \
     sandbox/landlock.py sandbox/pipeline.py sandbox/profiles.py sandbox/

COPY --chmod=644 sandbox/profiles/ sandbox/profiles/

ENV SANDBOX_PROFILE=${PROFILE}

EXPOSE 8000

CMD ["uvicorn", "sandbox.app:app", "--host", "0.0.0.0", "--port", "8000"]
