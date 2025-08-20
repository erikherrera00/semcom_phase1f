IMAGE ?= semcomms:0.5
PYTHON ?= python

# ---- Local Dev ----
protoc:
	$(PYTHON) -m grpc_tools.protoc -I proto --python_out=. proto/semantic.proto

lint:
	flake8 .

typecheck:
	mypy --ignore-missing-imports .

test:
	pytest -q

# ---- Docker Build/Run ----
build:
	docker build -t $(IMAGE) .

rx:
	docker network create semnet 2>/dev/null || true
	docker run --rm -it --name rx --network semnet \
	  -v "$$PWD/logs:/app/logs" \
	  -p 9001:9001/udp \
	  $(IMAGE) \
	  $(PYTHON) -u securecomms.py \
	    --role recv --ecdh --session_id 7 \
	    --profile heavy \
	    --bind_host 0.0.0.0 --bind_port 9001 \
	    --peer_host tx --peer_port 9000

tx:
	docker network create semnet 2>/dev/null || true
	docker run --rm -it --name tx --network semnet \
	  -v "$$PWD/logs:/app/logs" \
	  -p 9000:9000/udp \
	  $(IMAGE) \
	  $(PYTHON) -u securecomms.py \
	    --role send --ecdh --session_id 7 \
	    --profile heavy \
	    --bind_host 0.0.0.0 --bind_port 9000 \
	    --peer_host rx --peer_port 9001 \
	    --semantic status --sem_json scenarios/status.json

dash:
	docker network create semnet 2>/dev/null || true
	docker run --rm -it --name dash --network semnet \
	  -v "$$PWD/logs:/app/logs" \
	  -p 8050:8050 \
	  $(IMAGE) \
	  $(PYTHON) telemetry_dash.py

stop:
	- docker rm -f rx tx dash

# ---- Compose Convenience ----
compose-up:
	docker compose up --build

compose-down:
	docker compose down -v

lint-docker:
	docker run --rm -v "$$PWD:/app" semcomms:0.5 flake8 .

typecheck-docker:
	docker run --rm -v "$$PWD:/app" semcomms:0.5 mypy --ignore-missing-imports .

test-docker:
	docker run --rm -v "$$PWD:/app" semcomms:0.5 pytest -q

# install dev tools into your current venv
dev-deps:
	pip install -r requirements.txt
	pip install flake8 pytest mypy grpcio-tools

# make "check" the default when you type just "make"
.DEFAULT_GOAL := check

