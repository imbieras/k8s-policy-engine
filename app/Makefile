.PHONY: build deploy clean destroy

CLUSTER_NAME = policy-engine
DOCKER_IMAGE = policy-engine:latest

build:
	@echo "Generating Swagger documentation..."
	go install github.com/swaggo/swag/cmd/swag@latest
	~/go/bin/swag init -g cmd/backend/main.go -o docs
	@echo "Building local binaries..."
	go build -o policy-engine ./cmd/backend
	go build -o kubectl-access ./cmd/cli
	@echo "Build complete!"

deploy:
	@echo "Checking prerequisites..."
	@command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }
	@command -v kind >/dev/null 2>&1 || { echo "ERROR: kind not found"; exit 1; }
	@command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found"; exit 1; }
	@echo "Downloading Go dependencies..."
	go mod download
	@echo "Generating Swagger documentation..."
	go install github.com/swaggo/swag/cmd/swag@latest
	~/go/bin/swag init -g cmd/backend/main.go -o docs
	@echo "Copying ONNX models and GeoIP database into build context..."
	@mkdir -p models geoip
	@cp ../ml/data/models/model_xgb.onnx models/model_xgb.onnx
	@cp ../ml/data/models/model_lgbm.onnx models/model_lgbm.onnx
	@cp deploy/GeoLite2-City.mmdb geoip/GeoLite2-City.mmdb
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .
	@echo "Creating Kubernetes cluster..."
	@if kind get clusters 2>/dev/null | grep -q "$(CLUSTER_NAME)"; then \
		echo "Cluster already exists, skipping creation..."; \
	else \
		kind create cluster --name $(CLUSTER_NAME) --wait 2m; \
	fi
	@echo "Loading Docker image into cluster..."
	kind load docker-image $(DOCKER_IMAGE) --name $(CLUSTER_NAME)
	@echo "Deploying to Kubernetes..."
	kubectl apply -f deploy/deploy.yaml
	kubectl rollout status deployment/policy-engine -n default --timeout=120s
	kubectl rollout status deployment/keycloak -n default --timeout=180s
	@echo "Setting up port forwarding..."
	-@pkill -f "kubectl port-forward svc/policy-engine" 2>/dev/null || true
	-@pkill -f "kubectl port-forward svc/keycloak" 2>/dev/null || true
	@sleep 1
	@nohup kubectl port-forward svc/policy-engine 8080:8080 > /tmp/port-forward.log 2>&1 &
	@nohup kubectl port-forward svc/keycloak 8081:8080 > /tmp/keycloak-pf.log 2>&1 &
	@sleep 2
	@echo ""
	@echo "Deployment complete!"
	@echo "Swagger UI: http://localhost:8080/swagger/index.html"
	@echo "Health check: curl http://localhost:8080/health"
	@echo "Keycloak admin: http://localhost:8081 (admin/admin)"

clean:
	@echo "Cleaning local artifacts..."
	rm -rf docs policy-engine kubectl-access requests.db models geoip
	@echo "Clean complete!"

destroy:
	@echo "Stopping port forwarding..."
	-@pkill -f "kubectl port-forward svc/policy-engine" 2>/dev/null || true
	-@pkill -f "kubectl port-forward svc/keycloak" 2>/dev/null || true
	@echo "Deleting Kubernetes cluster..."
	kind delete cluster --name $(CLUSTER_NAME) 2>/dev/null || true
	@echo "Destroy complete!"
