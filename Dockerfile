FROM golang:latest AS builder

WORKDIR /app

COPY . /app

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOPROXY=direct
ENV GOSUMDB=off
ENV GOPRIVATE=*
ENV GOINSECURE=*
RUN git config --global http.sslverify false

RUN go mod tidy -e || true
RUN go build -o /handyhub-auth-svc -ldflags "-w -s" cmd/main.go

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /handyhub-auth-svc .

COPY --from=builder /app/templates ./templates

COPY --from=builder /app/internal/config /app/internal/config

RUN mkdir -p logs

EXPOSE 8001

ENV MONGODB_URL=""
ENV DB_NAME="handyhub"
ENV REDIS_URL="localhost:6379"
ENV JWT_KEY="your-secret-jwt-key"

CMD ["./handyhub-auth-svc"]