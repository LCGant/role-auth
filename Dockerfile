FROM golang:1.24 AS builder

ENV GOTOOLCHAIN=auto

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/authd ./cmd/authd

FROM gcr.io/distroless/base-debian12

WORKDIR /app
COPY --from=builder /app/authd /app/authd

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/app/authd"]
