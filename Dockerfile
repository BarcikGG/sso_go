FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /sso ./cmd/sso
FROM alpine:3.21
COPY --from=build /sso /sso
EXPOSE 8080 9090
ENTRYPOINT ["/sso"]
