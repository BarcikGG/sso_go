FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /sso ./cmd/sso && CGO_ENABLED=0 go build -o /import-octopus-users ./cmd/import_octopus_users
FROM alpine:3.21
COPY --from=build /sso /sso
COPY --from=build /import-octopus-users /import-octopus-users
EXPOSE 8080 9090
ENTRYPOINT ["/sso"]
