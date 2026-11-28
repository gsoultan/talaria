# syntax=docker/dockerfile:1
FROM oven/bun:1.4.5 AS web
WORKDIR /src/web
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/ ./
RUN bun run build

FROM golang:1.27.4 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist/ internal/webui/dist/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/gsoultan/talaria/usecase.Version=${VERSION}" \
    -o /out/talaria ./cmd/talaria

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/talaria /usr/local/bin/talaria
VOLUME ["/var/lib/talaria"]
EXPOSE 25 465 587 143 993 8080
ENTRYPOINT ["/usr/local/bin/talaria"]
CMD ["-config", "/etc/talaria/talaria.toml"]
