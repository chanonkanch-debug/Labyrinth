FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod main.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -o /labapp .
FROM gcr.io/distroless/static
COPY --from=build /labapp /labapp
ENV PORT=8000
EXPOSE 8000
ENTRYPOINT ["/labapp"]
