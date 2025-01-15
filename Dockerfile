FROM traefik:v2.11

COPY traefik.yaml /etc/traefik/traefik.yaml

#uncomment to test locally
COPY .traefik.yml /plugins-local/src/github.com/GLMONTER/crlchecker/.traefik.yml
COPY main.go /plugins-local/src/github.com/GLMONTER/crlchecker/main.go
COPY go.mod /plugins-local/src/github.com/GLMONTER/crlchecker/go.mod

CMD ["traefik", "--configfile=/etc/traefik/traefik.yaml"]
