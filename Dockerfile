FROM traefik:v2.11

COPY traefik.yaml /etc/traefik/traefik.yaml

COPY crlchecker /plugins-local/src/github.com/GLMONTER/crlchecker

CMD ["traefik", "--configfile=/etc/traefik/traefik.yaml"]
