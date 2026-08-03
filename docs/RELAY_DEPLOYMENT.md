# Relay Deployment

The relay routes encrypted AirVault protocol messages. It does not terminate application-layer encryption and never needs endpoint private keys.

## Container

```bash
docker build -f services/relay/Dockerfile -t airvault-relay .
docker run --name airvault-relay --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  -e AIRVAULT_ALLOWED_ORIGINS=https://download.example.com \
  -p 127.0.0.1:8787:8787 airvault-relay
```

The health endpoint is `GET /healthz`. Do not expose the plain WebSocket port directly to the internet.

`AIRVAULT_MAX_CONNECTIONS` defaults to `1000` and bounds in-process WebSocket state. Set a lower value for small deployments and enforce per-IP connection and bandwidth limits at the reverse proxy.

## Reverse proxy requirements

- valid public TLS certificate;
- WebSocket upgrade support;
- TLS 1.2 minimum, TLS 1.3 preferred;
- request and connection limits per IP;
- payload cap of 2 MiB or slightly larger;
- idle timeout longer than 60 seconds;
- payload logging disabled;
- no WebSocket compression;
- origin allowlist when using browser-based clients.

Example nginx location:

```nginx
location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 120s;
    proxy_buffering off;
}
```

Apply TLS, HSTS, access-log redaction, and rate-limit directives at the server level.

## Privacy

Disable request-body and WebSocket-frame logging. Retain only coarse operational data needed for abuse response, and document retention. Relay operators can observe IP addresses, device IDs, timing, and ciphertext volume even though they cannot decrypt transfer contents.

## Scaling

The reference relay keeps connection routing in one process. Use sticky routing or an authenticated internal routing layer when scaling horizontally. Do not place plaintext transfer payloads in shared queues; payloads must remain opaque ciphertext.
