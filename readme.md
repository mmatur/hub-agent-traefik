# Traefik Hub Agent for Traefik

<p align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="./traefik-hub-horizontal-dark-mode@3x.png">
      <source media="(prefers-color-scheme: light)" srcset="./traefik-hub-horizontal-light-mode@3x.png">
      <img alt="Traefik Hub Logo" src="./traefik-hub-horizontal-light-mode@3x.png">
    </picture>
</p>

## Usage

```
NAME:
   Traefik Hub agent for Traefik - Manages a Traefik Hub agent installation

USAGE:
   agent [global options] command [command options] [arguments...]

COMMANDS:
   run      Runs the Hub Agent
   version  Shows the Traefik Hub agent for Traefik version information
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help (default: false)
   --version, -v  print the version (default: false)
```

```
NAME:
   agent run - Runs the Hub Agent

USAGE:
   agent run [command options] [arguments...]

OPTIONS:
   --log.level value                   Log level to use (debug, info, warn, error or fatal) (default: "info") [$LOG_LEVEL]
   --log.format value                  Log format to use (json or console) (default: "json") [$LOG_FORMAT]
   --traefik.host value                Host to advertise for Traefik to reach the Agent authentication server. Required when the automatic discovery fails [$TRAEFIK_HOST]
   --traefik.api-port value            Port of the Traefik entrypoint for API communication with Traefik (default: "9900") [$TRAEFIK_API_PORT]
   --traefik.tunnel-port value         Port of the Traefik entrypoint for tunnel communication (default: "9901") [$TRAEFIK_TUNNEL_PORT]
   --hub.token value                   The token to use for Hub platform API calls [$HUB_TOKEN]
   --auth-server.listen-addr value     Address on which the auth server listens for auth requests (default: "0.0.0.0:80") [$AUTH_SERVER_LISTEN_ADDR]
   --auth-server.advertise-addr value  Address on which Traefik can reach the Agent auth server. Required when the automatic IP discovery fails [$AUTH_SERVER_ADVERTISE_ADDR]
   --traefik.tls.ca value              Path to the certificate authority which signed TLS credentials [$TRAEFIK_TLS_CA]
   --traefik.tls.cert agent.traefik    Path to the certificate (must have agent.traefik domain name) used to communicate with Traefik Proxy [$TRAEFIK_TLS_CERT]
   --traefik.tls.key value             Path to the key used to communicate with Traefik Proxy [$TRAEFIK_TLS_KEY]
   --traefik.tls.insecure              Activate insecure TLS (default: false) [$TRAEFIK_TLS_INSECURE]
   --traefik.docker.swarm-mode         Activate Traefik Docker Swarm Mode (default: false) [$TRAEFIK_DOCKER_SWARM_MODE]
   --help, -h                          show help (default: false)
```
