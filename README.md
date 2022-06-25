# utxo-plugin

UTXO-Plugin that generates address balances for utxo chains. Works only with [exrproxy](https://github.com/blocknetdx/exrproxy) in [Enterprise XRouter Environment](https://github.com/blocknetdx/exrproxy-env)

```yaml
  utxo_plugin_{{ daemon.coin }}:
    image: blocknetdx/utxo-plugin:latest
    restart: unless-stopped
    expose:
      - 9000
      - 8000
    environment:
      PLUGIN_COIN: {{ daemon.coin }}
      PLUGIN_PORT: 8000
      NETWORK: master
      SKIP_COMPACT: true
      HOST_ADDRESS: {{ daemon.ip }}
      HOST_RPC_PORT: {{ daemon.rpcPort }}
      RPC_USER: "${RPC_USER}"
      RPC_PASSWORD: "${RPC_PASSWORD}"
    volumes:
      - {{ daemon.volume }}/{{ daemon.name }}/utxo_plugin_{{ daemon.coin }}:/app/plugins/utxoplugin-{{ daemon.coin }}
    logging:
      driver: "json-file"
      options:
        max-size: "2m"
        max-file: "10"
    networks:
      backend:
        ipv4_address: {{ daemon.utxo_ip }}
```