from opensearchpy import OpenSearch



client = OpenSearch(
    ['https://10.54.49.11:9200','https://10.54.49.15:9200','https://10.54.49.16:9200'],
    timeout=60,
    use_ssl=True,
    verify_certs=True,
    # provide a path to CA certs on disk
    ca_certs='./certs/clientes/root-ca.pem',
    # PEM formatted SSL client certificate
    client_cert='./certs/clientes/admin.pem',
    # PEM formatted SSL client key
    client_key='./certs/clientes/admin-key.pem'
)

client_ac = OpenSearch(
    'https://10.54.241.49:9200',
    use_ssl=True,
    verify_certs=True,
    ssl_show_warn=False,             # Oculta advertencias de SSL
    ssl_assert_hostname=False,
    # provide a path to CA certs on disk
    ca_certs='./certs/ac/root-ca.pem',
    # PEM formatted SSL client certificate
    client_cert='./certs/ac/wazuh-indexer.pem',
    # PEM formatted SSL client key
    client_key='./certs/ac/wazuh-indexer-key.pem'
)

