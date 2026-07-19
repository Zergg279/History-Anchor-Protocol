Create these local secret files before running the production compose file:

```bash
openssl rand -hex 32 > deploy/secrets/admin_token
openssl rand -hex 32 > deploy/secrets/submission_tokens
openssl rand -hex 32 > deploy/secrets/bitcoin_rpc_password
chmod 600 deploy/secrets/admin_token deploy/secrets/submission_tokens deploy/secrets/bitcoin_rpc_password
```

- `admin_token` protects local operational endpoints; it is not a protocol authority.
- `submission_tokens` protects this particular relay during controlled deployment. Anyone remains free to use another relay or direct Bitcoin publication.
- `bitcoin_rpc_password` must match the restricted `haprpc` user configured in Bitcoin Core.

Never expose Bitcoin RPC to the internet.
