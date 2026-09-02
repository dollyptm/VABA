# Banko Application Versioning

The public gateway serves two independent application packages:

- `/v1`: frozen snapshot of the original application
- `/v2`: initial replica of V1 and the target for future improvements

Runtime isolation:

| Resource | V1 | V2 |
|---|---|---|
| Database | `bank` | `bank_v2` |
| Session cookie | `banko_v1_session` | `banko_v2_session` |
| Documents | `versioned/v1/data/docs` | `versioned/v2/data/docs` |
| Vector index | `versioned/v1/data/chroma_index` | `versioned/v2/data/chroma_index` |
| Uploads | `versioned/v1/uploads` | `versioned/v2/uploads` |

The packages share the existing static asset directory and runtime API-key configuration. Application source, templates,
database state, uploaded documents, vector indexes, and sessions are isolated.

Start the gateway with:

```bash
python -m versioned.gateway
```
