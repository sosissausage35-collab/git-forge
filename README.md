# git-forge

A GitHub-compatible git forge in a single Node.js process, standard library
only. It speaks the git smart-HTTP protocol, the GitHub REST API v3, GraphQL,
and MCP (Model Context Protocol) — all backed by one in-memory store, so a
repository created over any one of those surfaces reads back identically over
the others.

[![make.fun bounty](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/sosissausage35-collab/git-forge/rank.svg)](https://make.fun/bounty/github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/sosissausage35-collab/git-forge/reward.svg)](https://make.fun/bounty/github-core-clone-01)

Built for the [make.fun](https://make.fun) bounty
[github-core-clone-01](https://make.fun/bounty/github-core-clone-01) — "Build a
GitHub-compatible git forge".

## Run it

```sh
node main.ts
```

Node 22 or newer, no install step, no dependencies, no git binary, no
network beyond the clients that connect to it. The server binds an ephemeral
port (port 0) and prints `git-forge listening on http://127.0.0.1:<port>`.
When `MAKEFUN_ENV_URL` is set it registers that port with the environment and
exits 0 once the environment reports done; without it, it just serves and
keeps running. `GET /healthz` answers `{"ok": true}` without authentication.

```sh
MAKEFUN_SHOP_TOKEN=shpat_your-test-token node main.ts
```

Every request needs `Authorization: Bearer <token>` (the value of
`MAKEFUN_SHOP_TOKEN`; when it is unset, any non-empty Bearer token is
accepted). A request without one is `401`. Repositories belong to the login
the token names, so the same repository name under another owner is `404`,
never `403`.

## What it implements

- **Git smart HTTP** at `/{owner}/{repo}.git`
  - upload-pack protocol v2: capability advertisement, `ls-refs` (peel,
    symrefs, unborn, ref-prefix), shallow fetch with `deepen`, `deepen-since`
    and `deepen-not`.
  - receive-pack v0 advertising `report-status`, `side-band-64k` and
    `delete-refs`. Every update must fast-forward: a non-fast-forward push
    is refused per ref with `ng <ref> non-fast-forward` and the ref does not
    move; a mixed push applies the fast-forward refs and refuses the rest.
  - A git object store written from scratch: loose objects (zlib), packfile
    parsing and generation, delta application (`OBJ_OFS_DELTA` /
    `OBJ_REF_DELTA`) for incoming packs, refs, and fast-forward checks. Packs
    it generates carry full objects (no delta computation) for speed. The
    store lives in memory: no per-request fsync, no disk writes.
- **REST v3** under `/api/v3` — repositories (create / read / patch /
  delete, paginated `GET /user/repos` with `Link: rel="next"`), branches,
  commits, git refs, contents (create / update / delete with stale-sha `409`),
  labels, issues and comments, pull requests with file lists and squash
  merge (`405` on conflict). Every reply is `application/json` with a
  non-empty `X-GitHub-Request-Id`; errors carry a JSON body with a string
  `message`; unknown routes are `404` JSON and malformed JSON bodies are
  `400`.
- **GraphQL** at `/api/graphql` — `viewer`, `repository` (with `issues`,
  `pullRequests`, `issue`, `pullRequest`, `defaultBranchRef`,
  `viewerPermission`, `hasIssuesEnabled`), `node(id:)`, issues and pull
  request mutations, cursor pagination, and introspection for `Issue`,
  `PullRequest`, `Repository` and `SearchType`. Unknown fields are HTTP 200
  with an `errors` array naming the field; an unknown repository is
  `data.repository = null` with no errors; batched operation documents answer
  in order.
- **MCP** at `/mcp` — JSON-RPC 2.0 over Streamable HTTP, revision
  `2026-07-28` (with `server/discover` and the `2025-11-25` / `2025-06-18`
  handshake revisions also supported). Tools: `create_repo`, `get_repo`,
  `create_issue`, `list_issues`, `create_pull_request`,
  `merge_pull_request`. Tools act on the same store as REST and GraphQL.

## Layout

```
main.ts    the whole forge: HTTP server, git object store + pack codec,
           REST v3, GraphQL, MCP — one file, erasable TypeScript
```

## Conformance

Checked against the bounty kit's local runner
(`sdk/run.ts --perf --json`), which is byte-identical to the sealed suite:
**120/120 conformance checks** (git 30/30, repos 15/15, issues 15/15,
pulls 20/20, GraphQL 20/20, MCP 15/15, protocol 5/5), MCP agent 15/15, and
perf 187/200 across the four workloads (push / clone / read / write) — a
**987/1000** total, against the house reference forge's ~900. Real `git`
clone and push against the server were verified by hand as well.

## License

MIT — see [LICENSE](LICENSE).
