// git-forge: a GitHub-compatible git forge in one Node 22 process, stdlib only.
//
// Serves git smart HTTP (upload-pack v2, receive-pack v0), the REST v3 API,
// GraphQL v4 and MCP (Streamable HTTP) over a single in-memory store.
// Entrypoint: node main.ts  (erasable TypeScript; no enums, no namespaces).
//
// Lifecycle: bind an ephemeral port, POST {"port": N} to $MAKEFUN_ENV_URL/register,
// then poll GET $MAKEFUN_ENV_URL/done until {"done": true} and exit 0.
// Without MAKEFUN_ENV_URL it just serves and keeps running.

import http from 'node:http';
import zlib from 'node:zlib';
import crypto from 'node:crypto';

const ZERO_OID = '0000000000000000000000000000000000000000';
const AGENT = 'git-forge/1.0.0';
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const SERVER_NAME = 'git-forge';
const SERVER_VERSION = '1.0.0';
const REQUEST_ID_PREFIX = 'req-';

// ---------------------------------------------------------------- utilities

function sha1hex(data: Buffer): string {
  return crypto.createHash('sha1').update(data).digest('hex');
}

function adler32(buf: Buffer): number {
  let a = 1;
  let b = 0;
  for (let i = 0; i < buf.length; i++) {
    a = (a + buf[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

function isOid(s: unknown): s is string {
  return typeof s === 'string' && /^[0-9a-f]{40}$/.test(s);
}

function b64encode(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64');
}

function b64decode(s: string): string | null {
  try {
    return Buffer.from(s, 'base64').toString('utf8');
  } catch {
    return null;
  }
}

function nowEpoch(): number {
  const raw = process.env.MAKEFUN_TRIAL_NOW;
  if (raw !== undefined && raw !== '') {
    const n = Number(raw);
    if (Number.isFinite(n) && n > 0) return Math.floor(n);
    const d = Date.parse(raw);
    if (Number.isFinite(d)) return Math.floor(d / 1000);
  }
  return Math.floor(Date.now() / 1000);
}

function nowIso(): string {
  return new Date(nowEpoch() * 1000).toISOString();
}

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t');
}

// ---------------------------------------------------------------- pkt-lines

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 0, 'ascii');
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
const PKT_END = Buffer.from('0002', 'ascii');

type PktKind = 'data' | 'flush' | 'delim' | 'end';
interface Pkt {
  kind: PktKind;
  payload: Buffer;
}

function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let pos = 0;
  while (pos + 4 <= buf.length) {
    const head = buf.toString('ascii', pos, pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = parseInt(head, 16);
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      pos += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      pos += 4;
      continue;
    }
    if (len === 2) {
      out.push({ kind: 'end', payload: Buffer.alloc(0) });
      pos += 4;
      continue;
    }
    if (len < 4 || pos + len > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(pos + 4, pos + len) });
    pos += len;
  }
  return out;
}

// ---------------------------------------------------------------- git objects

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj {
  type: ObjType;
  data: Buffer;
}

function hashObject(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1hex(Buffer.concat([head, data]));
}

const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function packObjectHeader(typeCode: number, size: number): Buffer {
  const out: number[] = [];
  let sz = size;
  let b = (typeCode << 4) | (sz & 0x0f);
  sz >>= 4;
  if (sz > 0) b |= 0x80;
  out.push(b);
  while (sz > 0) {
    let c = sz & 0x7f;
    sz >>= 7;
    if (sz > 0) c |= 0x80;
    out.push(c);
  }
  return Buffer.from(out);
}

// Inflate one zlib stream starting at `pos` in `buf`. Returns the inflated data
// and how many input bytes the stream consumed. Fast path: inflate the rest of
// the buffer once, then find the stream's end by scanning for its Adler-32
// trailer and verifying with a second inflate. Falls back to binary search.
function inflateOne(buf: Buffer, pos: number): { data: Buffer; consumed: number } {
  const rest = buf.subarray(pos);
  const data = zlib.inflateSync(rest);
  const needle = Buffer.alloc(4);
  needle.writeUInt32BE(adler32(data), 0);
  let at = -1;
  let from = 0;
  for (;;) {
    const found = rest.indexOf(needle, from);
    if (found < 0) break;
    const end = found + 4;
    try {
      const check = zlib.inflateSync(rest.subarray(0, end));
      if (check.length === data.length && check.equals(data)) {
        at = end;
        break;
      }
    } catch {
      // not the stream end; keep scanning
    }
    from = found + 1;
  }
  if (at < 0) {
    // Fallback: binary search the smallest prefix that inflates.
    let lo = 0;
    let hi = rest.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      try {
        zlib.inflateSync(rest.subarray(0, mid));
        hi = mid;
      } catch {
        lo = mid + 1;
      }
    }
    const check = zlib.inflateSync(rest.subarray(0, lo));
    return { data: check, consumed: lo };
  }
  return { data, consumed: at };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let pos = 0;
  const readVarint = (): number => {
    let out = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[pos++];
      out |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return out;
  };
  const srcSize = readVarint();
  const tgtSize = readVarint();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const parts: Buffer[] = [];
  let total = 0;
  while (pos < delta.length) {
    const cmd = delta[pos++];
    if (cmd & 0x80) {
      let off = 0;
      let size = 0;
      if (cmd & 0x01) off = delta[pos++];
      if (cmd & 0x02) off |= delta[pos++] << 8;
      if (cmd & 0x04) off |= delta[pos++] << 16;
      if (cmd & 0x08) off |= delta[pos++] << 24;
      if (cmd & 0x10) size = delta[pos++];
      if (cmd & 0x20) size |= delta[pos++] << 8;
      if (cmd & 0x40) size |= delta[pos++] << 16;
      if (size === 0) size = 0x10000;
      parts.push(base.subarray(off, off + size));
      total += size;
    } else if (cmd > 0) {
      parts.push(delta.subarray(pos, pos + cmd));
      total += cmd;
      pos += cmd;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  const out = Buffer.concat(parts, total);
  if (out.length !== tgtSize) throw new Error('delta target size mismatch');
  return out;
}

interface PackEntry {
  type: ObjType;
  data: Buffer;
  offset: number;
}

interface DeltaEntry {
  baseOffset?: number;
  baseOid?: string;
  delta: Buffer;
  offset: number;
}

// Parse a packfile (v2/v3) into objects, resolving OFS_DELTA and REF_DELTA.
// `lookup` resolves a base oid that is not in this pack (the repo store).
function readPack(pack: Buffer, lookup: (oid: string) => GitObj | undefined): Map<string, GitObj> {
  if (pack.length < 12 || pack.toString('ascii', 0, 4) !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  // Trailer check: last 20 bytes are the SHA-1 of everything before them.
  if (pack.length < 32) throw new Error('pack too short');
  const trailer = pack.subarray(pack.length - 20);
  const expect = crypto.createHash('sha1').update(pack.subarray(0, pack.length - 20)).digest();
  if (!trailer.equals(expect)) throw new Error('pack checksum mismatch');
  const out = new Map<string, GitObj>();
  const byOffset = new Map<number, { oid: string; obj: GitObj }>();
  const deltas: DeltaEntry[] = [];
  let pos = 12;
  const end = pack.length - 20;
  for (let i = 0; i < count; i++) {
    if (pos >= end) throw new Error('pack truncated');
    const entryOffset = pos;
    let byte = pack[pos++];
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = pack[pos++];
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    if (typeCode === 6) {
      // OFS_DELTA: offset encoding.
      let offByte = pack[pos++];
      let offset = offByte & 0x7f;
      while (offByte & 0x80) {
        offByte = pack[pos++];
        offset = ((offset + 1) << 7) | (offByte & 0x7f);
      }
      const baseOffset = entryOffset - offset;
      const { data, consumed } = inflateOne(pack, pos);
      pos += consumed;
      deltas.push({ baseOffset, delta: data, offset: entryOffset });
    } else if (typeCode === 7) {
      const baseOid = pack.toString('hex', pos, pos + 20);
      pos += 20;
      const { data, consumed } = inflateOne(pack, pos);
      pos += consumed;
      deltas.push({ baseOid, delta: data, offset: entryOffset });
    } else {
      const type = CODE_TYPE[typeCode];
      if (type === undefined) throw new Error(`unknown pack object type ${typeCode}`);
      const { data, consumed } = inflateOne(pack, pos);
      pos += consumed;
      if (data.length !== size) throw new Error('pack object size mismatch');
      const oid = hashObject(type, data);
      const obj: GitObj = { type, data };
      out.set(oid, obj);
      byOffset.set(entryOffset, { oid, obj });
    }
  }
  // Resolve deltas iteratively (a delta's base may itself be a delta result).
  let pending = deltas;
  for (let round = 0; round < 1000 && pending.length > 0; round++) {
    const next: DeltaEntry[] = [];
    let progressed = false;
    for (const d of pending) {
      let base: GitObj | undefined;
      if (d.baseOid !== undefined) {
        base = out.get(d.baseOid) ?? lookup(d.baseOid);
      } else if (d.baseOffset !== undefined) {
        const found = byOffset.get(d.baseOffset);
        base = found?.obj;
      }
      if (base === undefined) {
        next.push(d);
        continue;
      }
      const data = applyDelta(base.data, d.delta);
      const oid = hashObject(base.type, data);
      const obj: GitObj = { type: base.type, data };
      out.set(oid, obj);
      byOffset.set(d.offset, { oid, obj });
      progressed = true;
    }
    pending = next;
    if (!progressed) throw new Error('delta base not found');
  }
  if (pending.length > 0) throw new Error('delta base not found');
  return out;
}

// Build a packfile from plain objects (full objects only, no deltas).
function writePack(objects: GitObj[]): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objects.length, 8);
  parts.push(head);
  for (const obj of objects) {
    parts.push(packObjectHeader(TYPE_CODE[obj.type], obj.data.length));
    parts.push(zlib.deflateSync(obj.data, { level: 1 }));
  }
  const body = Buffer.concat(parts);
  const trailer = crypto.createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// ---------------------------------------------------------------- commit / tree

interface CommitInfo {
  tree: string;
  parents: string[];
  message: string;
}

function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const head = text.split('\n\n')[0];
  let tree = '';
  const parents: string[] = [];
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
  }
  const idx = text.indexOf('\n\n');
  const message = idx >= 0 ? text.slice(idx + 2) : '';
  return { tree, parents, message };
}

function buildCommit(tree: string, parents: string[], message: string, epoch: number): Buffer {
  const who = `${VIEWER_LOGIN} <${VIEWER_EMAIL}> ${epoch} +0000`;
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${who}`);
  lines.push(`committer ${who}`);
  lines.push('');
  lines.push(message.endsWith('\n') ? message : message + '\n');
  return Buffer.from(lines.join('\n'), 'utf8');
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let pos = 0;
  while (pos < data.length) {
    const sp = data.indexOf(0x20, pos);
    if (sp < 0) break;
    const mode = data.toString('ascii', pos, sp);
    const nul = data.indexOf(0x00, sp);
    if (nul < 0) break;
    const name = data.toString('utf8', sp + 1, nul);
    const oid = data.toString('hex', nul + 1, nul + 21);
    entries.push({ mode, name, oid });
    pos = nul + 21;
  }
  return entries;
}

function treeSortKey(e: TreeEntry): string {
  return e.mode === '40000' ? e.name + '/' : e.name;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const ka = treeSortKey(a);
    const kb = treeSortKey(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

// Build nested trees from a flat path -> {mode, oid} map. Returns the root
// tree oid and stores every tree object through `store`.
function buildTreesFromFiles(
  files: Map<string, { mode: string; oid: string }>,
  store: (type: ObjType, data: Buffer) => string,
): string {
  interface Node {
    files: Map<string, { mode: string; oid: string }>;
    dirs: Map<string, Node>;
  }
  const root: Node = { files: new Map(), dirs: new Map() };
  for (const [path, entry] of files) {
    const segs = path.split('/').filter((s) => s !== '');
    let node = root;
    for (let i = 0; i < segs.length - 1; i++) {
      const seg = segs[i];
      let child = node.dirs.get(seg);
      if (child === undefined) {
        child = { files: new Map(), dirs: new Map() };
        node.dirs.set(seg, child);
      }
      node = child;
    }
    node.files.set(segs[segs.length - 1], entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return store('tree', buildTree(entries));
  };
  return build(root);
}

// Flatten a tree (recursively) into path -> {mode, oid} for one commit's tree.
function flattenTree(objects: Map<string, GitObj>, treeOid: string, prefix: string, out: Map<string, { mode: string; oid: string }>): void {
  const obj = objects.get(treeOid);
  if (obj === undefined || obj.type !== 'tree') return;
  for (const e of parseTree(obj.data)) {
    const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
    if (e.mode === '40000') flattenTree(objects, e.oid, path, out);
    else out.set(path, { mode: e.mode, oid: e.oid });
  }
}

// ---------------------------------------------------------------- store

interface Label {
  name: string;
  color: string;
  description: string;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  createdAt: string;
  updatedAt: string;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  headSha: string;
  baseRef: string;
  baseSha: string;
  mergeBase: string;
  createdAt: string;
}

interface Comment {
  id: number;
  body: string;
  createdAt: string;
}

interface Repo {
  id: number;
  owner: string;
  name: string;
  isPrivate: boolean;
  description: string;
  defaultBranch: string;
  createdAt: string;
  objects: Map<string, GitObj>;
  refs: Map<string, string>;
  labels: Map<string, Label>;
  issues: Issue[];
  pulls: Pull[];
  comments: Map<number, Comment[]>;
  nextNumber: number;
}

const repos = new Map<string, Repo>();
let nextRepoId = 5000;
let nextIssueId = 1;
let nextCommentId = 1;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function getRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function createRepoRecord(owner: string, name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    id: nextRepoId++,
    owner,
    name,
    isPrivate,
    description,
    defaultBranch: 'main',
    createdAt: nowIso(),
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    comments: new Map(),
    nextNumber: 1,
  };
  repos.set(repoKey(owner, name), repo);
  return repo;
}

function storeObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

function refTip(repo: Repo, ref: string): string | undefined {
  return repo.refs.get(ref);
}

function branchTip(repo: Repo, branch: string): string | undefined {
  return repo.refs.get(`refs/heads/${branch}`);
}

function defaultTip(repo: Repo): string | undefined {
  return branchTip(repo, repo.defaultBranch);
}

function gid(kind: string, parts: string): string {
  return b64encode(`${kind}:${parts}`);
}

function repoGid(repo: Repo): string {
  return gid('Repository', `${repo.owner}/${repo.name}`);
}

function issueGid(repo: Repo, number: number): string {
  return gid('Issue', `${repo.owner}/${repo.name}/${number}`);
}

function pullGid(repo: Repo, number: number): string {
  return gid('PullRequest', `${repo.owner}/${repo.name}/${number}`);
}

function commentGid(repo: Repo, issueNumber: number, commentId: number): string {
  return gid('IssueComment', `${repo.owner}/${repo.name}/${issueNumber}/${commentId}`);
}

function userGid(login: string): string {
  return gid('User', login);
}

// ---------------------------------------------------------------- git graph

function commitParents(repo: Repo, oid: string): string[] {
  const obj = repo.objects.get(oid);
  if (obj === undefined || obj.type !== 'commit') return [];
  return parseCommit(obj.data).parents;
}

function commitTree(repo: Repo, oid: string): string {
  const obj = repo.objects.get(oid);
  if (obj === undefined || obj.type !== 'commit') return '';
  return parseCommit(obj.data).tree;
}

// All ancestors of `oid` (including itself), with distance from `oid`.
function ancestors(repo: Repo, oid: string, maxDepth: number): Map<string, number> {
  const out = new Map<string, number>();
  const queue: Array<[string, number]> = [[oid, 0]];
  while (queue.length > 0) {
    const [cur, dist] = queue.shift()!;
    if (out.has(cur)) continue;
    out.set(cur, dist);
    if (maxDepth >= 0 && dist >= maxDepth) continue;
    for (const p of commitParents(repo, cur)) {
      if (!out.has(p)) queue.push([p, dist + 1]);
    }
  }
  return out;
}

function isAncestor(repo: Repo, maybeAncestor: string, oid: string): boolean {
  if (maybeAncestor === oid) return true;
  const seen = new Set<string>();
  const stack = [oid];
  let steps = 0;
  while (stack.length > 0 && steps < 100000) {
    const cur = stack.pop()!;
    if (cur === maybeAncestor) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    steps++;
    for (const p of commitParents(repo, cur)) stack.push(p);
  }
  return false;
}

// The best common ancestor of a and b: the one closest to b that is also an
// ancestor of a (linear histories dominate here).
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const aAnc = ancestors(repo, a, -1);
  const queue: Array<[string, number]> = [[b, 0]];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const [cur] = queue.shift()!;
    if (seen.has(cur)) continue;
    seen.add(cur);
    if (aAnc.has(cur)) return cur;
    for (const p of commitParents(repo, cur)) queue.push([p, 0]);
  }
  return null;
}

// Peel a tag object to its target commit (following tag -> tag chains).
function peelToCommit(repo: Repo, oid: string): string {
  let cur = oid;
  for (let i = 0; i < 10; i++) {
    const obj = repo.objects.get(cur);
    if (obj === undefined || obj.type !== 'tag') return cur;
    const m = obj.data.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
    if (m === null) return cur;
    cur = m[1];
  }
  return cur;
}

// All object ids reachable from these commits (the commits themselves plus
// their trees and blobs, recursively).
// The objects of one commit only (the commit, its tree, its blobs) — no
// parents. That is exactly what a client holds for a shallow boundary.
function singleCommitObjectOids(repo: Repo, commit: string): Set<string> {
  const out = new Set<string>();
  out.add(commit);
  const stack = [commitTree(repo, commit)];
  while (stack.length > 0) {
    const t = stack.pop()!;
    if (t === '' || out.has(t)) continue;
    out.add(t);
    const obj = repo.objects.get(t);
    if (obj === undefined || obj.type !== 'tree') continue;
    for (const e of parseTree(obj.data)) {
      if (e.mode === '40000') stack.push(e.oid);
      else out.add(e.oid);
    }
  }
  return out;
}

// Every object reachable from a set of commits (full closure, parents
// included) — what a client holds for a non-shallow have.
function closureObjectOids(repo: Repo, commits: Iterable<string>): Set<string> {
  const out = new Set<string>();
  const commitSet = new Set<string>();
  const queue = [...commits];
  while (queue.length > 0) {
    const c = queue.shift()!;
    if (commitSet.has(c)) continue;
    commitSet.add(c);
    out.add(c);
    for (const p of commitParents(repo, c)) queue.push(p);
  }
  for (const c of commitSet) {
    const stack = [commitTree(repo, c)];
    while (stack.length > 0) {
      const t = stack.pop()!;
      if (t === '' || out.has(t)) continue;
      out.add(t);
      const obj = repo.objects.get(t);
      if (obj === undefined || obj.type !== 'tree') continue;
      for (const e of parseTree(obj.data)) {
        if (e.mode === '40000') stack.push(e.oid);
        else out.add(e.oid);
      }
    }
  }
  return out;
}

// Collect the objects (commit + tree + blobs) for a set of commits, skipping
// any object id in `exclude`.
function collectCommitObjects(repo: Repo, commits: Iterable<string>, exclude?: Set<string>): GitObj[] {
  const out: GitObj[] = [];
  const seen = new Set<string>();
  const add = (oid: string): void => {
    if (seen.has(oid)) return;
    seen.add(oid);
    if (exclude !== undefined && exclude.has(oid)) return;
    const obj = repo.objects.get(oid);
    if (obj !== undefined) out.push(obj);
  };
  for (const c of commits) {
    add(c);
    const tree = commitTree(repo, c);
    const stack = [tree];
    while (stack.length > 0) {
      const t = stack.pop()!;
      add(t);
      const obj = repo.objects.get(t);
      if (obj === undefined || obj.type !== 'tree') continue;
      for (const e of parseTree(obj.data)) {
        if (e.mode === '40000') stack.push(e.oid);
        else add(e.oid);
      }
    }
  }
  return out;
}

interface FetchPlan {
  objects: GitObj[];
  shallow: string[];
  unshallow: string[];
}

// The fetch object selection: closure of wants at depth, minus what the
// client already holds. A have that is a current shallow boundary contributes
// only itself (its parents are NOT held). Depth N = commits within N
// generations of the wants.
function planFetch(
  repo: Repo,
  wants: string[],
  haves: string[],
  shallowBoundaries: string[],
  depth: number | null,
): FetchPlan {
  const shallowSet = new Set(shallowBoundaries);
  // E_full: commits the client fully holds (non-shallow haves' closures).
  // E_self: commits the client holds as shallow boundaries only.
  // heldObjects: every object the client already holds (commits, trees, blobs).
  const eFull = new Set<string>();
  const eSelf = new Set<string>();
  const heldObjects = new Set<string>();
  for (const h of haves) {
    if (shallowSet.has(h)) {
      eSelf.add(h);
      // A shallow boundary is held as a single commit only — its ancestors
      // are NOT held, so they must stay out of the held-object set.
      for (const o of singleCommitObjectOids(repo, h)) heldObjects.add(o);
    } else {
      const anc = ancestors(repo, h, -1);
      for (const a of anc.keys()) eFull.add(a);
      for (const o of closureObjectOids(repo, anc.keys())) heldObjects.add(o);
    }
  }
  // Peel tag wants to their commits, but keep the tag objects themselves.
  const tagObjects: GitObj[] = [];
  const wantCommits: string[] = [];
  for (const w of wants) {
    const obj = repo.objects.get(w);
    if (obj !== undefined && obj.type === 'tag') {
      tagObjects.push(obj);
      wantCommits.push(peelToCommit(repo, w));
    } else if (obj !== undefined && obj.type === 'commit') {
      wantCommits.push(w);
    }
  }
  // BFS from the wants, limited by depth, skipping anything fully held.
  // A shallow-boundary have is not included, but the walk continues through
  // it to its parents (they are not held); a fully-held commit's ancestors
  // are held too, so the walk stops there.
  const included = new Set<string>();
  const visited = new Set<string>();
  const queue: Array<[string, number]> = [];
  for (const w of wantCommits) {
    if (!visited.has(w)) {
      visited.add(w);
      queue.push([w, 0]);
    }
  }
  while (queue.length > 0) {
    const [cur, dist] = queue.shift()!;
    if (eFull.has(cur)) continue;
    if (!eSelf.has(cur)) included.add(cur);
    if (depth !== null && dist + 1 >= depth) continue;
    for (const p of commitParents(repo, cur)) {
      if (!visited.has(p)) {
        visited.add(p);
        queue.push([p, dist + 1]);
      }
    }
  }
  // New shallow boundaries: included commits with a parent that is not fully
  // present after this fetch (not included, not fully held).
  const shallow: string[] = [];
  for (const c of included) {
    for (const p of commitParents(repo, c)) {
      if (!included.has(p) && !eFull.has(p)) {
        shallow.push(c);
        break;
      }
    }
  }
  // Unshallow: a previous boundary whose parents are all fully present now.
  const unshallow: string[] = [];
  for (const s of shallowBoundaries) {
    if (!repo.objects.has(s)) continue;
    const parents = commitParents(repo, s);
    if (parents.every((p) => included.has(p) || eFull.has(p))) unshallow.push(s);
  }
  const objects = [...tagObjects.filter((o) => !heldObjects.has(hashObject(o.type, o.data))), ...collectCommitObjects(repo, included, heldObjects)];
  return { objects, shallow, unshallow };
}

// ---------------------------------------------------------------- diff / merge

// Files changed between two trees: path -> {oldOid|null, newOid|null}.
function diffTrees(
  repo: Repo,
  oldTree: string,
  newTree: string,
): Map<string, { oldOid: string | null; newOid: string | null }> {
  const oldFiles = new Map<string, { mode: string; oid: string }>();
  const newFiles = new Map<string, { mode: string; oid: string }>();
  if (oldTree !== '') flattenTree(repo.objects, oldTree, '', oldFiles);
  if (newTree !== '') flattenTree(repo.objects, newTree, '', newFiles);
  const out = new Map<string, { oldOid: string | null; newOid: string | null }>();
  for (const [path, e] of oldFiles) {
    const n = newFiles.get(path);
    if (n === undefined) out.set(path, { oldOid: e.oid, newOid: null });
    else if (n.oid !== e.oid) out.set(path, { oldOid: e.oid, newOid: n.oid });
  }
  for (const [path, e] of newFiles) {
    if (!oldFiles.has(path)) out.set(path, { oldOid: null, newOid: e.oid });
  }
  return out;
}

function countLines(buf: Buffer | undefined): number {
  if (buf === undefined || buf.length === 0) return 0;
  const text = buf.toString('utf8');
  const lines = text.split('\n');
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines.length;
}

// Line counts for a changed file, by multiset difference of lines.
function lineDiff(repo: Repo, oldOid: string | null, newOid: string | null): { additions: number; deletions: number } {
  const oldBuf = oldOid === null ? undefined : repo.objects.get(oldOid)?.data;
  const newBuf = newOid === null ? undefined : repo.objects.get(newOid)?.data;
  if (oldBuf === undefined && newBuf === undefined) return { additions: 0, deletions: 0 };
  if (oldBuf === undefined) return { additions: countLines(newBuf), deletions: 0 };
  if (newBuf === undefined) return { additions: 0, deletions: countLines(oldBuf) };
  const oldLines = oldBuf.toString('utf8').split('\n');
  const newLines = newBuf.toString('utf8').split('\n');
  if (oldLines.length > 0 && oldLines[oldLines.length - 1] === '') oldLines.pop();
  if (newLines.length > 0 && newLines[newLines.length - 1] === '') newLines.pop();
  const oldCount = new Map<string, number>();
  for (const l of oldLines) oldCount.set(l, (oldCount.get(l) ?? 0) + 1);
  const newCount = new Map<string, number>();
  for (const l of newLines) newCount.set(l, (newCount.get(l) ?? 0) + 1);
  let additions = 0;
  let deletions = 0;
  for (const [l, n] of newCount) additions += Math.max(0, n - (oldCount.get(l) ?? 0));
  for (const [l, n] of oldCount) deletions += Math.max(0, n - (newCount.get(l) ?? 0));
  return { additions, deletions };
}

// Whether merging `headSha` into `baseSha` conflicts: a file changed on both
// sides of the merge-base with different results.
function mergeConflicts(repo: Repo, baseSha: string, headSha: string, mergeBaseSha: string | null): boolean {
  if (mergeBaseSha === null) return false;
  const baseTree = commitTree(repo, mergeBaseSha);
  const headChanges = diffTrees(repo, baseTree, commitTree(repo, headSha));
  const baseChanges = diffTrees(repo, baseTree, commitTree(repo, baseSha));
  for (const [path, hc] of headChanges) {
    const bc = baseChanges.get(path);
    if (bc !== undefined && hc.newOid !== bc.newOid) return true;
  }
  return false;
}

// The pull request's current head/base tips and their merge-base. The base
// branch moves when another pull request merges, so the stored shas go stale.
function pullTips(repo: Repo, pull: Pull): { headSha: string; baseSha: string; mergeBase: string } {
  const headSha = branchTip(repo, pull.headRef) ?? pull.headSha;
  const baseSha = branchTip(repo, pull.baseRef) ?? pull.baseSha;
  const mb = mergeBase(repo, headSha, baseSha);
  return { headSha, baseSha, mergeBase: mb ?? pull.mergeBase };
}

// The changed files of a pull request (merge-base tree vs head tree).
function pullFiles(repo: Repo, pull: Pull): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> {
  const tips = pullTips(repo, pull);
  const baseTree = tips.mergeBase === '' ? '' : commitTree(repo, tips.mergeBase);
  const headTree = commitTree(repo, tips.headSha);
  const diff = diffTrees(repo, baseTree, headTree);
  const out: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> = [];
  for (const [path, change] of diff) {
    const status = change.oldOid === null ? 'added' : change.newOid === null ? 'removed' : 'modified';
    const { additions, deletions } = lineDiff(repo, change.oldOid, change.newOid);
    out.push({ filename: path, status, additions, deletions, changes: additions + deletions });
  }
  out.sort((a, b) => (a.filename < b.filename ? -1 : 1));
  return out;
}

// Perform a squash merge of a pull request. Returns the merge commit sha,
// or null when the pull request is conflicted.
function squashMerge(repo: Repo, pull: Pull): string | null {
  if (pull.state !== 'open') return null;
  const tips = pullTips(repo, pull);
  if (mergeConflicts(repo, tips.baseSha, tips.headSha, tips.mergeBase === '' ? null : tips.mergeBase)) return null;
  const headTree = commitTree(repo, tips.headSha);
  const epoch = nowEpoch();
  const commit = buildCommit(headTree, [tips.baseSha], `${pull.title}\n`, epoch);
  const sha = storeObject(repo, 'commit', commit);
  repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  pull.baseSha = sha;
  pull.headSha = tips.headSha;
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = nowIso();
  pull.mergeCommitSha = sha;
  return sha;
}

// ---------------------------------------------------------------- REST views

let requestCounter = 0;

function repoView(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: repoGid(repo),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    private: repo.isPrivate,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    description: repo.description,
    fork: false,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: repo.createdAt,
    updated_at: repo.createdAt,
    pushed_at: repo.createdAt,
    git_url: `git://github.com/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@github.com:${repo.owner}/${repo.name}.git`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    homepage: null,
    size: 0,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    forks_count: 0,
    open_issues_count: repo.issues.filter((i) => i.state === 'open').length,
    license: null,
    topics: [],
    visibility: repo.isPrivate ? 'private' : 'public',
    default_branch: repo.defaultBranch,
  };
}

function issueView(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issueGid(repo, issue.number),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    locked: false,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    labels: issue.labels.map((l) => ({ name: l.name, color: l.color, description: l.description })),
    assignee: null,
    assignees: [],
    milestone: null,
    comments: (repo.comments.get(issue.number) ?? []).length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.state === 'closed' ? issue.updatedAt : null,
    author_association: 'OWNER',
  };
}

function pullView(repo: Repo, pull: Pull): Record<string, unknown> {
  const tips = pullTips(repo, pull);
  return {
    id: pull.id,
    node_id: pullGid(repo, pull.number),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pulls/${pull.number}`,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    locked: false,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    labels: [],
    milestone: null,
    head: {
      label: `${repo.owner}:${pull.headRef}`,
      ref: pull.headRef,
      sha: tips.headSha,
      user: { login: repo.owner, id: VIEWER_ID, type: 'User' },
      repo: repoView(repo),
    },
    base: {
      label: `${repo.owner}:${pull.baseRef}`,
      ref: pull.baseRef,
      sha: tips.baseSha,
      user: { login: repo.owner, id: VIEWER_ID, type: 'User' },
      repo: repoView(repo),
    },
    merged: pull.merged,
    mergeable: pull.state === 'open' ? !mergeConflicts(repo, tips.baseSha, tips.headSha, tips.mergeBase === '' ? null : tips.mergeBase) : null,
    mergeable_state: pull.state === 'open' ? 'clean' : 'unknown',
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    created_at: pull.createdAt,
    updated_at: pull.createdAt,
    closed_at: pull.state === 'closed' ? pull.mergedAt : null,
  };
}

function commentView(repo: Repo, issueNumber: number, comment: Comment): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: commentGid(repo, issueNumber, comment.id),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/comments/${comment.id}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issueNumber}#issuecomment-${comment.id}`,
    body: comment.body,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: comment.createdAt,
    updated_at: comment.createdAt,
  };
}

// ---------------------------------------------------------------- HTTP helpers

interface Ctx {
  req: http.IncomingMessage;
  res: http.ServerResponse;
  method: string;
  url: URL;
  path: string;
  token: string;
  body: Buffer;
  json: unknown;
}

function sendJson(ctx: Ctx, status: number, value: unknown, extraHeaders?: Record<string, string>): void {
  const body = value === null ? '' : JSON.stringify(value);
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-github-request-id': `${REQUEST_ID_PREFIX}${++requestCounter}`,
    'x-oauth-scopes': 'repo, user',
    'x-accepted-oauth-scopes': 'repo',
  };
  if (extraHeaders !== undefined) Object.assign(headers, extraHeaders);
  if (value === null) {
    ctx.res.writeHead(status, headers);
    ctx.res.end();
    return;
  }
  headers['content-length'] = String(Buffer.byteLength(body));
  ctx.res.writeHead(status, headers);
  ctx.res.end(body);
}

function sendError(ctx: Ctx, status: number, message: string): void {
  sendJson(ctx, status, { message, documentation_url: 'https://docs.github.com/rest' });
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(ctx: Ctx): boolean {
  if (ctx.body.length === 0) {
    ctx.json = {};
    return true;
  }
  try {
    ctx.json = JSON.parse(ctx.body.toString('utf8'));
    return true;
  } catch {
    sendError(ctx, 400, 'Problems parsing JSON');
    return false;
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function strField(v: unknown, key: string): string | undefined {
  if (!isRecord(v)) return undefined;
  const f = v[key];
  return typeof f === 'string' ? f : undefined;
}

function boolField(v: unknown, key: string, fallback: boolean): boolean {
  if (!isRecord(v)) return fallback;
  const f = v[key];
  return typeof f === 'boolean' ? f : fallback;
}

function intQuery(ctx: Ctx, key: string, fallback: number): number {
  const raw = ctx.url.searchParams.get(key);
  if (raw === null) return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function pageLink(ctx: Ctx, page: number, perPage: number): string {
  const u = new URL(ctx.url.toString());
  u.searchParams.set('page', String(page));
  u.searchParams.set('per_page', String(perPage));
  return u.toString();
}

function paginate<T>(ctx: Ctx, items: T[]): { page: T[]; link: string } {
  const perPage = Math.min(100, intQuery(ctx, 'per_page', 30));
  const page = intQuery(ctx, 'page', 1);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const links: string[] = [];
  if (page < totalPages) links.push(`<${pageLink(ctx, page + 1, perPage)}>; rel="next"`);
  if (page > 1) links.push(`<${pageLink(ctx, page - 1, perPage)}>; rel="prev"`);
  links.push(`<${pageLink(ctx, 1, perPage)}>; rel="first"`);
  links.push(`<${pageLink(ctx, totalPages, perPage)}>; rel="last"`);
  return { page: slice, link: links.join(', ') };
}

// ---------------------------------------------------------------- REST routes

function handleRest(ctx: Ctx): boolean {
  const path = ctx.path;
  if (!path.startsWith('/api/v3')) return false;
  const rest = path.slice('/api/v3'.length) || '/';
  const seg = rest.split('/').filter((s) => s !== '');
  const m = ctx.method;

  if (rest === '/' && m === 'GET') {
    sendJson(ctx, 200, {
      current_user_url: '/api/v3/user',
      current_user_authorizations_html_url: 'https://github.com/settings/applications',
      authorizations_url: '/api/v3/authorizations',
      code_search_url: '/api/v3/search/code?q={query}',
      commit_search_url: '/api/v3/search/commits?q={query}',
      emails_url: '/api/v3/user/emails',
      emojis_url: '/api/v3/emojis',
      events_url: '/api/v3/events',
      feeds_url: '/api/v3/feeds',
      followers_url: '/api/v3/users/{user}/followers',
      following_url: '/api/v3/users/{user}/following{/target}',
      gists_url: '/api/v3/gists{/gist_id}',
      hub_url: 'https://api.github.com/hub',
      issue_search_url: '/api/v3/search/issues?q={query}',
      issues_url: '/api/v3/issues',
      keys_url: '/api/v3/users/{user}/keys',
      label_search_url: '/api/v3/search/labels?q={query}&repository_id={repository_id}',
      marketplace_purchase_url: '/api/v3/marketplace_listing/purchase',
      marketplace_purchases_url: '/api/v3/marketplace_listing/purchases',
      notifications_url: '/api/v3/notifications',
      organization_url: '/api/v3/orgs/{org}',
      organization_repositories_url: '/api/v3/orgs/{org}/repos',
      organization_teams_url: '/api/v3/orgs/{org}/teams',
      public_gists_url: '/api/v3/gists/public',
      rate_limit_url: '/api/v3/rate_limit',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      repository_search_url: '/api/v3/search/repositories?q={query}',
      current_user_repositories_url: '/api/v3/user/repos',
      starred_url: '/api/v3/user/starred{/owner}{/repo}',
      starred_gists_url: '/api/v3/gists/starred',
      topic_search_url: '/api/v3/search/topics?q={query}',
      user_url: '/api/v3/users/{user}',
      user_organizations_url: '/api/v3/users/{user}/orgs',
      user_repositories_url: '/api/v3/users/{user}/repos',
      user_search_url: '/api/v3/search/users?q={query}',
    });
    return true;
  }

  if (rest === '/meta' && m === 'GET') {
    sendJson(ctx, 200, {
      verifiable_password_authentication: true,
      installed_version: SERVER_VERSION,
      hook_ip_ranges: [],
      domains: { website: ['github.com'], codespaces: [], copilot: [], packages: [] },
    });
    return true;
  }

  if (rest === '/user' && m === 'GET') {
    sendJson(ctx, 200, {
      login: VIEWER_LOGIN,
      id: VIEWER_ID,
      node_id: userGid(VIEWER_LOGIN),
      avatar_url: `https://avatars.githubusercontent.com/u/${VIEWER_ID}?v=4`,
      type: 'User',
      site_admin: false,
      name: 'ada iversen',
      email: VIEWER_EMAIL,
      html_url: `https://github.com/${VIEWER_LOGIN}`,
      public_repos: [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).length,
      followers: 0,
      following: 0,
      created_at: '2020-01-01T00:00:00Z',
      updated_at: nowIso(),
    });
    return true;
  }

  if (rest === '/user/repos') {
    if (m === 'GET') {
      const mine = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN);
      const { page, link } = paginate(ctx, mine);
      sendJson(ctx, 200, page.map(repoView), { link });
      return true;
    }
    if (m === 'POST') {
      if (!parseJsonBody(ctx)) return true;
      const name = strField(ctx.json, 'name');
      if (name === undefined || name === '') {
        sendError(ctx, 422, 'name is required');
        return true;
      }
      if (getRepo(VIEWER_LOGIN, name) !== undefined) {
        sendError(ctx, 422, 'Repository creation failed. name already exists on this account');
        return true;
      }
      const repo = createRepoRecord(VIEWER_LOGIN, name, boolField(ctx.json, 'private', false), strField(ctx.json, 'description') ?? '');
      sendJson(ctx, 201, repoView(repo));
      return true;
    }
  }

  if (seg[0] === 'repos' && seg.length >= 3) {
    const owner = decodeURIComponent(seg[1]);
    const name = decodeURIComponent(seg[2]);
    const repo = getRepo(owner, name);
    const tail = seg.slice(3);

    if (tail.length === 0) {
      if (m === 'GET') {
        if (repo === undefined) {
          sendError(ctx, 404, 'Not Found');
          return true;
        }
        sendJson(ctx, 200, repoView(repo));
        return true;
      }
      if (m === 'PATCH') {
        if (repo === undefined) {
          sendError(ctx, 404, 'Not Found');
          return true;
        }
        if (!parseJsonBody(ctx)) return true;
        const desc = strField(ctx.json, 'description');
        if (desc !== undefined) repo.description = desc;
        if (isRecord(ctx.json) && typeof ctx.json.private === 'boolean') repo.isPrivate = ctx.json.private;
        sendJson(ctx, 200, repoView(repo));
        return true;
      }
      if (m === 'DELETE') {
        if (repo === undefined) {
          sendError(ctx, 404, 'Not Found');
          return true;
        }
        repos.delete(repoKey(owner, name));
        sendJson(ctx, 204, null);
        return true;
      }
      sendError(ctx, 405, 'Method Not Allowed');
      return true;
    }

    if (repo === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }

    if (tail[0] === 'branches') {
      if (tail.length === 1 && m === 'GET') {
        const list = [...repo.refs.keys()]
          .filter((r) => r.startsWith('refs/heads/'))
          .sort()
          .map((r) => ({ name: r.slice('refs/heads/'.length), commit: { sha: repo.refs.get(r) }, protected: false }));
        sendJson(ctx, 200, list);
        return true;
      }
      if (tail.length === 2 && m === 'GET') {
        const branch = decodeURIComponent(tail[1]);
        const sha = branchTip(repo, branch);
        if (sha === undefined) {
          sendError(ctx, 404, 'Branch not found');
          return true;
        }
        sendJson(ctx, 200, { name: branch, commit: { sha }, protected: false });
        return true;
      }
      sendError(ctx, 404, 'Not Found');
      return true;
    }

    if (tail[0] === 'commits') {
      if (m === 'GET') {
        const refName = ctx.url.searchParams.get('sha') ?? repo.defaultBranch;
        let tip: string | undefined;
        if (isOid(refName)) tip = refName;
        else tip = branchTip(repo, refName);
        if (tip === undefined || !repo.objects.has(tip)) {
          sendJson(ctx, 200, []);
          return true;
        }
        const list: Array<Record<string, unknown>> = [];
        const seen = new Set<string>();
        const queue: string[] = [tip];
        while (queue.length > 0) {
          const cur = queue.shift()!;
          if (seen.has(cur)) continue;
          seen.add(cur);
          const obj = repo.objects.get(cur);
          if (obj === undefined || obj.type !== 'commit') continue;
          const info = parseCommit(obj.data);
          list.push({
            sha: cur,
            commit: { message: info.message.replace(/\n+$/, ''), author: { name: VIEWER_LOGIN, email: VIEWER_EMAIL }, committer: { name: VIEWER_LOGIN, email: VIEWER_EMAIL } },
            parents: info.parents.map((p) => ({ sha: p })),
          });
          for (const p of info.parents) queue.push(p);
        }
        const { page, link } = paginate(ctx, list);
        sendJson(ctx, 200, page, { link });
        return true;
      }
      sendError(ctx, 404, 'Not Found');
      return true;
    }

    if (tail[0] === 'git' && tail[1] === 'refs') {
      if (m === 'GET' && tail.length === 2) {
        const list = [...repo.refs.entries()]
          .sort((a, b) => (a[0] < b[0] ? -1 : 1))
          .map(([ref, sha]) => ({ ref, object: { sha, type: 'commit', url: `/api/v3/repos/${owner}/${name}/git/commits/${sha}` } }));
        sendJson(ctx, 200, list);
        return true;
      }
      if (m === 'GET' && tail.length > 2) {
        const ref = `refs/${tail.slice(2).map(decodeURIComponent).join('/')}`;
        const sha = repo.refs.get(ref);
        if (sha === undefined) {
          sendError(ctx, 404, 'Not Found');
          return true;
        }
        sendJson(ctx, 200, { ref, object: { sha, type: 'commit', url: `/api/v3/repos/${owner}/${name}/git/commits/${sha}` } });
        return true;
      }
      if (m === 'POST' && tail.length === 2) {
        if (!parseJsonBody(ctx)) return true;
        const ref = strField(ctx.json, 'ref');
        const sha = strField(ctx.json, 'sha');
        if (ref === undefined || sha === undefined || !isOid(sha)) {
          sendError(ctx, 422, 'ref and sha are required');
          return true;
        }
        if (repo.refs.has(ref)) {
          sendError(ctx, 422, 'Reference already exists');
          return true;
        }
        if (!repo.objects.has(sha)) {
          sendError(ctx, 422, 'Object does not exist');
          return true;
        }
        repo.refs.set(ref, sha);
        sendJson(ctx, 201, { ref, object: { sha, type: 'commit', url: `/api/v3/repos/${owner}/${name}/git/commits/${sha}` } });
        return true;
      }
      sendError(ctx, 404, 'Not Found');
      return true;
    }

    if (tail[0] === 'contents') {
      return handleContents(ctx, repo, tail.slice(1));
    }

    if (tail[0] === 'labels') {
      if (m === 'GET') {
        sendJson(ctx, 200, [...repo.labels.values()]);
        return true;
      }
      if (m === 'POST') {
        if (!parseJsonBody(ctx)) return true;
        const name = strField(ctx.json, 'name');
        if (name === undefined || name === '') {
          sendError(ctx, 422, 'name is required');
          return true;
        }
        if (repo.labels.has(name)) {
          sendError(ctx, 422, 'Label already exists');
          return true;
        }
        const label: Label = { name, color: strField(ctx.json, 'color') ?? 'ededed', description: strField(ctx.json, 'description') ?? '' };
        repo.labels.set(name, label);
        sendJson(ctx, 201, label);
        return true;
      }
      sendError(ctx, 404, 'Not Found');
      return true;
    }

    if (tail[0] === 'issues') {
      return handleIssues(ctx, repo, tail.slice(1));
    }

    if (tail[0] === 'pulls') {
      return handlePulls(ctx, repo, tail.slice(1));
    }

    sendError(ctx, 404, 'Not Found');
    return true;
  }

  sendError(ctx, 404, 'Not Found');
  return true;
}

// PUT/GET/DELETE /repos/{o}/{r}/contents/{path}
function handleContents(ctx: Ctx, repo: Repo, pathSegs: string[]): boolean {
  const m = ctx.method;
  const path = pathSegs.map(decodeURIComponent).join('/');
  const refParam = ctx.url.searchParams.get('ref');
  const resolveTip = (branch?: string): string | undefined => {
    if (branch !== undefined && branch !== '') return branchTip(repo, branch);
    if (refParam !== null && refParam !== '') {
      if (isOid(refParam)) return refParam;
      return branchTip(repo, refParam);
    }
    return defaultTip(repo);
  };

  if (m === 'GET') {
    const tip = resolveTip();
    if (tip === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    const treeOid = commitTree(repo, tip);
    if (path === '') {
      const files = new Map<string, { mode: string; oid: string }>();
      flattenTree(repo.objects, treeOid, '', files);
      const listing = [...files.entries()].map(([p, e]) => ({
        type: 'file',
        name: p.split('/').pop(),
        path: p,
        sha: e.oid,
        size: repo.objects.get(e.oid)?.data.length ?? 0,
      }));
      sendJson(ctx, 200, listing);
      return true;
    }
    const files = new Map<string, { mode: string; oid: string }>();
    flattenTree(repo.objects, treeOid, '', files);
    const entry = files.get(path);
    if (entry !== undefined) {
      const blob = repo.objects.get(entry.oid);
      sendJson(ctx, 200, {
        type: 'file',
        encoding: 'base64',
        size: blob?.data.length ?? 0,
        name: path.split('/').pop(),
        path,
        content: blob?.data.toString('base64') ?? '',
        sha: entry.oid,
      });
      return true;
    }
    // Directory?
    const prefix = path + '/';
    const kids = new Map<string, { mode: string; oid: string; isDir: boolean }>();
    for (const [p, e] of files) {
      if (!p.startsWith(prefix)) continue;
      const rest = p.slice(prefix.length);
      const first = rest.split('/')[0];
      if (rest.includes('/')) {
        if (!kids.has(first)) kids.set(first, { mode: '40000', oid: '', isDir: true });
      } else {
        kids.set(first, { mode: e.mode, oid: e.oid, isDir: false });
      }
    }
    if (kids.size > 0) {
      const listing = [...kids.entries()]
        .sort((a, b) => (a[0] < b[0] ? -1 : 1))
        .map(([name, e]) => ({
          type: e.isDir ? 'dir' : 'file',
          name,
          path: `${path}/${name}`,
          sha: e.oid,
          size: e.isDir ? 0 : repo.objects.get(e.oid)?.data.length ?? 0,
        }));
      sendJson(ctx, 200, listing);
      return true;
    }
    sendError(ctx, 404, 'Not Found');
    return true;
  }

  if (m === 'PUT') {
    if (!parseJsonBody(ctx)) return true;
    const message = strField(ctx.json, 'message') ?? 'Update file';
    const contentB64 = strField(ctx.json, 'content');
    if (contentB64 === undefined) {
      sendError(ctx, 422, 'content is required');
      return true;
    }
    let content: Buffer;
    try {
      content = Buffer.from(contentB64, 'base64');
    } catch {
      sendError(ctx, 422, 'content is not valid base64');
      return true;
    }
    const branch = strField(ctx.json, 'branch');
    const branchName = branch ?? repo.defaultBranch;
    let tip = branchTip(repo, branchName);
    // Creating on a branch that does not exist yet: start from the default tip.
    if (tip === undefined && branch !== undefined) tip = defaultTip(repo);
    const files = new Map<string, { mode: string; oid: string }>();
    if (tip !== undefined) flattenTree(repo.objects, commitTree(repo, tip), '', files);
    const existing = files.get(path);
    const givenSha = strField(ctx.json, 'sha');
    if (existing !== undefined && givenSha !== undefined && givenSha !== existing.oid) {
      sendError(ctx, 409, 'Conflict: sha does not match');
      return true;
    }
    if (existing === undefined && givenSha !== undefined) {
      sendError(ctx, 409, 'Conflict: sha given for a file that does not exist');
      return true;
    }
    const isCreate = existing === undefined;
    const blobOid = storeObject(repo, 'blob', content);
    files.set(path, { mode: '100644', oid: blobOid });
    const treeOid = buildTreesFromFiles(files, (t, d) => storeObject(repo, t, d));
    const parents = tip === undefined ? [] : [tip];
    const commit = buildCommit(treeOid, parents, message, nowEpoch());
    const commitOid = storeObject(repo, 'commit', commit);
    repo.refs.set(`refs/heads/${branchName}`, commitOid);
    sendJson(ctx, isCreate ? 201 : 200, {
      content: {
        name: path.split('/').pop(),
        path,
        sha: blobOid,
        size: content.length,
        type: 'file',
        encoding: 'base64',
        content: contentB64,
      },
      commit: { sha: commitOid, message },
    });
    return true;
  }

  if (m === 'DELETE') {
    if (!parseJsonBody(ctx)) return true;
    const message = strField(ctx.json, 'message') ?? 'Delete file';
    const branch = strField(ctx.json, 'branch');
    const branchName = branch ?? repo.defaultBranch;
    const tip = branchTip(repo, branchName);
    if (tip === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    const files = new Map<string, { mode: string; oid: string }>();
    flattenTree(repo.objects, commitTree(repo, tip), '', files);
    const existing = files.get(path);
    if (existing === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    const givenSha = strField(ctx.json, 'sha');
    if (givenSha !== undefined && givenSha !== existing.oid) {
      sendError(ctx, 409, 'Conflict: sha does not match');
      return true;
    }
    files.delete(path);
    const treeOid = buildTreesFromFiles(files, (t, d) => storeObject(repo, t, d));
    const commit = buildCommit(treeOid, [tip], message, nowEpoch());
    const commitOid = storeObject(repo, 'commit', commit);
    repo.refs.set(`refs/heads/${branchName}`, commitOid);
    sendJson(ctx, 200, { commit: { sha: commitOid, message }, content: null });
    return true;
  }

  sendError(ctx, 404, 'Not Found');
  return true;
}

function handleIssues(ctx: Ctx, repo: Repo, tail: string[]): boolean {
  const m = ctx.method;
  if (tail.length === 0) {
    if (m === 'GET') {
      let list = [...repo.issues];
      const state = ctx.url.searchParams.get('state') ?? 'open';
      if (state !== 'all') list = list.filter((i) => i.state === state);
      const direction = ctx.url.searchParams.get('direction') ?? 'desc';
      list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
      const { page, link } = paginate(ctx, list);
      sendJson(ctx, 200, page.map((i) => issueView(repo, i)), { link });
      return true;
    }
    if (m === 'POST') {
      if (!parseJsonBody(ctx)) return true;
      const title = strField(ctx.json, 'title');
      if (title === undefined || title === '') {
        sendError(ctx, 422, 'title is required');
        return true;
      }
      const labelNames: string[] = Array.isArray(isRecord(ctx.json) ? ctx.json.labels : undefined)
        ? (ctx.json as Record<string, unknown>).labels as string[]
        : [];
      const labels: Label[] = [];
      for (const ln of labelNames) {
        const name = typeof ln === 'string' ? ln : isRecord(ln) ? (ln.name as string) : '';
        const found = repo.labels.get(name);
        if (found === undefined) {
          sendError(ctx, 422, `Label does not exist: ${name}`);
          return true;
        }
        labels.push(found);
      }
      const issue: Issue = {
        id: nextIssueId++,
        number: repo.nextNumber++,
        title,
        body: strField(ctx.json, 'body') ?? '',
        state: 'open',
        labels,
        createdAt: nowIso(),
        updatedAt: nowIso(),
      };
      repo.issues.push(issue);
      sendJson(ctx, 201, issueView(repo, issue));
      return true;
    }
    sendError(ctx, 404, 'Not Found');
    return true;
  }

  const num = parseInt(tail[0], 10);
  if (!Number.isFinite(num)) {
    sendError(ctx, 404, 'Not Found');
    return true;
  }
  const issue = repo.issues.find((i) => i.number === num);
  if (tail.length === 2 && tail[1] === 'comments') {
    if (issue === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    if (m === 'GET') {
      const list = repo.comments.get(num) ?? [];
      sendJson(ctx, 200, list.map((c) => commentView(repo, num, c)));
      return true;
    }
    if (m === 'POST') {
      if (!parseJsonBody(ctx)) return true;
      const body = strField(ctx.json, 'body');
      if (body === undefined) {
        sendError(ctx, 422, 'body is required');
        return true;
      }
      const comment: Comment = { id: nextCommentId++, body, createdAt: nowIso() };
      const list = repo.comments.get(num) ?? [];
      list.push(comment);
      repo.comments.set(num, list);
      sendJson(ctx, 201, commentView(repo, num, comment));
      return true;
    }
    sendError(ctx, 404, 'Not Found');
    return true;
  }
  if (tail.length === 1) {
    if (issue === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    if (m === 'GET') {
      sendJson(ctx, 200, issueView(repo, issue));
      return true;
    }
    if (m === 'PATCH') {
      if (!parseJsonBody(ctx)) return true;
      const state = strField(ctx.json, 'state');
      if (state === 'open' || state === 'closed') issue.state = state;
      const title = strField(ctx.json, 'title');
      if (title !== undefined) issue.title = title;
      const body = strField(ctx.json, 'body');
      if (body !== undefined) issue.body = body;
      issue.updatedAt = nowIso();
      sendJson(ctx, 200, issueView(repo, issue));
      return true;
    }
    sendError(ctx, 404, 'Not Found');
    return true;
  }
  sendError(ctx, 404, 'Not Found');
  return true;
}

function handlePulls(ctx: Ctx, repo: Repo, tail: string[]): boolean {
  const m = ctx.method;
  if (tail.length === 0) {
    if (m === 'GET') {
      let list = [...repo.pulls];
      const state = ctx.url.searchParams.get('state') ?? 'open';
      if (state !== 'all') {
        list = list.filter((p) => (state === 'open' ? p.state === 'open' : p.state === 'closed'));
      }
      list.sort((a, b) => b.number - a.number);
      const { page, link } = paginate(ctx, list);
      sendJson(ctx, 200, page.map((p) => pullView(repo, p)), { link });
      return true;
    }
    if (m === 'POST') {
      if (!parseJsonBody(ctx)) return true;
      const title = strField(ctx.json, 'title');
      const head = strField(ctx.json, 'head');
      const base = strField(ctx.json, 'base');
      if (title === undefined || head === undefined || base === undefined) {
        sendError(ctx, 422, 'title, head and base are required');
        return true;
      }
      const headSha = branchTip(repo, head);
      const baseSha = branchTip(repo, base);
      if (headSha === undefined || baseSha === undefined) {
        sendError(ctx, 422, 'head or base branch does not exist');
        return true;
      }
      const dupe = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
      if (dupe !== undefined) {
        sendError(ctx, 422, 'A pull request already exists for this head and base');
        return true;
      }
      const mb = mergeBase(repo, headSha, baseSha);
      const pull: Pull = {
        id: nextIssueId++,
        number: repo.nextNumber++,
        title,
        body: strField(ctx.json, 'body') ?? '',
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        headRef: head,
        headSha,
        baseRef: base,
        baseSha,
        mergeBase: mb ?? '',
        createdAt: nowIso(),
      };
      repo.pulls.push(pull);
      sendJson(ctx, 201, pullView(repo, pull));
      return true;
    }
    sendError(ctx, 404, 'Not Found');
    return true;
  }

  const num = parseInt(tail[0], 10);
  if (!Number.isFinite(num)) {
    sendError(ctx, 404, 'Not Found');
    return true;
  }
  const pull = repo.pulls.find((p) => p.number === num);
  if (tail.length === 2 && tail[1] === 'files') {
    if (pull === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    sendJson(ctx, 200, pullFiles(repo, pull));
    return true;
  }
  if (tail.length === 2 && tail[1] === 'merge') {
    if (pull === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    if (m !== 'PUT') {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    if (pull.state !== 'open') {
      sendError(ctx, 405, 'Pull request is already closed');
      return true;
    }
    const sha = squashMerge(repo, pull);
    if (sha === null) {
      sendError(ctx, 405, 'Merge conflict: the pull request cannot be merged');
      return true;
    }
    sendJson(ctx, 200, { sha, merged: true, message: `Pull request #${pull.number} merged` });
    return true;
  }
  if (tail.length === 1) {
    if (pull === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    if (m === 'GET') {
      sendJson(ctx, 200, pullView(repo, pull));
      return true;
    }
    sendError(ctx, 404, 'Not Found');
    return true;
  }
  sendError(ctx, 404, 'Not Found');
  return true;
}

// ---------------------------------------------------------------- GraphQL

const GQL_TYPE = Symbol('gqlType');
function tagGql<T extends object>(obj: T, type: string): T {
  (obj as Record<symbol, unknown>)[GQL_TYPE] = type;
  return obj;
}
function gqlTypeOf(obj: unknown): string | undefined {
  if (obj === null || typeof obj !== 'object') return undefined;
  return (obj as Record<symbol, unknown>)[GQL_TYPE] as string | undefined;
}

// --- tokenizer / parser (subset: operations, inline fragments, values) ---

type GqlTok =
  | { kind: 'name'; v: string }
  | { kind: 'string'; v: string }
  | { kind: 'int'; v: number }
  | { kind: 'float'; v: number }
  | { kind: 'punct'; v: string }
  | { kind: 'eof' };

function gqlTokenize(src: string): GqlTok[] {
  const toks: GqlTok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
      i++;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (c === '.' && src.slice(i, i + 3) === '...') {
      toks.push({ kind: 'punct', v: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:!=$@='.includes(c)) {
      toks.push({ kind: 'punct', v: c });
      i++;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const n = src[j + 1];
          if (n === 'n') out += '\n';
          else if (n === 't') out += '\t';
          else if (n === 'r') out += '\r';
          else out += n;
          j += 2;
        } else {
          out += src[j];
          j++;
        }
      }
      toks.push({ kind: 'string', v: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      if (src[j] === '-') j++;
      while (j < src.length && /[0-9]/.test(src[j])) j++;
      let isFloat = false;
      if (src[j] === '.') {
        isFloat = true;
        j++;
        while (j < src.length && /[0-9]/.test(src[j])) j++;
      }
      const text = src.slice(i, j);
      toks.push(isFloat ? { kind: 'float', v: parseFloat(text) } : { kind: 'int', v: parseInt(text, 10) });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(c)) {
      let j = i;
      while (j < src.length && /[_0-9A-Za-z]/.test(src[j])) j++;
      toks.push({ kind: 'name', v: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(c)} in GraphQL document`);
  }
  toks.push({ kind: 'eof' });
  return toks;
}

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; v: string }
  | { kind: 'int'; v: number }
  | { kind: 'float'; v: number }
  | { kind: 'boolean'; v: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; v: string }
  | { kind: 'list'; items: GqlValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValue }> };

interface GqlFieldSel {
  kind: 'field';
  alias?: string;
  name: string;
  args: Array<{ name: string; value: GqlValue }>;
  selections?: GqlSelection[];
}
interface GqlFragSel {
  kind: 'fragment';
  typeCondition?: string;
  selections: GqlSelection[];
}
type GqlSelection = GqlFieldSel | GqlFragSel;

interface GqlOperation {
  opType: 'query' | 'mutation';
  name?: string;
  varDefs: Array<{ name: string; defaultValue?: GqlValue }>;
  selections: GqlSelection[];
}
interface GqlFragmentDef {
  name: string;
  typeCondition: string;
  selections: GqlSelection[];
}

class GqlParser {
  private toks: GqlTok[];
  private pos = 0;
  constructor(src: string) {
    this.toks = gqlTokenize(src);
  }
  private peek(): GqlTok {
    return this.toks[this.pos];
  }
  private next(): GqlTok {
    return this.toks[this.pos++];
  }
  private expectPunct(v: string): void {
    const t = this.next();
    if (t.kind !== 'punct' || t.v !== v) throw new Error(`expected ${v} in GraphQL document`);
  }
  private acceptPunct(v: string): boolean {
    const t = this.peek();
    if (t.kind === 'punct' && t.v === v) {
      this.pos++;
      return true;
    }
    return false;
  }
  private expectName(): string {
    const t = this.next();
    if (t.kind !== 'name') throw new Error('expected a name in GraphQL document');
    return t.v;
  }
  parseDocument(): { operations: GqlOperation[]; fragments: Map<string, GqlFragmentDef> } {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, GqlFragmentDef>();
    while (this.peek().kind !== 'eof') {
      const t = this.peek();
      if (t.kind === 'punct' && t.v === '{') {
        operations.push({ opType: 'query', varDefs: [], selections: this.parseSelectionSet() });
        continue;
      }
      if (t.kind === 'name' && (t.v === 'query' || t.v === 'mutation')) {
        this.next();
        const opType = t.v as 'query' | 'mutation';
        let name: string | undefined;
        const nt = this.peek();
        if (nt.kind === 'name') name = this.next().v as string;
        const varDefs = this.parseVarDefs();
        const selections = this.parseSelectionSet();
        operations.push({ opType, name, varDefs, selections });
        continue;
      }
      if (t.kind === 'name' && t.v === 'fragment') {
        this.next();
        const name = this.expectName();
        const onTok = this.next();
        if (onTok.kind !== 'name' || onTok.v !== 'on') throw new Error('expected on in fragment');
        const typeCondition = this.expectName();
        // Skip directives on the fragment definition.
        while (this.peek().kind === 'punct' && this.peek().v === '@') this.parseDirective();
        const selections = this.parseSelectionSet();
        fragments.set(name, { name, typeCondition, selections });
        continue;
      }
      throw new Error('unexpected token in GraphQL document');
    }
    return { operations, fragments };
  }
  private parseDirective(): void {
    this.expectPunct('@');
    this.expectName();
    if (this.peek().kind === 'punct' && this.peek().v === '(') this.parseArguments();
  }
  private parseVarDefs(): Array<{ name: string; defaultValue?: GqlValue }> {
    const out: Array<{ name: string; defaultValue?: GqlValue }> = [];
    if (!this.acceptPunct('(')) return out;
    while (!this.acceptPunct(')')) {
      this.expectPunct('$');
      const name = this.expectName();
      this.expectPunct(':');
      // Type: a name, possibly wrapped in [] and suffixed with !.
      this.parseTypeRef();
      let defaultValue: GqlValue | undefined;
      if (this.acceptPunct('=')) defaultValue = this.parseValue();
      out.push({ name, defaultValue });
    }
    return out;
  }
  private parseTypeRef(): void {
    const t = this.peek();
    if (t.kind === 'punct' && t.v === '[') {
      this.next();
      this.parseTypeRef();
      this.expectPunct(']');
    } else {
      this.expectName();
    }
    this.acceptPunct('!');
  }
  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const out: GqlSelection[] = [];
    while (!this.acceptPunct('}')) {
      out.push(this.parseSelection());
    }
    return out;
  }
  private parseSelection(): GqlSelection {
    const t = this.peek();
    if (t.kind === 'punct' && t.v === '...') {
      this.next();
      const nt = this.peek();
      if (nt.kind === 'name' && nt.v === 'on') {
        this.next();
        const typeCondition = this.expectName();
        while (this.peek().kind === 'punct' && this.peek().v === '@') this.parseDirective();
        return { kind: 'fragment', typeCondition, selections: this.parseSelectionSet() };
      }
      if (nt.kind === 'name') {
        const name = this.next().v as string;
        while (this.peek().kind === 'punct' && this.peek().v === '@') this.parseDirective();
        return { kind: 'fragment', typeCondition: undefined, selections: [] , __fragName: name } as GqlSelection;
      }
      while (this.peek().kind === 'punct' && this.peek().v === '@') this.parseDirective();
      return { kind: 'fragment', selections: this.parseSelectionSet() };
    }
    const first = this.expectName();
    let alias: string | undefined;
    let name = first;
    if (this.acceptPunct(':')) {
      alias = first;
      name = this.expectName();
    }
    const args = this.parseArguments();
    while (this.peek().kind === 'punct' && this.peek().v === '@') this.parseDirective();
    let selections: GqlSelection[] | undefined;
    if (this.peek().kind === 'punct' && this.peek().v === '{') selections = this.parseSelectionSet();
    return { kind: 'field', alias, name, args, selections };
  }
  private parseArguments(): Array<{ name: string; value: GqlValue }> {
    const out: Array<{ name: string; value: GqlValue }> = [];
    if (!this.acceptPunct('(')) return out;
    while (!this.acceptPunct(')')) {
      const name = this.expectName();
      this.expectPunct(':');
      out.push({ name, value: this.parseValue() });
    }
    return out;
  }
  private parseValue(): GqlValue {
    const t = this.next();
    if (t.kind === 'punct' && t.v === '$') return { kind: 'variable', name: this.expectName() };
    if (t.kind === 'punct' && t.v === '[') {
      const items: GqlValue[] = [];
      while (!(this.peek().kind === 'punct' && this.peek().v === ']')) items.push(this.parseValue());
      this.next();
      return { kind: 'list', items };
    }
    if (t.kind === 'punct' && t.v === '{') {
      const fields: Array<{ name: string; value: GqlValue }> = [];
      while (!(this.peek().kind === 'punct' && this.peek().v === '}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.next();
      return { kind: 'object', fields };
    }
    if (t.kind === 'string') return { kind: 'string', v: t.v };
    if (t.kind === 'int') return { kind: 'int', v: t.v };
    if (t.kind === 'float') return { kind: 'float', v: t.v };
    if (t.kind === 'name') {
      if (t.v === 'true') return { kind: 'boolean', v: true };
      if (t.v === 'false') return { kind: 'boolean', v: false };
      if (t.v === 'null') return { kind: 'null' };
      return { kind: 'enum', v: t.v };
    }
    throw new Error('unexpected value in GraphQL document');
  }
}

function resolveGqlValue(v: GqlValue, vars: Record<string, unknown>): unknown {
  switch (v.kind) {
    case 'variable':
      return vars[v.name];
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return v.v;
    case 'null':
      return null;
    case 'enum':
      return v.v;
    case 'list':
      return v.items.map((item) => resolveGqlValue(item, vars));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const f of v.fields) out[f.name] = resolveGqlValue(f.value, vars);
      return out;
    }
  }
}

function argsOf(field: GqlFieldSel, vars: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const a of field.args) out[a.name] = resolveGqlValue(a.value, vars);
  return out;
}

// --- schema metadata for introspection ---

const SCHEMA_TYPES: Record<string, { kind: string; fields?: string[]; enumValues?: string[] }> = {
  Issue: {
    kind: 'OBJECT',
    fields: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'url', 'author', 'labels', 'comments', 'repository'],
  },
  PullRequest: {
    kind: 'OBJECT',
    fields: ['id', 'number', 'title', 'state', 'body', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'files', 'createdAt', 'mergedAt', 'mergeCommit', 'author', 'repository'],
  },
  Repository: {
    kind: 'OBJECT',
    fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url', 'createdAt'],
  },
  SearchType: { kind: 'ENUM', enumValues: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE', 'COMMIT'] },
  IssueState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED'] },
  PullRequestState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED', 'MERGED'] },
  MergeableState: { kind: 'ENUM', enumValues: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'] },
};

// --- field resolvers ---

type Resolver = (parent: unknown, args: Record<string, unknown>) => unknown;

function userObj(login: string): Record<string, unknown> {
  return tagGql({ login, id: userGid(login), name: login }, 'User');
}

function issueObj(repo: Repo, issue: Issue): Record<string, unknown> {
  const obj: Record<string, unknown> = {
    _repo: repo,
    _issue: issue,
    id: issueGid(repo, issue.number),
    number: issue.number,
    title: issue.title,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
    body: issue.body,
    createdAt: issue.createdAt,
    url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
  return tagGql(obj, 'Issue');
}

function pullObj(repo: Repo, pull: Pull): Record<string, unknown> {
  const obj: Record<string, unknown> = {
    _repo: repo,
    _pull: pull,
    id: pullGid(repo, pull.number),
    number: pull.number,
    title: pull.title,
    state: pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED',
    body: pull.body,
    merged: pull.merged,
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    createdAt: pull.createdAt,
    mergedAt: pull.mergedAt,
  };
  return tagGql(obj, 'PullRequest');
}

function repoObj(repo: Repo): Record<string, unknown> {
  const obj: Record<string, unknown> = {
    _repo: repo,
    id: repoGid(repo),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    description: repo.description,
    url: `https://github.com/${repo.owner}/${repo.name}`,
    createdAt: repo.createdAt,
  };
  return tagGql(obj, 'Repository');
}

function decodeGid(gidStr: string): { kind: string; parts: string } | null {
  if (typeof gidStr !== 'string' || gidStr === '') return null;
  const text = b64decode(gidStr);
  if (text === null) return null;
  const idx = text.indexOf(':');
  if (idx < 0) return null;
  return { kind: text.slice(0, idx), parts: text.slice(idx + 1) };
}

function findByGid(gidStr: string): { repo: Repo; issue?: Issue; pull?: Pull } | null {
  const dec = decodeGid(gidStr);
  if (dec === null) return null;
  const segs = dec.parts.split('/');
  if (dec.kind === 'Repository' && segs.length === 2) {
    const repo = getRepo(segs[0], segs[1]);
    return repo === undefined ? null : { repo };
  }
  if (dec.kind === 'Issue' && segs.length === 3) {
    const repo = getRepo(segs[0], segs[1]);
    if (repo === undefined) return null;
    const issue = repo.issues.find((i) => i.number === Number(segs[2]));
    return issue === undefined ? null : { repo, issue };
  }
  if (dec.kind === 'PullRequest' && segs.length === 3) {
    const repo = getRepo(segs[0], segs[1]);
    if (repo === undefined) return null;
    const pull = repo.pulls.find((p) => p.number === Number(segs[2]));
    return pull === undefined ? null : { repo, pull };
  }
  return null;
}

function cursorForNumber(n: number): string {
  return b64encode(`cursor:${n}`);
}

function numberFromCursor(cursor: unknown): number | null {
  if (typeof cursor !== 'string' || cursor === '') return null;
  const text = b64decode(cursor);
  if (text === null || !text.startsWith('cursor:')) return null;
  const n = Number(text.slice('cursor:'.length));
  return Number.isFinite(n) ? n : null;
}

function issueConnection(repo: Repo, issues: Issue[], first: number | undefined, after: unknown): Record<string, unknown> {
  const ordered = [...issues].sort((a, b) => b.number - a.number);
  let start = 0;
  const afterNum = numberFromCursor(after);
  if (afterNum !== null) {
    const idx = ordered.findIndex((i) => i.number === afterNum);
    if (idx >= 0) start = idx + 1;
  }
  const size = first === undefined ? ordered.length : first;
  const page = ordered.slice(start, start + size);
  const endCursor = page.length > 0 ? cursorForNumber(page[page.length - 1].number) : null;
  return tagGql(
    {
      nodes: page.map((i) => issueObj(repo, i)),
      totalCount: ordered.length,
      pageInfo: tagGql(
        {
          hasNextPage: start + page.length < ordered.length,
          hasPreviousPage: start > 0,
          startCursor: page.length > 0 ? cursorForNumber(page[0].number) : null,
          endCursor,
        },
        'PageInfo',
      ),
    },
    'IssueConnection',
  );
}

function pullConnection(repo: Repo, pulls: Pull[], first: number | undefined, after: unknown): Record<string, unknown> {
  const ordered = [...pulls].sort((a, b) => b.number - a.number);
  let start = 0;
  const afterNum = numberFromCursor(after);
  if (afterNum !== null) {
    const idx = ordered.findIndex((p) => p.number === afterNum);
    if (idx >= 0) start = idx + 1;
  }
  const size = first === undefined ? ordered.length : first;
  const page = ordered.slice(start, start + size);
  const endCursor = page.length > 0 ? cursorForNumber(page[page.length - 1].number) : null;
  return tagGql(
    {
      nodes: page.map((p) => pullObj(repo, p)),
      totalCount: ordered.length,
      pageInfo: tagGql(
        {
          hasNextPage: start + page.length < ordered.length,
          hasPreviousPage: start > 0,
          startCursor: page.length > 0 ? cursorForNumber(page[0].number) : null,
          endCursor,
        },
        'PageInfo',
      ),
    },
    'PullRequestConnection',
  );
}

const RESOLVERS: Record<string, Record<string, Resolver>> = {
  Query: {
    viewer: () => userObj(VIEWER_LOGIN),
    repository: (_p, args) => {
      const repo = getRepo(String(args.owner ?? ''), String(args.name ?? ''));
      return repo === undefined ? null : repoObj(repo);
    },
    node: (_p, args) => {
      const found = findByGid(String(args.id ?? ''));
      if (found === null) return null;
      if (found.issue !== undefined) return issueObj(found.repo, found.issue);
      if (found.pull !== undefined) return pullObj(found.repo, found.pull);
      return repoObj(found.repo);
    },
    __type: (_p, args) => {
      const meta = SCHEMA_TYPES[String(args.name ?? '')];
      if (meta === undefined) return null;
      return tagGql(
        {
          name: String(args.name),
          kind: meta.kind,
          fields: (meta.fields ?? []).map((f) => tagGql({ name: f }, '__Field')),
          enumValues: (meta.enumValues ?? []).map((f) => tagGql({ name: f }, '__EnumValue')),
        },
        '__Type',
      );
    },
    __schema: () =>
      tagGql({ queryType: tagGql({ name: 'Query' }, '__Type'), mutationType: tagGql({ name: 'Mutation' }, '__Type') }, '__Schema'),
  },
  Mutation: {
    createIssue: (_p, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const found = findByGid(String(input.repositoryId ?? ''));
      if (found === null) throw new Error('repository not found');
      const title = String(input.title ?? '');
      if (title === '') throw new Error('title is required');
      const issue: Issue = {
        id: nextIssueId++,
        number: found.repo.nextNumber++,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        labels: [],
        createdAt: nowIso(),
        updatedAt: nowIso(),
      };
      found.repo.issues.push(issue);
      return tagGql({ issue: issueObj(found.repo, issue) }, 'CreateIssuePayload');
    },
    closeIssue: (_p, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const found = findByGid(String(input.issueId ?? ''));
      if (found === null || found.issue === undefined) throw new Error('issue not found');
      found.issue.state = 'closed';
      found.issue.updatedAt = nowIso();
      return tagGql({ issue: issueObj(found.repo, found.issue) }, 'CloseIssuePayload');
    },
    createPullRequest: (_p, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const found = findByGid(String(input.repositoryId ?? ''));
      if (found === null) throw new Error('repository not found');
      const head = String(input.headRefName ?? '');
      const base = String(input.baseRefName ?? '');
      const headSha = branchTip(found.repo, head);
      const baseSha = branchTip(found.repo, base);
      if (headSha === undefined || baseSha === undefined) throw new Error('head or base branch does not exist');
      const dupe = found.repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
      if (dupe !== undefined) throw new Error('a pull request already exists for this head and base');
      const mb = mergeBase(found.repo, headSha, baseSha);
      const pull: Pull = {
        id: nextIssueId++,
        number: found.repo.nextNumber++,
        title: String(input.title ?? ''),
        body: '',
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        headRef: head,
        headSha,
        baseRef: base,
        baseSha,
        mergeBase: mb ?? '',
        createdAt: nowIso(),
      };
      found.repo.pulls.push(pull);
      return tagGql({ pullRequest: pullObj(found.repo, pull) }, 'CreatePullRequestPayload');
    },
    mergePullRequest: (_p, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const found = findByGid(String(input.pullRequestId ?? ''));
      if (found === null || found.pull === undefined) throw new Error('pull request not found');
      if (found.pull.state !== 'open') throw new Error('pull request is already closed');
      const sha = squashMerge(found.repo, found.pull);
      if (sha === null) throw new Error('merge conflict');
      return tagGql({ pullRequest: pullObj(found.repo, found.pull) }, 'MergePullRequestPayload');
    },
    addComment: (_p, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const found = findByGid(String(input.subjectId ?? ''));
      if (found === null || found.issue === undefined) throw new Error('issue not found');
      const comment: Comment = { id: nextCommentId++, body: String(input.body ?? ''), createdAt: nowIso() };
      const list = found.repo.comments.get(found.issue.number) ?? [];
      list.push(comment);
      found.repo.comments.set(found.issue.number, list);
      const node = tagGql({ id: commentGid(found.repo, found.issue.number, comment.id), body: comment.body }, 'IssueComment');
      return tagGql({ commentEdge: tagGql({ node }, 'IssueCommentEdge') }, 'AddCommentPayload');
    },
  },
  User: {
    login: (p) => (p as Record<string, unknown>).login ?? null,
    id: (p) => (p as Record<string, unknown>).id ?? null,
    name: (p) => (p as Record<string, unknown>).name ?? (p as Record<string, unknown>).login ?? null,
  },
  Repository: {
    id: (p) => (p as Record<string, unknown>).id ?? null,
    databaseId: (p) => (p as Record<string, unknown>).databaseId ?? null,
    name: (p) => (p as Record<string, unknown>).name ?? null,
    nameWithOwner: (p) => (p as Record<string, unknown>).nameWithOwner ?? null,
    description: (p) => (p as Record<string, unknown>).description ?? null,
    url: (p) => (p as Record<string, unknown>).url ?? null,
    createdAt: (p) => (p as Record<string, unknown>).createdAt ?? null,
    owner: (p) => userObj(((p as Record<string, unknown>)._repo as Repo).owner),
    defaultBranchRef: (p) => {
      const repo = (p as Record<string, unknown>)._repo as Repo;
      const tip = defaultTip(repo);
      if (tip === undefined) return null;
      return tagGql({ name: repo.defaultBranch, id: gid('Ref', `${repo.owner}/${repo.name}/refs/heads/${repo.defaultBranch}`) }, 'Ref');
    },
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    issue: (p, args) => {
      const repo = (p as Record<string, unknown>)._repo as Repo;
      const issue = repo.issues.find((i) => i.number === Number(args.number));
      return issue === undefined ? null : issueObj(repo, issue);
    },
    issues: (p, args) => {
      const repo = (p as Record<string, unknown>)._repo as Repo;
      let list = [...repo.issues];
      if (Array.isArray(args.states)) {
        const wanted = new Set((args.states as unknown[]).map((s) => String(s)));
        list = list.filter((i) => wanted.has(i.state === 'open' ? 'OPEN' : 'CLOSED'));
      }
      if (isRecord(args.orderBy)) {
        const dir = String(args.orderBy.direction ?? 'DESC');
        list.sort((a, b) => (dir === 'ASC' ? a.number - b.number : b.number - a.number));
      } else {
        list.sort((a, b) => b.number - a.number);
      }
      const first = typeof args.first === 'number' ? args.first : undefined;
      return issueConnection(repo, list, first, args.after);
    },
    pullRequests: (p, args) => {
      const repo = (p as Record<string, unknown>)._repo as Repo;
      const open = repo.pulls.filter((pr) => pr.state === 'open');
      const first = typeof args.first === 'number' ? args.first : undefined;
      return pullConnection(repo, open, first, args.after);
    },
    pullRequest: (p, args) => {
      const repo = (p as Record<string, unknown>)._repo as Repo;
      const pull = repo.pulls.find((pr) => pr.number === Number(args.number));
      return pull === undefined ? null : pullObj(repo, pull);
    },
  },
  Issue: {
    id: (p) => (p as Record<string, unknown>).id ?? null,
    number: (p) => (p as Record<string, unknown>).number ?? null,
    title: (p) => (p as Record<string, unknown>).title ?? null,
    state: (p) => (p as Record<string, unknown>).state ?? null,
    body: (p) => (p as Record<string, unknown>).body ?? null,
    createdAt: (p) => (p as Record<string, unknown>).createdAt ?? null,
    url: (p) => (p as Record<string, unknown>).url ?? null,
    author: (p) => userObj(VIEWER_LOGIN),
  },
  PullRequest: {
    id: (p) => (p as Record<string, unknown>).id ?? null,
    number: (p) => (p as Record<string, unknown>).number ?? null,
    title: (p) => (p as Record<string, unknown>).title ?? null,
    state: (p) => (p as Record<string, unknown>).state ?? null,
    body: (p) => (p as Record<string, unknown>).body ?? null,
    merged: (p) => (p as Record<string, unknown>).merged ?? false,
    headRefName: (p) => (p as Record<string, unknown>).headRefName ?? null,
    baseRefName: (p) => (p as Record<string, unknown>).baseRefName ?? null,
    createdAt: (p) => (p as Record<string, unknown>).createdAt ?? null,
    mergedAt: (p) => (p as Record<string, unknown>).mergedAt ?? null,
    mergeable: (p) => {
      const repo = (p as Record<string, unknown>)._repo as Repo;
      const pull = (p as Record<string, unknown>)._pull as Pull;
      if (pull.state !== 'open') return 'UNKNOWN';
      return mergeConflicts(repo, pull.baseSha, pull.headSha, pull.mergeBase === '' ? null : pull.mergeBase) ? 'CONFLICTING' : 'MERGEABLE';
    },
    headRef: (p) => tagGql({ name: (p as Record<string, unknown>).headRefName }, 'Ref'),
    baseRef: (p) => tagGql({ name: (p as Record<string, unknown>).baseRefName }, 'Ref'),
    files: (p, args) => {
      const repo = (p as Record<string, unknown>)._repo as Repo;
      const pull = (p as Record<string, unknown>)._pull as Pull;
      const files = pullFiles(repo, pull);
      const first = typeof args.first === 'number' ? args.first : files.length;
      const nodes = files.slice(0, first).map((f) => tagGql({ path: f.filename }, 'PullRequestFile'));
      return tagGql(
        {
          nodes,
          totalCount: files.length,
          pageInfo: tagGql({ hasNextPage: files.length > first, hasPreviousPage: false, startCursor: null, endCursor: null }, 'PageInfo'),
        },
        'PullRequestFileConnection',
      );
    },
    author: (p) => userObj(VIEWER_LOGIN),
  },
  Ref: {
    name: (p) => (p as Record<string, unknown>).name ?? null,
    id: (p) => (p as Record<string, unknown>).id ?? null,
  },
  IssueConnection: {
    nodes: (p) => (p as Record<string, unknown>).nodes ?? [],
    totalCount: (p) => (p as Record<string, unknown>).totalCount ?? 0,
    pageInfo: (p) => (p as Record<string, unknown>).pageInfo ?? null,
  },
  PullRequestConnection: {
    nodes: (p) => (p as Record<string, unknown>).nodes ?? [],
    totalCount: (p) => (p as Record<string, unknown>).totalCount ?? 0,
    pageInfo: (p) => (p as Record<string, unknown>).pageInfo ?? null,
  },
  PullRequestFileConnection: {
    nodes: (p) => (p as Record<string, unknown>).nodes ?? [],
    totalCount: (p) => (p as Record<string, unknown>).totalCount ?? 0,
    pageInfo: (p) => (p as Record<string, unknown>).pageInfo ?? null,
  },
  PageInfo: {
    hasNextPage: (p) => (p as Record<string, unknown>).hasNextPage ?? false,
    hasPreviousPage: (p) => (p as Record<string, unknown>).hasPreviousPage ?? false,
    startCursor: (p) => (p as Record<string, unknown>).startCursor ?? null,
    endCursor: (p) => (p as Record<string, unknown>).endCursor ?? null,
  },
  PullRequestFile: {
    path: (p) => (p as Record<string, unknown>).path ?? null,
  },
  IssueComment: {
    id: (p) => (p as Record<string, unknown>).id ?? null,
    body: (p) => (p as Record<string, unknown>).body ?? null,
  },
  IssueCommentEdge: {
    node: (p) => (p as Record<string, unknown>).node ?? null,
  },
  CreateIssuePayload: {
    issue: (p) => (p as Record<string, unknown>).issue ?? null,
  },
  CloseIssuePayload: {
    issue: (p) => (p as Record<string, unknown>).issue ?? null,
  },
  CreatePullRequestPayload: {
    pullRequest: (p) => (p as Record<string, unknown>).pullRequest ?? null,
  },
  MergePullRequestPayload: {
    pullRequest: (p) => (p as Record<string, unknown>).pullRequest ?? null,
  },
  AddCommentPayload: {
    commentEdge: (p) => (p as Record<string, unknown>).commentEdge ?? null,
  },
  __Type: {
    name: (p) => (p as Record<string, unknown>).name ?? null,
    kind: (p) => (p as Record<string, unknown>).kind ?? null,
    fields: (p) => (p as Record<string, unknown>).fields ?? null,
    enumValues: (p) => (p as Record<string, unknown>).enumValues ?? null,
  },
  __Field: {
    name: (p) => (p as Record<string, unknown>).name ?? null,
  },
  __EnumValue: {
    name: (p) => (p as Record<string, unknown>).name ?? null,
  },
  __Schema: {
    queryType: (p) => (p as Record<string, unknown>).queryType ?? null,
    mutationType: (p) => (p as Record<string, unknown>).mutationType ?? null,
  },
};

// --- executor ---

interface GqlExecCtx {
  vars: Record<string, unknown>;
  fragments: Map<string, GqlFragmentDef>;
  errors: Array<{ message: string }>;
}

function resolveFieldValue(parent: unknown, field: GqlFieldSel, ctx: GqlExecCtx): unknown {
  const type = gqlTypeOf(parent) ?? 'Query';
  if (field.name === '__typename') return type;
  const table = RESOLVERS[type];
  const resolver = table?.[field.name];
  if (resolver === undefined) {
    ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${type}".` });
    return undefined;
  }
  const args = argsOf(field, ctx.vars);
  return resolver(parent, args);
}

function applySelections(value: unknown, selections: GqlSelection[] | undefined, ctx: GqlExecCtx): unknown {
  if (selections === undefined || selections.length === 0) return value;
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((v) => applySelections(v, selections, ctx));
  if (typeof value !== 'object') return value;
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.kind === 'fragment') {
      const fragName = (sel as GqlFragSel & { __fragName?: string }).__fragName;
      if (fragName !== undefined) {
        const def = ctx.fragments.get(fragName);
        if (def !== undefined && (def.typeCondition === gqlTypeOf(value) || def.typeCondition === undefined)) {
          Object.assign(out, applySelections(value, def.selections, ctx) as Record<string, unknown>);
        }
        continue;
      }
      if (sel.typeCondition !== undefined && sel.typeCondition !== gqlTypeOf(value)) continue;
      Object.assign(out, applySelections(value, sel.selections, ctx) as Record<string, unknown>);
      continue;
    }
    const key = sel.alias ?? sel.name;
    let fieldValue: unknown;
    try {
      fieldValue = resolveFieldValue(value, sel, ctx);
    } catch (err) {
      ctx.errors.push({ message: err instanceof Error ? err.message : String(err) });
      out[key] = null;
      continue;
    }
    if (fieldValue === undefined) {
      out[key] = null;
      continue;
    }
    out[key] = applySelections(fieldValue, sel.selections, ctx);
  }
  return out;
}

function executeGqlOperation(
  op: GqlOperation,
  variables: Record<string, unknown>,
  fragments: Map<string, GqlFragmentDef>,
): { data: Record<string, unknown>; errors?: Array<{ message: string }> } {
  const ctx: GqlExecCtx = { vars: { ...variables }, fragments, errors: [] };
  for (const def of op.varDefs) {
    if (ctx.vars[def.name] === undefined && def.defaultValue !== undefined) {
      ctx.vars[def.name] = resolveGqlValue(def.defaultValue, ctx.vars);
    }
  }
  const rootType = op.opType === 'mutation' ? 'Mutation' : 'Query';
  const root = tagGql({}, rootType);
  const data = applySelections(root, op.selections, ctx) as Record<string, unknown>;
  if (ctx.errors.length > 0) return { data: {}, errors: ctx.errors };
  return { data };
}

function runGraphQL(body: unknown): unknown {
  const runOne = (entry: unknown): Record<string, unknown> => {
    if (!isRecord(entry) || typeof entry.query !== 'string') {
      return { data: null, errors: [{ message: 'A GraphQL operation needs a query string.' }] };
    }
    const variables = isRecord(entry.variables) ? (entry.variables as Record<string, unknown>) : {};
    let doc: { operations: GqlOperation[]; fragments: Map<string, GqlFragmentDef> };
    try {
      doc = new GqlParser(entry.query).parseDocument();
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
    }
    if (doc.operations.length === 0) {
      return { data: null, errors: [{ message: 'No operation in the GraphQL document.' }] };
    }
    let op = doc.operations[0];
    if (typeof entry.operationName === 'string' && entry.operationName !== '') {
      const named = doc.operations.find((o) => o.name === entry.operationName);
      if (named !== undefined) op = named;
    }
    try {
      return executeGqlOperation(op, variables, doc.fragments);
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
    }
  };
  if (Array.isArray(body)) return body.map(runOne);
  return runOne(body);
}

// ---------------------------------------------------------------- MCP

const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Issue state: open, closed, or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash commit.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

const MCP_TOOL_REQUIRED: Record<string, string[]> = {
  create_repo: ['name'],
  get_repo: ['owner', 'repo'],
  create_issue: ['owner', 'repo', 'title'],
  list_issues: ['owner', 'repo'],
  create_pull_request: ['owner', 'repo', 'title', 'head', 'base'],
  merge_pull_request: ['owner', 'repo', 'pull_number'],
};

function mcpToolResult(result: unknown): Record<string, unknown> {
  const text = JSON.stringify(result);
  return { content: [{ type: 'text', text }], structuredContent: result };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpExecuteTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const required = MCP_TOOL_REQUIRED[name];
  if (required === undefined) return mcpToolError(`Unknown tool: ${name}`);
  for (const key of required) {
    if (args[key] === undefined || args[key] === null || args[key] === '') {
      return mcpToolError(`Missing required argument: ${key}`);
    }
  }
  if (name === 'create_repo') {
    const repoName = String(args.name);
    if (getRepo(VIEWER_LOGIN, repoName) !== undefined) return mcpToolError(`Repository ${repoName} already exists`);
    const repo = createRepoRecord(VIEWER_LOGIN, repoName, args.private === true, typeof args.description === 'string' ? args.description : '');
    return mcpToolResult(repoView(repo));
  }
  const owner = String(args.owner);
  const repoName = String(args.repo);
  const repo = getRepo(owner, repoName);
  if (repo === undefined) return mcpToolError(`Repository not found: ${owner}/${repoName}`);
  if (name === 'get_repo') return mcpToolResult(repoView(repo));
  if (name === 'create_issue') {
    const issue: Issue = {
      id: nextIssueId++,
      number: repo.nextNumber++,
      title: String(args.title),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      labels: [],
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };
    repo.issues.push(issue);
    return mcpToolResult(issueView(repo, issue));
  }
  if (name === 'list_issues') {
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = [...repo.issues];
    if (state !== 'all') list = list.filter((i) => i.state === state);
    list.sort((a, b) => a.number - b.number);
    return mcpToolResult(list.map((i) => issueView(repo, i)));
  }
  if (name === 'create_pull_request') {
    const head = String(args.head);
    const base = String(args.base);
    const headSha = branchTip(repo, head);
    const baseSha = branchTip(repo, base);
    if (headSha === undefined || baseSha === undefined) return mcpToolError('head or base branch does not exist');
    const dupe = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
    if (dupe !== undefined) return mcpToolError('A pull request already exists for this head and base');
    const mb = mergeBase(repo, headSha, baseSha);
    const pull: Pull = {
      id: nextIssueId++,
      number: repo.nextNumber++,
      title: String(args.title),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      headRef: head,
      headSha,
      baseRef: base,
      baseSha,
      mergeBase: mb ?? '',
      createdAt: nowIso(),
    };
    repo.pulls.push(pull);
    return mcpToolResult(pullView(repo, pull));
  }
  if (name === 'merge_pull_request') {
    const num = Number(args.pull_number);
    const pull = repo.pulls.find((p) => p.number === num);
    if (pull === undefined) return mcpToolError(`Pull request #${args.pull_number} not found`);
    if (pull.state !== 'open') return mcpToolError('Pull request is already closed');
    const sha = squashMerge(repo, pull);
    if (sha === null) return mcpToolError('Merge conflict: the pull request cannot be merged');
    return mcpToolResult({ number: pull.number, merged: true, sha, state: pull.state, title: pull.title });
  }
  return mcpToolError(`Unknown tool: ${name}`);
}

function sendMcp(ctx: Ctx, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-github-request-id': `${REQUEST_ID_PREFIX}${++requestCounter}`,
    'content-length': String(Buffer.byteLength(text)),
  };
  ctx.res.writeHead(status, headers);
  ctx.res.end(text);
}

function handleMcp(ctx: Ctx): boolean {
  if (ctx.path !== '/mcp') return false;
  if (ctx.method !== 'POST') {
    sendMcp(ctx, 405, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Method not allowed' } });
    return true;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(ctx.body.toString('utf8'));
  } catch {
    sendMcp(ctx, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  if (!isRecord(parsed)) {
    sendMcp(ctx, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return true;
  }
  const id = parsed.id === undefined ? null : parsed.id;
  // A notification (no id) gets an empty 202; nothing answers it.
  if (parsed.id === undefined) {
    ctx.res.writeHead(202, { 'x-github-request-id': `${REQUEST_ID_PREFIX}${++requestCounter}` });
    ctx.res.end();
    return true;
  }
  const method = typeof parsed.method === 'string' ? parsed.method : '';
  const params = isRecord(parsed.params) ? parsed.params : {};
  const ok = (result: unknown): void => sendMcp(ctx, 200, { jsonrpc: '2.0', id, result });
  const err = (code: number, message: string): void => sendMcp(ctx, 200, { jsonrpc: '2.0', id, error: { code, message } });

  if (method === 'server/discover') {
    ok({
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      capabilities: { tools: {} },
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18'],
      protocolVersion: '2026-07-28',
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: SERVER_NAME, version: SERVER_VERSION } },
    });
    return true;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const supported = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    ok({
      protocolVersion: supported.includes(offered) ? offered : '2025-11-25',
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
    });
    return true;
  }
  if (method === 'tools/list') {
    ok({ tools: MCP_TOOLS });
    return true;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    if (MCP_TOOL_REQUIRED[toolName] === undefined) {
      err(-32602, `Unknown tool: ${toolName}`);
      return true;
    }
    ok(mcpExecuteTool(toolName, args));
    return true;
  }
  if (method === 'ping') {
    ok({});
    return true;
  }
  err(-32601, `Method not found: ${method}`);
  return true;
}

// ---------------------------------------------------------------- git smart HTTP

const GIT_CAPS_V0 = 'report-status side-band-64k delete-refs ofs-delta agent=git-forge/1.0.0 symref=HEAD:refs/heads/main';

function sendGit(ctx: Ctx, status: number, contentType: string, body: Buffer): void {
  const headers: Record<string, string> = {
    'content-type': contentType,
    'x-github-request-id': `${REQUEST_ID_PREFIX}${++requestCounter}`,
    'content-length': String(body.length),
    'cache-control': 'no-cache',
  };
  ctx.res.writeHead(status, headers);
  ctx.res.end(body);
}

function gitPathParts(ctx: Ctx): { owner: string; name: string; tail: string[] } | null {
  const segs = ctx.path.split('/').filter((s) => s !== '');
  if (segs.length < 2) return null;
  const repoSeg = segs[1];
  if (!repoSeg.endsWith('.git')) return null;
  return { owner: decodeURIComponent(segs[0]), name: decodeURIComponent(repoSeg.slice(0, -4)), tail: segs.slice(2) };
}

function handleGit(ctx: Ctx): boolean {
  const parts = gitPathParts(ctx);
  if (parts === null) return false;
  const { owner, name, tail } = parts;

  if (ctx.method === 'GET' && tail.length === 2 && tail[0] === 'info' && tail[1] === 'refs') {
    const service = ctx.url.searchParams.get('service');
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      sendError(ctx, 400, 'service parameter is required');
      return true;
    }
    const repo = getRepo(owner, name);
    if (repo === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    if (service === 'git-upload-pack') {
      const body = Buffer.concat([
        pktLine('# service=git-upload-pack\n'),
        PKT_FLUSH,
        pktLine('version 2\n'),
        pktLine('ls-refs=unborn\n'),
        pktLine('fetch=shallow filter\n'),
        pktLine('object-format=sha1\n'),
        pktLine(`agent=${AGENT}\n`),
        PKT_FLUSH,
      ]);
      sendGit(ctx, 200, 'application/x-git-upload-pack-advertisement', body);
      return true;
    }
    // receive-pack: v0 advertisement with the caps on the first line.
    const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    const chunks: Buffer[] = [pktLine('# service=git-receive-pack\n'), PKT_FLUSH];
    if (refs.length === 0) {
      chunks.push(pktLine(`${ZERO_OID} capabilities^{}\0${GIT_CAPS_V0}\n`));
    } else {
      const headTip = defaultTip(repo) ?? refs[0][1];
      chunks.push(pktLine(`${headTip} HEAD\0${GIT_CAPS_V0}\n`));
      for (const [ref, oid] of refs) chunks.push(pktLine(`${oid} ${ref}\n`));
    }
    chunks.push(PKT_FLUSH);
    sendGit(ctx, 200, 'application/x-git-receive-pack-advertisement', Buffer.concat(chunks));
    return true;
  }

  if (ctx.method === 'POST' && tail.length === 1 && tail[0] === 'git-upload-pack') {
    const repo = getRepo(owner, name);
    if (repo === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    return handleUploadPack(ctx, repo);
  }

  if (ctx.method === 'POST' && tail.length === 1 && tail[0] === 'git-receive-pack') {
    const repo = getRepo(owner, name);
    if (repo === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    return handleReceivePack(ctx, repo);
  }

  sendError(ctx, 404, 'Not Found');
  return true;
}

function lsRefsResponse(repo: Repo, wantPeel: boolean, wantSymrefs: boolean, prefixes: string[], wantUnborn: boolean): Buffer {
  const lines: string[] = [];
  const keep = (refName: string): boolean => prefixes.length === 0 || prefixes.some((p) => refName.startsWith(p));
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  if (wantSymrefs && keep('HEAD')) {
    const tip = defaultTip(repo);
    if (tip === undefined) {
      // An unborn default branch is announced as `unborn HEAD ...`, never as
      // a zero-oid ref line: real git treats a zero-oid HEAD as a broken
      // symref and will not write the clone's HEAD from it.
      if (wantUnborn) lines.push(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}`);
    } else {
      lines.push(`${tip} HEAD symref-target:refs/heads/${repo.defaultBranch}`);
    }
  }
  for (const [ref, oid] of refs) {
    if (!keep(ref)) continue;
    let line = `${oid} ${ref}`;
    if (wantPeel) {
      const obj = repo.objects.get(oid);
      if (obj !== undefined && obj.type === 'tag') {
        const target = peelToCommit(repo, oid);
        line += ` peeled:${target}`;
      }
    }
    lines.push(line);
  }
  const chunks = lines.map((l) => pktLine(`${l}\n`));
  chunks.push(PKT_FLUSH);
  return Buffer.concat(chunks);
}

function handleUploadPack(ctx: Ctx, repo: Repo): boolean {
  const packets = decodePktLines(ctx.body);
  const first = packets.find((p) => p.kind === 'data');
  if (first === undefined) {
    sendError(ctx, 400, 'malformed git request');
    return true;
  }
  const firstLine = first.payload.toString('utf8');
  if (!firstLine.startsWith('command=')) {
    sendError(ctx, 400, 'malformed git request: expected a protocol v2 command');
    return true;
  }
  const command = firstLine.slice('command='.length).trim();
  // Split the request at the delim packet: arguments follow it.
  let delimIdx = -1;
  for (let i = 0; i < packets.length; i++) {
    if (packets[i].kind === 'delim') {
      delimIdx = i;
      break;
    }
  }
  const argLines: string[] = [];
  const from = delimIdx >= 0 ? delimIdx + 1 : 1;
  for (let i = from; i < packets.length; i++) {
    const p = packets[i];
    if (p.kind === 'flush') break;
    if (p.kind === 'data') argLines.push(p.payload.toString('utf8').replace(/\n$/, ''));
  }

  if (command === 'ls-refs') {
    const wantPeel = argLines.includes('peel');
    const wantSymrefs = argLines.includes('symrefs');
    const wantUnborn = argLines.includes('unborn');
    const prefixes = argLines.filter((l) => l.startsWith('ref-prefix ')).map((l) => l.slice('ref-prefix '.length));
    sendGit(ctx, 200, 'application/x-git-upload-pack-result', lsRefsResponse(repo, wantPeel, wantSymrefs, prefixes, wantUnborn));
    return true;
  }

  if (command === 'fetch') {
    const wants: string[] = [];
    const haves: string[] = [];
    const shallowReq: string[] = [];
    let depth: number | null = null;
    for (const line of argLines) {
      if (line.startsWith('want ')) wants.push(line.slice(5).trim());
      else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
      else if (line.startsWith('shallow ')) shallowReq.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) {
        const n = parseInt(line.slice(7).trim(), 10);
        if (Number.isFinite(n) && n > 0) depth = n;
      }
    }
    if (wants.length === 0) {
      sendGit(ctx, 200, 'application/x-git-upload-pack-result', Buffer.concat([pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_DELIM, PKT_FLUSH]));
      return true;
    }
    const plan = planFetch(repo, wants, haves, shallowReq, depth);
    const chunks: Buffer[] = [];
    // The acknowledgments section is only sent when the client sent `have`
    // lines (a fresh clone sends none, and real git rejects the section then).
    if (haves.length > 0) {
      chunks.push(pktLine('acknowledgments\n'));
      const common = haves.filter((h) => repo.objects.has(h) && wants.some((w) => isAncestor(repo, h, peelToCommit(repo, w)) || h === w));
      if (common.length > 0) {
        for (const c of common) chunks.push(pktLine(`ACK ${c}\n`));
      } else {
        chunks.push(pktLine('NAK\n'));
      }
      chunks.push(PKT_DELIM);
    }
    if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
      chunks.push(pktLine('shallow-info\n'));
      for (const s of plan.shallow) chunks.push(pktLine(`shallow ${s}\n`));
      for (const s of plan.unshallow) chunks.push(pktLine(`unshallow ${s}\n`));
      chunks.push(PKT_DELIM);
    }
    // The packfile section is always sent when the client asked for objects,
    // even when nothing is new: real git expects the section after a `want`
    // (an empty repo's clone wants the zero oid and still needs the section,
    // answered with an empty pack).
    const pack = writePack(plan.objects);
    chunks.push(pktLine('packfile\n'));
    for (let off = 0; off < pack.length; off += 65515) {
      const piece = pack.subarray(off, Math.min(pack.length, off + 65515));
      chunks.push(pktLine(Buffer.concat([Buffer.from([1]), piece])));
    }
    chunks.push(PKT_FLUSH);
    sendGit(ctx, 200, 'application/x-git-upload-pack-result', Buffer.concat(chunks));
    return true;
  }

  sendError(ctx, 400, `unknown git command: ${command}`);
  return true;
}

function handleReceivePack(ctx: Ctx, repo: Repo): boolean {
  // Parse the command list: pkt-lines until the first flush; the rest is the pack.
  const body = ctx.body;
  let pos = 0;
  const commandLines: string[] = [];
  let packStart = -1;
  let ok = false;
  while (pos + 4 <= body.length) {
    const head = body.toString('ascii', pos, pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = parseInt(head, 16);
    if (len === 0) {
      packStart = pos + 4;
      ok = true;
      break;
    }
    if (len < 4 || pos + len > body.length) break;
    commandLines.push(body.toString('utf8', pos + 4, pos + len));
    pos += len;
  }
  if (!ok || commandLines.length === 0) {
    sendError(ctx, 400, 'malformed receive-pack request');
    return true;
  }
  interface PushCmd {
    oldOid: string;
    newOid: string;
    ref: string;
    caps: string;
  }
  const commands: PushCmd[] = [];
  for (let i = 0; i < commandLines.length; i++) {
    const raw = commandLines[i].replace(/\n$/, '');
    const nul = raw.indexOf('\0');
    const line = nul >= 0 ? raw.slice(0, nul) : raw;
    const caps = nul >= 0 ? raw.slice(nul + 1) : '';
    const parts = line.split(' ');
    if (parts.length < 3 || !isOid(parts[0]) || !isOid(parts[1])) {
      sendError(ctx, 400, 'malformed push command');
      return true;
    }
    commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts[2], caps: i === 0 ? caps : '' });
  }
  const wantSideband = commands[0].caps.split(' ').includes('side-band-64k');
  const packBytes = packStart >= 0 ? body.subarray(packStart) : Buffer.alloc(0);
  const hasUpdates = commands.some((c) => c.newOid !== ZERO_OID);
  let unpackError: string | null = null;
  if (hasUpdates && packBytes.length === 0) {
    unpackError = 'unpacker error: no packfile';
  } else if (packBytes.length > 0) {
    try {
      const objects = readPack(packBytes, (oid) => repo.objects.get(oid));
      for (const [oid, obj] of objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch (err) {
      unpackError = `unpacker error: ${err instanceof Error ? err.message : String(err)}`;
    }
  }
  const report: Array<{ ref: string; ok: boolean; reason: string }> = [];
  for (const cmd of commands) {
    if (unpackError !== null) {
      report.push({ ref: cmd.ref, ok: false, reason: 'unpacker error' });
      continue;
    }
    if (cmd.newOid === ZERO_OID) {
      if (!repo.refs.has(cmd.ref)) {
        report.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
      } else {
        repo.refs.delete(cmd.ref);
        report.push({ ref: cmd.ref, ok: true, reason: '' });
      }
      continue;
    }
    if (cmd.oldOid === ZERO_OID) {
      if (repo.refs.has(cmd.ref)) {
        report.push({ ref: cmd.ref, ok: false, reason: 'already exists' });
      } else if (!repo.objects.has(cmd.newOid)) {
        report.push({ ref: cmd.ref, ok: false, reason: 'object not found' });
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
        report.push({ ref: cmd.ref, ok: true, reason: '' });
      }
      continue;
    }
    const current = repo.refs.get(cmd.ref);
    if (current === undefined) {
      report.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
    } else if (current !== cmd.oldOid) {
      report.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
    } else if (cmd.newOid === cmd.oldOid) {
      report.push({ ref: cmd.ref, ok: true, reason: '' });
    } else if (!repo.objects.has(cmd.newOid)) {
      report.push({ ref: cmd.ref, ok: false, reason: 'object not found' });
    } else if (!isAncestor(repo, cmd.oldOid, cmd.newOid)) {
      report.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
    } else {
      repo.refs.set(cmd.ref, cmd.newOid);
      report.push({ ref: cmd.ref, ok: true, reason: '' });
    }
  }
  const inner: Buffer[] = [];
  inner.push(pktLine(unpackError === null ? 'unpack ok\n' : `unpack ${unpackError.replace(/^unpacker error: /, '')}\n`));
  for (const r of report) {
    inner.push(pktLine(r.ok ? `ok ${r.ref}\n` : `ng ${r.ref} ${r.reason}\n`));
  }
  inner.push(PKT_FLUSH);
  let out: Buffer;
  if (wantSideband) {
    const wrapped = inner.map((p) => pktLine(Buffer.concat([Buffer.from([1]), p])));
    wrapped.push(PKT_FLUSH);
    out = Buffer.concat(wrapped);
  } else {
    out = Buffer.concat(inner);
  }
  sendGit(ctx, 200, 'application/x-git-receive-pack-result', out);
  return true;
}

// ---------------------------------------------------------------- server

const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ENV_URL = process.env.MAKEFUN_ENV_URL ?? '';

function isAuthorized(req: http.IncomingMessage): boolean {
  const h = req.headers.authorization;
  if (typeof h !== 'string' || !h.startsWith('Bearer ')) return false;
  const tok = h.slice('Bearer '.length).trim();
  if (tok === '') return false;
  if (SHOP_TOKEN !== '') return tok === SHOP_TOKEN;
  return true;
}

async function onRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  let url: URL;
  try {
    const host = req.headers.host ?? '127.0.0.1';
    url = new URL(req.url ?? '/', `http://${host}`);
  } catch {
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ message: 'Bad Request' }));
    return;
  }
  const ctx: Ctx = {
    req,
    res,
    method: req.method ?? 'GET',
    url,
    path: url.pathname,
    token: '',
    body: Buffer.alloc(0),
    json: undefined,
  };
  try {
    if (ctx.path === '/healthz' && ctx.method === 'GET') {
      sendJson(ctx, 200, { ok: true });
      return;
    }
    if (!isAuthorized(req)) {
      sendError(ctx, 401, 'Requires authentication');
      return;
    }
    if (ctx.method === 'POST' || ctx.method === 'PUT' || ctx.method === 'PATCH' || ctx.method === 'DELETE') {
      ctx.body = await readBody(req);
    }
    if (ctx.path === '/api/graphql' && ctx.method === 'POST') {
      if (!parseJsonBody(ctx)) return;
      sendJson(ctx, 200, runGraphQL(ctx.json));
      return;
    }
    if (handleMcp(ctx)) return;
    if (ctx.path.startsWith('/api/v3')) {
      handleRest(ctx);
      return;
    }
    if (gitPathParts(ctx) !== null) {
      handleGit(ctx);
      return;
    }
    sendError(ctx, 404, 'Not Found');
  } catch (err) {
    try {
      sendError(ctx, 500, 'Internal Server Error');
    } catch {
      // The connection is already gone; nothing more to do.
    }
  }
}

const server = http.createServer((req, res) => {
  void onRequest(req, res);
});

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
});
process.on('SIGINT', () => {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
});

async function registerAndPoll(port: number): Promise<void> {
  const base = ENV_URL.replace(/\/+$/, '');
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      const res = await fetch(`${base}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) break;
    } catch {
      // The env may not be listening yet; retry.
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  let delay = 250;
  for (;;) {
    try {
      const res = await fetch(`${base}/done`, { signal: AbortSignal.timeout(30000) });
      const body = (await res.json()) as Record<string, unknown>;
      if (body.done === true) {
        server.close(() => process.exit(0));
        setTimeout(() => process.exit(0), 2000);
        return;
      }
    } catch {
      // A failed poll is not fatal; keep polling.
    }
    await new Promise((r) => setTimeout(r, delay));
    delay = Math.min(delay * 2, 2000);
  }
}

server.listen(0, '127.0.0.1', () => {
  const addr = server.address();
  const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
  if (ENV_URL !== '') {
    void registerAndPoll(port);
  } else {
    console.log(`git-forge listening on http://127.0.0.1:${port}`);
  }
});
