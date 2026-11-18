// A GitHub-compatible git forge: smart HTTP (upload-pack v2, receive-pack v0),
// REST v3, GraphQL v4 and MCP, all over one in-memory store, in one process.
//
// Everything here is deterministic: commit times, API timestamps and request
// ids all come from counters, never from the wall clock or randomness, so a
// replay of the same requests leaves exactly the same state. Only the Node
// standard library is used and the process reaches no network of its own.

import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { createInflate, deflateSync, inflateSync } from 'node:zlib';

// ------------------------------------------------------------------ constants

const FORGE_NAME = 'forge';
const FORGE_VERSION = '1.0.0';
const FORGE_AGENT = 'forge/1.0.0';
const ZERO_OID = '0000000000000000000000000000000000000000';
const DEFAULT_BRANCH = 'main';
const MCP_REVISION = '2026-07-28';
const MCP_LEGACY = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const EPOCH_BASE = 1763000000; // seconds; every timestamp below is base + a counter

// The token the suite presents, when the trial sets one. Local runs that do
// not set it accept any non-empty bearer token instead.
const EXPECTED_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

// ------------------------------------------------------------------ counters

// One counter drives every deterministic value in the process: commit times,
// created_at stamps and request ids all read it, so the same request order
// always produces the same bytes.
let tick = 0;
function nextTick(): number {
  tick += 1;
  return tick;
}
function stampFor(seq: number): string {
  return new Date((EPOCH_BASE + seq) * 1000).toISOString();
}
function gitTimeFor(seq: number): string {
  return `${EPOCH_BASE + seq} +0000`;
}
let requestSeq = 0;
function nextRequestId(): string {
  requestSeq += 1;
  return `req-${requestSeq}`;
}

// ------------------------------------------------------------------ bytes

function sha1Hex(bytes: Buffer): string {
  return createHash('sha1').update(bytes).digest('hex');
}
function b64url(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64url');
}
function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s+/g, ''), 'base64');
}
function isOid(text: unknown): text is string {
  return typeof text === 'string' && /^[0-9a-f]{40}$/.test(text);
}

// ------------------------------------------------------------------ pkt-lines

// A pkt-line is a 4-hex-digit length (itself included) plus the payload.
// '0000' is a flush, '0001' a delimiter. No payload may make a line longer
// than 65520 bytes, so sideband chunks stay below that.
function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.from((body.length + 4).toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

interface Pkt {
  kind: 'data' | 'flush' | 'delim';
  payload: Buffer;
}

// Read pkt-lines from the front of `buf` until a flush, a delimiter, or the
// end of the buffer. Returns the packets and the offset just past the last
// one read, so a caller can treat the rest of the buffer as something else
// (a packfile follows the flush in a receive-pack body).
function readPktLines(buf: Buffer, start = 0): { packets: Pkt[]; offset: number } {
  const packets: Pkt[] = [];
  let offset = start;
  while (offset + 4 <= buf.length) {
    const head = buf.toString('ascii', offset, offset + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('bad pkt-line length');
    const len = parseInt(head, 16);
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
      break;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (len < 4 || offset + len > buf.length) throw new Error('truncated pkt-line');
    packets.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + len) });
    offset += len;
  }
  return { packets, offset };
}

// Read every pkt-line in a buffer (used for request bodies that are only
// pkt-lines, such as ls-refs and fetch). A trailing flush is fine.
function allPktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let offset = 0;
  while (offset < buf.length) {
    const { packets, offset: next } = readPktLines(buf, offset);
    out.push(...packets);
    if (next === offset) break;
    offset = next;
    if (packets.length > 0 && packets[packets.length - 1]?.kind === 'flush') break;
  }
  return out;
}

// Wrap bytes in sideband band 1 (pack data), chunked so no pkt-line exceeds
// the 65520-byte ceiling, and finish with a flush.
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 65515; // 4 (length) + 1 (band) + data <= 65520
  for (let at = 0; at < pack.length; at += CHUNK) {
    const slice = pack.subarray(at, Math.min(pack.length, at + CHUNK));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

// ------------------------------------------------------------------ zlib

// Inflate exactly one zlib stream starting at `offset` and report where it
// ended. One streaming inflate does it in a single pass: the inflater stops
// at the end of the deflate stream and reports exactly how many compressed
// bytes it consumed (bytesWritten), so there is no probe-and-bisect search
// over the length. This is an order of magnitude faster than re-inflating
// at candidate ends, and it matters on the push path, which inflates every
// object the client sends.
function inflateOne(buf: Buffer, offset: number): Promise<{ data: Buffer; end: number }> {
  return new Promise((resolve, reject) => {
    const inflater = createInflate();
    const chunks: Buffer[] = [];
    inflater.on('data', (chunk: Buffer) => chunks.push(chunk));
    inflater.on('error', (err: Error) => reject(err));
    inflater.on('end', () => {
      const end = offset + inflater.bytesWritten;
      if (end <= offset || end > buf.length) reject(new Error('zlib stream end is out of range'));
      else resolve({ data: Buffer.concat(chunks), end });
    });
    inflater.end(buf.subarray(offset));
  });
}

// Read a git varint: 7 bits per byte, little-endian groups, the high bit
// continuing. Used by pack object headers and delta base offsets.
function readVarint(buf: Buffer, offset: number): { value: number; next: number } {
  let value = 0;
  let shift = 0;
  let at = offset;
  for (;;) {
    if (at >= buf.length) throw new Error('varint runs past the buffer');
    const byte = buf[at]!;
    value |= (byte & 0x7f) << shift;
    at += 1;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return { value, next: at };
}

// ------------------------------------------------------------------ git objects

type ObjectKind = 'commit' | 'tree' | 'blob' | 'tag';
const KIND_CODE: Record<ObjectKind, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_KIND: Record<number, ObjectKind> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

interface GitObject {
  kind: ObjectKind;
  data: Buffer;
}

function objectId(kind: ObjectKind, data: Buffer): string {
  const head = Buffer.from(`${kind} ${data.length}\0`, 'ascii');
  return sha1Hex(Buffer.concat([head, data]));
}

interface CommitParts {
  tree: string;
  parents: string[];
  message: string;
}

function parseCommit(data: Buffer): CommitParts {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = ZERO_OID;
  const parents: string[] = [];
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
  }
  return { tree, parents, message };
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let at = 0;
  while (at < data.length) {
    const space = data.indexOf(0x20, at);
    if (space < 0) break;
    const mode = data.toString('ascii', at, space);
    const nul = data.indexOf(0, space + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const name = data.toString('utf8', space + 1, nul);
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    at = nul + 21;
  }
  return entries;
}

// Git's tree sort: entries compare by name, with a '/' appended for trees.
function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}

function buildTreeBytes(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface TagParts {
  object: string;
  type: string;
  tag: string;
  message: string;
}

function parseTag(data: Buffer): TagParts {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let object = ZERO_OID;
  let type = '';
  let tag = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
  }
  return { object, type, tag, message };
}

// Apply a git delta stream to a base object's bytes.
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let at = 0;
  const readSize = (): number => {
    let out = 0;
    let shift = 0;
    for (;;) {
      if (at >= delta.length) throw new Error('delta size is truncated');
      const byte = delta[at]!;
      at += 1;
      out |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) return out;
    }
  };
  const sourceSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const targetSize = readSize();
  const out = Buffer.alloc(targetSize);
  let written = 0;
  while (at < delta.length) {
    const op = delta[at]!;
    at += 1;
    if (op & 0x80) {
      let copyOff = 0;
      let copySize = 0;
      for (let i = 0; i < 4; i += 1) {
        if (op & (1 << i)) {
          if (at >= delta.length) throw new Error('delta copy offset is truncated');
          copyOff |= delta[at]! << (8 * i);
          at += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if (op & (0x10 << i)) {
          if (at >= delta.length) throw new Error('delta copy size is truncated');
          copySize |= delta[at]! << (8 * i);
          at += 1;
        }
      }
      if (copySize === 0) copySize = 0x10000;
      if (copyOff + copySize > base.length || written + copySize > targetSize) throw new Error('delta copy is out of range');
      base.copy(out, written, copyOff, copyOff + copySize);
      written += copySize;
    } else if (op !== 0) {
      if (at + op > delta.length || written + op > targetSize) throw new Error('delta insert is out of range');
      delta.copy(out, written, at, at + op);
      at += op;
      written += op;
    } else {
      throw new Error('delta opcode 0 is invalid');
    }
  }
  if (written !== targetSize) throw new Error('delta produced the wrong size');
  return out;
}

// ------------------------------------------------------------------ the store

interface Label {
  id: number;
  name: string;
  color: string;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdSeq: number;
  updatedSeq: number;
  comments: Comment[];
}

interface Comment {
  id: number;
  body: string;
  createdSeq: number;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  mergedAt: string | null;
  mergeSha: string | null;
  createdSeq: number;
  updatedSeq: number;
}

interface Repo {
  id: number;
  owner: string;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdSeq: number;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  labels: Map<string, Label>;
  issues: Issue[];
  pulls: Pull[];
  issueByNumber: Map<number, Issue>;
  pullByNumber: Map<number, Pull>;
  nextNumber: number;
  nextLabelId: number;
  version: number;
  // Lazily built, whole-response caches; cleared whenever the repo changes.
  advV2: Buffer | null;
  advV0Up: Buffer | null;
  advV0Recv: Buffer | null;
  lsRefs: Map<string, Buffer>;
  fetchResp: Map<string, Buffer>;
  issueJson: Map<number, { origin: string; buf: Buffer }>;
  repoJson: Buffer | null;
  repoJsonOrigin: string;
  // Deflated bytes per object id. Objects are content-addressed and never
  // change, so a deflated form is stable; the clone workload asks for the
  // same pack fifty times and re-deflating it each time is pure waste.
  deflated: Map<string, Buffer>;
}

interface Store {
  repos: Map<string, Repo>;
  viewer: string;
  nextRepoId: number;
  nextIssueId: number;
  nextCommentId: number;
}

const store: Store = {
  repos: new Map(),
  viewer: '',
  nextRepoId: 1,
  nextIssueId: 1000,
  nextCommentId: 1,
};

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}
function findRepo(owner: string, name: string): Repo | null {
  return store.repos.get(repoKey(owner, name)) ?? null;
}

// The token names no login, so the viewer is learned from the first
// owner-bearing request: the suite always addresses its own repos by the
// scenario's login, and git runs before anything else. One wrinkle: the
// git group's setup creates its first repository through POST /user/repos
// before any owner-bearing request exists, so that repository is first held
// under no owner at all; the moment the viewer is learned, every such
// unattributed repository is re-attributed to them.
function learnViewer(owner: string): void {
  if (store.viewer !== '') return;
  store.viewer = owner;
  for (const repo of [...store.repos.values()]) {
    if (repo.owner !== '') continue;
    store.repos.delete(repoKey('', repo.name));
    repo.owner = owner;
    store.repos.set(repoKey(owner, repo.name), repo);
    invalidate(repo);
  }
}

// Drop every cached rendering of a repo after it changes.
function invalidate(repo: Repo): void {
  repo.version += 1;
  repo.advV2 = null;
  repo.advV0Up = null;
  repo.advV0Recv = null;
  repo.lsRefs.clear();
  repo.fetchResp.clear();
  repo.issueJson.clear();
  repo.repoJson = null;
  repo.repoJsonOrigin = '';
}

function newRepo(owner: string, name: string, description: string, isPrivate: boolean): Repo {
  const seq = nextTick();
  const repo: Repo = {
    id: store.nextRepoId,
    owner,
    name,
    description,
    isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    createdSeq: seq,
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    issueByNumber: new Map(),
    pullByNumber: new Map(),
    nextNumber: 1,
    nextLabelId: 1,
    version: 1,
    advV2: null,
    advV0Up: null,
    advV0Recv: null,
    lsRefs: new Map(),
    fetchResp: new Map(),
    issueJson: new Map(),
    repoJson: null,
    repoJsonOrigin: '',
    deflated: new Map(),
  };
  store.nextRepoId += 1;
  store.repos.set(repoKey(owner, name), repo);
  return repo;
}

// ------------------------------------------------------------------ objects

function putObject(repo: Repo, kind: ObjectKind, data: Buffer): string {
  const oid = objectId(kind, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { kind, data });
  return oid;
}
function getObject(repo: Repo, oid: string): GitObject | null {
  return repo.objects.get(oid) ?? null;
}
function refTip(repo: Repo, ref: string): string | null {
  return repo.refs.get(ref) ?? null;
}
function branchTip(repo: Repo, branch: string): string | null {
  return repo.refs.get(`refs/heads/${branch}`) ?? null;
}

// Build the commit object for a tree with parents and a message, using the
// forge's fixed identity and a counter timestamp.
function makeCommit(repo: Repo, tree: string, parents: string[], message: string): string {
  const seq = nextTick();
  const stamp = gitTimeFor(seq);
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author Forge <forge@make.fun> ${stamp}`);
  lines.push(`committer Forge <forge@make.fun> ${stamp}`);
  lines.push('');
  lines.push(message.endsWith('\n') ? message : `${message}\n`);
  return putObject(repo, 'commit', Buffer.from(lines.join('\n'), 'utf8'));
}

// Build nested trees from a flat path -> {mode, oid} map.
function buildTree(repo: Repo, files: Map<string, { mode: string; oid: string }>): string {
  if (files.size === 0) return putObject(repo, 'tree', Buffer.alloc(0));
  const buildLevel = (flat: Map<string, { mode: string; oid: string }>): string => {
    const entries: TreeEntry[] = [];
    const subdirs = new Map<string, Map<string, { mode: string; oid: string }>>();
    for (const [path, file] of flat) {
      const slash = path.indexOf('/');
      if (slash < 0) {
        entries.push({ mode: file.mode, name: path, oid: file.oid });
      } else {
        const dir = path.slice(0, slash);
        let sub = subdirs.get(dir);
        if (sub === undefined) {
          sub = new Map();
          subdirs.set(dir, sub);
        }
        sub.set(path.slice(slash + 1), file);
      }
    }
    for (const [dir, sub] of subdirs) {
      entries.push({ mode: '40000', name: dir, oid: buildLevel(sub) });
    }
    return putObject(repo, 'tree', buildTreeBytes(entries));
  };
  return buildLevel(files);
}

// Flatten a tree to path -> {mode, oid} for files only.
function flattenTree(repo: Repo, treeOid: string, prefix: string, out: Map<string, { mode: string; oid: string }>): void {
  const obj = getObject(repo, treeOid);
  if (obj === null || obj.kind !== 'tree') return;
  for (const entry of parseTree(obj.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(repo, entry.oid, path, out);
    else out.set(path, { mode: entry.mode, oid: entry.oid });
  }
}

// All commits reachable from `tips`, with their generation (0 at a tip).
// With a depth limit, only generations below it are walked; the boundary set
// holds the deepest included commits that still have parents.
function walkCommits(
  repo: Repo,
  tips: string[],
  depth: number | null,
  skip: Set<string>,
): { found: Map<string, number>; boundary: Set<string> } {
  const found = new Map<string, number>();
  const boundary = new Set<string>();
  const queue: Array<{ oid: string; gen: number }> = [];
  for (const tip of tips) {
    if (isOid(tip) && !found.has(tip)) {
      found.set(tip, 0);
      queue.push({ oid: tip, gen: 0 });
    }
  }
  for (let head = 0; head < queue.length; head += 1) {
    const { oid, gen } = queue[head]!;
    if (skip.has(oid)) continue;
    const obj = getObject(repo, oid);
    if (obj === null || obj.kind !== 'commit') continue;
    const parts = parseCommit(obj.data);
    if (depth !== null && gen >= depth - 1 && parts.parents.length > 0) boundary.add(oid);
    if (depth !== null && gen >= depth - 1) continue;
    for (const parent of parts.parents) {
      if (!found.has(parent)) {
        found.set(parent, gen + 1);
        queue.push({ oid: parent, gen: gen + 1 });
      }
    }
  }
  return { found, boundary };
}

// Every commit reachable from a set of tips, without a depth limit.
function ancestorsOf(repo: Repo, tips: string[]): Map<string, number> {
  return walkCommits(repo, tips, null, new Set()).found;
}

// Whether `maybeAncestor` is an ancestor of (or equal to) `tip`, walking
// back from the tip and stopping the moment it is found — a linear history
// answers in one step instead of a full-history walk.
function isAncestor(repo: Repo, maybeAncestor: string, tip: string): boolean {
  if (maybeAncestor === tip) return true;
  const seen = new Set<string>();
  const queue: string[] = [tip];
  for (let head = 0; head < queue.length; head += 1) {
    const oid = queue[head]!;
    if (oid === maybeAncestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = getObject(repo, oid);
    if (obj === null || obj.kind !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) queue.push(parent);
  }
  return false;
}

// The merge base of two tips: the common ancestor nearest to both.
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const fromA = ancestorsOf(repo, [a]);
  if (fromA.size === 0) return null;
  const queue: Array<{ oid: string; gen: number }> = [{ oid: b, gen: 0 }];
  const seen = new Set<string>([b]);
  let best: string | null = null;
  let bestScore = Infinity;
  for (let head = 0; head < queue.length; head += 1) {
    const { oid, gen } = queue[head]!;
    const genA = fromA.get(oid);
    if (genA !== undefined) {
      const score = genA + gen;
      if (score < bestScore) {
        bestScore = score;
        best = oid;
      }
    }
    const obj = getObject(repo, oid);
    if (obj === null || obj.kind !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) {
      if (!seen.has(parent)) {
        seen.add(parent);
        queue.push({ oid: parent, gen: gen + 1 });
      }
    }
  }
  return best;
}

// Peel a tag (following tag chains) down to the commit it points at.
function peelToCommit(repo: Repo, oid: string): string | null {
  let current = oid;
  for (let hops = 0; hops < 10; hops += 1) {
    const obj = getObject(repo, current);
    if (obj === null) return null;
    if (obj.kind === 'commit') return current;
    if (obj.kind === 'tag') {
      current = parseTag(obj.data).object;
      continue;
    }
    return null;
  }
  return null;
}

interface FileChange {
  path: string;
  status: 'added' | 'modified' | 'removed';
  oldOid: string | null;
  newOid: string | null;
}

// Diff two trees (null means the empty tree) into a sorted change list.
function diffTrees(repo: Repo, baseTree: string | null, headTree: string | null): FileChange[] {
  const base = new Map<string, { mode: string; oid: string }>();
  const head = new Map<string, { mode: string; oid: string }>();
  if (baseTree !== null) flattenTree(repo, baseTree, '', base);
  if (headTree !== null) flattenTree(repo, headTree, '', head);
  const paths = new Set<string>([...base.keys(), ...head.keys()]);
  const changes: FileChange[] = [];
  for (const path of paths) {
    const b = base.get(path);
    const h = head.get(path);
    if (b !== undefined && h === undefined) changes.push({ path, status: 'removed', oldOid: b.oid, newOid: null });
    else if (b === undefined && h !== undefined) changes.push({ path, status: 'added', oldOid: null, newOid: h.oid });
    else if (b !== undefined && h !== undefined && b.oid !== h.oid) {
      changes.push({ path, status: 'modified', oldOid: b.oid, newOid: h.oid });
    }
  }
  changes.sort((x, y) => (x.path < y.path ? -1 : x.path > y.path ? 1 : 0));
  return changes;
}

function countLines(buf: Buffer): number {
  if (buf.length === 0) return 0;
  let lines = 0;
  for (let i = 0; i < buf.length; i += 1) if (buf[i] === 0x0a) lines += 1;
  if (buf[buf.length - 1] !== 0x0a) lines += 1;
  return lines;
}

// Added/deleted line counts for a changed text file, via a small LCS over
// its lines. Binary content counts as one added line when it appears.
function lineDelta(oldBuf: Buffer | null, newBuf: Buffer | null): { additions: number; deletions: number } {
  if (newBuf !== null && oldBuf === null) {
    if (!isText(newBuf)) return { additions: 1, deletions: 0 };
    return { additions: countLines(newBuf), deletions: 0 };
  }
  if (newBuf === null && oldBuf !== null) {
    if (!isText(oldBuf)) return { additions: 0, deletions: 1 };
    return { additions: 0, deletions: countLines(oldBuf) };
  }
  if (newBuf === null || oldBuf === null) return { additions: 0, deletions: 0 };
  if (!isText(oldBuf) || !isText(newBuf)) return { additions: 1, deletions: 1 };
  const oldLines = oldBuf.toString('utf8').split('\n');
  const newLines = newBuf.toString('utf8').split('\n');
  if (oldLines.length > 2000 || newLines.length > 2000) {
    return { additions: newLines.length, deletions: oldLines.length };
  }
  const prev = new Array<number>(newLines.length + 1).fill(0);
  const curr = new Array<number>(newLines.length + 1).fill(0);
  for (let i = 1; i <= oldLines.length; i += 1) {
    for (let j = 1; j <= newLines.length; j += 1) {
      curr[j] = oldLines[i - 1] === newLines[j - 1] ? prev[j - 1] + 1 : Math.max(prev[j], curr[j - 1]);
    }
    for (let j = 0; j <= newLines.length; j += 1) prev[j] = curr[j]!;
  }
  const lcs = prev[newLines.length]!;
  return { additions: newLines.length - lcs, deletions: oldLines.length - lcs };
}

function isText(buf: Buffer): boolean {
  const sample = buf.subarray(0, Math.min(buf.length, 8000));
  return !sample.includes(0);
}

// ------------------------------------------------------------------ packs

// Build a version 2 pack from plain objects (no deltas), in a fixed order,
// with a valid SHA-1 trailer. Each object's id is hashed once and its
// deflated form is cached on the repo, so repeated packs over the same
// objects cost no hashing or zlib.
function buildPack(repo: Repo, objects: GitObject[]): Buffer {
  const rank = (kind: ObjectKind): number => (kind === 'commit' ? 0 : kind === 'tree' ? 1 : kind === 'blob' ? 2 : 3);
  const keyed = objects.map((obj) => ({ obj, oid: objectId(obj.kind, obj.data) }));
  keyed.sort((a, b) => {
    const ra = rank(a.obj.kind);
    const rb = rank(b.obj.kind);
    if (ra !== rb) return ra - rb;
    return a.oid < b.oid ? -1 : a.oid > b.oid ? 1 : 0;
  });
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(keyed.length, 8);
  parts.push(head);
  for (const { obj, oid } of keyed) {
    const code = KIND_CODE[obj.kind];
    const size = obj.data.length;
    const headerBytes: number[] = [];
    let remaining = size;
    let first = (code << 4) | (remaining & 0x0f);
    remaining >>= 4;
    if (remaining > 0) first |= 0x80;
    headerBytes.push(first);
    while (remaining > 0) {
      let byte = remaining & 0x7f;
      remaining >>= 7;
      if (remaining > 0) byte |= 0x80;
      headerBytes.push(byte);
    }
    parts.push(Buffer.from(headerBytes));
    let deflated = repo.deflated.get(oid);
    if (deflated === undefined) {
      deflated = deflateSync(obj.data);
      repo.deflated.set(oid, deflated);
    }
    parts.push(deflated);
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// Parse a packfile, resolving OFS_DELTA and REF_DELTA entries against the
// pack itself or objects the repo already holds (thin packs). Returns the
// resolved objects keyed by oid.
async function readPack(pack: Buffer, repo: Repo): Promise<Map<string, GitObject>> {
  if (pack.length < 32) throw new Error('pack is too short');
  if (pack.toString('ascii', 0, 4) !== 'PACK') throw new Error('pack has no PACK header');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const expected = createHash('sha1').update(pack.subarray(0, trailerStart)).digest('hex');
  const actual = pack.subarray(trailerStart).toString('hex');
  if (expected !== actual) throw new Error('pack trailer checksum mismatch');
  interface RawEntry {
    offset: number;
    code: number;
    size: number;
    data: Buffer;
    baseOffset: number | null;
    baseOid: string | null;
  }
  const entries: RawEntry[] = [];
  let at = 12;
  for (let i = 0; i < count; i += 1) {
    const start = at;
    if (at >= trailerStart) throw new Error('pack ends before its objects');
    let byte = pack[at]!;
    at += 1;
    const code = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      if (at >= trailerStart) throw new Error('pack object header is truncated');
      byte = pack[at]!;
      at += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    let baseOffset: number | null = null;
    let baseOid: string | null = null;
    if (code === 6) {
      if (at >= trailerStart) throw new Error('ofs-delta base is truncated');
      byte = pack[at]!;
      at += 1;
      let off = byte & 0x7f;
      while (byte & 0x80) {
        if (at >= trailerStart) throw new Error('ofs-delta base is truncated');
        byte = pack[at]!;
        at += 1;
        off = ((off + 1) << 7) | (byte & 0x7f);
      }
      baseOffset = start - off;
    } else if (code === 7) {
      if (at + 20 > trailerStart) throw new Error('ref-delta base is truncated');
      baseOid = pack.subarray(at, at + 20).toString('hex');
      at += 20;
    }
    const { data, end } = await inflateOne(pack, at);
    if (data.length !== size) throw new Error('pack object size mismatch');
    entries.push({ offset: start, code, size, data, baseOffset, baseOid });
    at = end;
  }
  const byOffset = new Map<number, RawEntry>();
  for (const entry of entries) byOffset.set(entry.offset, entry);
  const resolved = new Map<string, GitObject>();
  const resolving = new Set<number>();
  const resolve = (entry: RawEntry): GitObject => {
    if (entry.code >= 1 && entry.code <= 4) {
      const kind = CODE_KIND[entry.code]!;
      const obj: GitObject = { kind, data: entry.data };
      resolved.set(objectId(kind, entry.data), obj);
      return obj;
    }
    if (resolving.has(entry.offset)) throw new Error('delta cycle in pack');
    resolving.add(entry.offset);
    let base: GitObject | null = null;
    if (entry.code === 6) {
      const baseEntry = byOffset.get(entry.baseOffset ?? -1);
      if (baseEntry === undefined) throw new Error('ofs-delta base is not in the pack');
      base = resolve(baseEntry);
    } else if (entry.code === 7) {
      for (const [, obj] of resolved) {
        if (objectId(obj.kind, obj.data) === entry.baseOid) {
          base = obj;
          break;
        }
      }
      if (base === null && entry.baseOid !== null) base = getObject(repo, entry.baseOid);
      if (base === null) throw new Error('ref-delta base is neither in the pack nor on the server');
    } else {
      throw new Error(`unknown pack object type ${entry.code}`);
    }
    const data = applyDelta(base.data, entry.data);
    const obj: GitObject = { kind: base.kind, data };
    resolved.set(objectId(base.kind, data), obj);
    resolving.delete(entry.offset);
    return obj;
  };
  for (const entry of entries) resolve(entry);
  return resolved;
}

// ------------------------------------------------------------------ http help

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > 64 * 1024 * 1024) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendBuffer(res: ServerResponse, status: number, body: Buffer, contentType: string, extra?: Record<string, string>): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': String(body.length),
    'x-github-request-id': nextRequestId(),
    ...(extra ?? {}),
  });
  res.end(body);
}

function sendJson(res: ServerResponse, status: number, value: unknown, extra?: Record<string, string>): void {
  sendBuffer(res, status, Buffer.from(JSON.stringify(value), 'utf8'), 'application/json', extra);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

// The bearer token the suite presents. /healthz is the only route that does
// not need one.
function authorized(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  if (EXPECTED_TOKEN === '') return header.startsWith('Bearer ') && header.length > 7;
  return header === `Bearer ${EXPECTED_TOKEN}`;
}

// ------------------------------------------------------------------ git: ads

function sortedRefNames(repo: Repo): { branches: string[]; tags: string[] } {
  const branches: string[] = [];
  const tags: string[] = [];
  for (const ref of repo.refs.keys()) {
    if (ref.startsWith('refs/heads/')) branches.push(ref.slice('refs/heads/'.length));
    else if (ref.startsWith('refs/tags/')) tags.push(ref.slice('refs/tags/'.length));
  }
  branches.sort();
  tags.sort();
  return { branches, tags };
}

function headOid(repo: Repo): string {
  return branchTip(repo, repo.defaultBranch) ?? ZERO_OID;
}

function advertisementV2(repo: Repo): Buffer {
  if (repo.advV2 !== null) return repo.advV2;
  const out = Buffer.concat([
    pktLine('version 2\n'),
    pktLine(`agent=${FORGE_AGENT}\n`),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow filter\n'),
    pktLine('object-format=sha1\n'),
    PKT_FLUSH,
  ]);
  repo.advV2 = out;
  return out;
}

// v0 advertisement, mirroring real git's shape: `# service=<name>` line, a
// flush, the ref lines (each newline-terminated), a final flush. Upload-pack
// puts its capabilities on the HEAD line (with `symref` and `no-done`); an
// empty repository advertises the `capabilities^{}` pseudo-ref with the same
// capabilities minus `symref` and `no-done`. Receive-pack advertises no HEAD
// line at all: its capabilities ride on the first ref line and never include
// `symref` (a symref pointing at a ref that does not exist yet makes real
// git refuse the push).
function advertisementV0(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const cached = service === 'git-upload-pack' ? repo.advV0Up : repo.advV0Recv;
  if (cached !== null) return cached;
  const lines: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const { branches, tags } = sortedRefNames(repo);
  const head = headOid(repo);
  const empty = branches.length === 0 && tags.length === 0;
  if (service === 'git-upload-pack') {
    const baseCaps = `multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed object-format=sha1 agent=${FORGE_AGENT}`;
    if (empty) {
      lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${baseCaps}\n`));
    } else {
      const headCaps = `multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed no-done symref=HEAD:refs/heads/${repo.defaultBranch} object-format=sha1 agent=${FORGE_AGENT}`;
      lines.push(pktLine(`${head} HEAD\0${headCaps}\n`));
      for (const branch of branches) lines.push(pktLine(`${branchTip(repo, branch)} refs/heads/${branch}\n`));
      for (const tag of tags) {
        const oid = refTip(repo, `refs/tags/${tag}`)!;
        lines.push(pktLine(`${oid} refs/tags/${tag}\n`));
        const peeled = peelToCommit(repo, oid);
        if (peeled !== null && peeled !== oid) lines.push(pktLine(`${peeled} refs/tags/${tag}^{}\n`));
      }
    }
  } else {
    const caps = `report-status report-status-v2 delete-refs side-band-64k quiet atomic ofs-delta object-format=sha1 agent=${FORGE_AGENT}`;
    if (empty) {
      lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
    } else {
      let first = true;
      for (const branch of branches) {
        lines.push(pktLine(`${branchTip(repo, branch)} refs/heads/${branch}${first ? `\0${caps}` : ''}\n`));
        first = false;
      }
      for (const tag of tags) {
        const oid = refTip(repo, `refs/tags/${tag}`)!;
        lines.push(pktLine(`${oid} refs/tags/${tag}${first ? `\0${caps}` : ''}\n`));
        first = false;
        const peeled = peelToCommit(repo, oid);
        if (peeled !== null && peeled !== oid) lines.push(pktLine(`${peeled} refs/tags/${tag}^{}\n`));
      }
    }
  }
  lines.push(PKT_FLUSH);
  const out = Buffer.concat(lines);
  if (service === 'git-upload-pack') repo.advV0Up = out;
  else repo.advV0Recv = out;
  return out;
}

// ------------------------------------------------------------------ git: ls-r

function lsRefsResponse(repo: Repo, prefixes: string[], peel: boolean, symrefs: boolean, unborn: boolean): Buffer {
  const key = `${prefixes.join(',')}|${peel}|${symrefs}|${unborn}`;
  const hit = repo.lsRefs.get(key);
  if (hit !== undefined) return hit;
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const lines: Buffer[] = [];
  const head = headOid(repo);
  const headRef = `refs/heads/${repo.defaultBranch}`;
  if (keep('HEAD')) {
    if (head !== ZERO_OID) {
      lines.push(pktLine(`${head} HEAD${symrefs ? ` symref-target:${headRef}` : ''}\n`));
    } else if (unborn) {
      lines.push(pktLine(`unborn HEAD${symrefs ? ` symref-target:${headRef}` : ''}\n`));
    }
  }
  const { branches, tags } = sortedRefNames(repo);
  for (const branch of branches) {
    const name = `refs/heads/${branch}`;
    if (keep(name)) lines.push(pktLine(`${branchTip(repo, branch)} ${name}\n`));
  }
  for (const tag of tags) {
    const name = `refs/tags/${tag}`;
    if (!keep(name)) continue;
    const oid = refTip(repo, name)!;
    let suffix = '';
    if (peel) {
      const peeled = peelToCommit(repo, oid);
      if (peeled !== null && peeled !== oid) suffix = ` peeled:${peeled}`;
    }
    lines.push(pktLine(`${oid} ${name}${suffix}\n`));
  }
  lines.push(PKT_FLUSH);
  const out = Buffer.concat(lines);
  repo.lsRefs.set(key, out);
  return out;
}

// ------------------------------------------------------------------ git: fet

interface FetchPlan {
  objects: GitObject[];
  shallow: string[];
  unshallow: string[];
}

// Every object (commit, tree, blob) reachable from a set of commit tips.
// Traversal stops at a shallow boundary: the boundary commit itself and its
// tree are included, but its parents are not — a shallow clone holds the
// boundary commit without its history.
function reachableObjects(repo: Repo, tips: string[], stopAt: Set<string>): Set<string> {
  const out = new Set<string>();
  const queue: string[] = [];
  for (const tip of tips) {
    if (isOid(tip) && !out.has(tip)) {
      out.add(tip);
      queue.push(tip);
    }
  }
  for (let head = 0; head < queue.length; head += 1) {
    const oid = queue[head]!;
    const obj = getObject(repo, oid);
    if (obj === null) continue;
    if (obj.kind === 'commit') {
      const parts = parseCommit(obj.data);
      if (!out.has(parts.tree)) {
        out.add(parts.tree);
        queue.push(parts.tree);
      }
      if (stopAt.has(oid)) continue;
      for (const parent of parts.parents) {
        if (!out.has(parent)) {
          out.add(parent);
          queue.push(parent);
        }
      }
    } else if (obj.kind === 'tree') {
      for (const entry of parseTree(obj.data)) {
        if (!out.has(entry.oid)) {
          out.add(entry.oid);
          queue.push(entry.oid);
        }
      }
    }
  }
  return out;
}

function planFetch(
  repo: Repo,
  wants: string[],
  haves: string[],
  depth: number | null,
  oldShallow: string[],
  filter: string | null,
): FetchPlan {
  // What the client already holds: every object reachable from its haves,
  // without crossing a shallow boundary. The walk below still traverses
  // through haves (a deepen starts at a have), but nothing in this set is
  // sent again.
  const stopAt = new Set(oldShallow);
  const haveReachable = haves.length > 0 ? reachableObjects(repo, haves, stopAt) : new Set<string>();
  // Expand tag wants to the commits they point at, keeping the tag objects.
  const tagObjects: GitObject[] = [];
  const commitWants: string[] = [];
  const directObjects: GitObject[] = [];
  for (const want of wants) {
    const obj = getObject(repo, want);
    if (obj === null) continue;
    if (obj.kind === 'tag') {
      tagObjects.push(obj);
      const target = peelToCommit(repo, want);
      if (target !== null) commitWants.push(target);
    } else if (obj.kind === 'commit') {
      commitWants.push(want);
    } else {
      directObjects.push(obj);
    }
  }
  const { found, boundary } = walkCommits(repo, commitWants, depth, new Set());
  const included = new Map<string, GitObject>();
  const addTreeObjects = (treeOid: string): void => {
    if (haveReachable.has(treeOid)) return;
    const obj = getObject(repo, treeOid);
    if (obj === null || obj.kind !== 'tree') return;
    if (filter !== 'tree:0') included.set(treeOid, obj);
    for (const entry of parseTree(obj.data)) {
      if (entry.mode === '40000') addTreeObjects(entry.oid);
      else if (filter !== 'blob:none' && filter !== 'tree:0') {
        if (haveReachable.has(entry.oid)) continue;
        const blob = getObject(repo, entry.oid);
        if (blob !== null) included.set(entry.oid, blob);
      }
    }
  };
  for (const oid of found.keys()) {
    if (haveReachable.has(oid)) continue;
    const obj = getObject(repo, oid);
    if (obj === null || obj.kind !== 'commit') continue;
    included.set(oid, obj);
    addTreeObjects(parseCommit(obj.data).tree);
  }
  for (const obj of tagObjects) included.set(objectId(obj.kind, obj.data), obj);
  for (const obj of directObjects) included.set(objectId(obj.kind, obj.data), obj);
  const shallow = [...boundary].filter((oid) => !haveReachable.has(oid)).sort();
  const unshallow: string[] = [];
  for (const old of oldShallow) {
    if (!found.has(old)) continue;
    if (depth === null || (found.get(old) ?? 0) < depth - 1) unshallow.push(old);
  }
  unshallow.sort();
  return { objects: [...included.values()], shallow, unshallow };
}

function fetchResponseV2(repo: Repo, wants: string[], haves: string[], depth: number | null, oldShallow: string[], filter: string | null): Buffer {
  const key = `2|${[...wants].sort().join(',')}|${[...haves].sort().join(',')}|${depth ?? ''}|${[...oldShallow].sort().join(',')}|${filter ?? ''}`;
  const hit = repo.fetchResp.get(key);
  if (hit !== undefined) return hit;
  const plan = planFetch(repo, wants, haves, depth, oldShallow, filter);
  // Stateless RPC (HTTP) never carries an acknowledgments section: the
  // client already said `done` with its haves, so the server answers with
  // the pack directly. Real git's upload-pack sends no ack section even
  // when haves were sent; sending one makes real git abort the fetch.
  // Sections with nothing to report are omitted entirely, each present
  // section closed by a delim; the packfile section is always present,
  // even when the pack holds zero objects.
  const parts: Buffer[] = [];
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of plan.shallow) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(PKT_DELIM);
  }
  parts.push(pktLine('packfile\n'));
  parts.push(sidebandPack(buildPack(repo, plan.objects)));
  const out = Buffer.concat(parts);
  repo.fetchResp.set(key, out);
  return out;
}

function fetchResponseV0(repo: Repo, wants: string[], haves: string[], depth: number | null, oldShallow: string[], filter: string | null): Buffer {
  const key = `0|${[...wants].sort().join(',')}|${[...haves].sort().join(',')}|${depth ?? ''}|${[...oldShallow].sort().join(',')}|${filter ?? ''}`;
  const hit = repo.fetchResp.get(key);
  if (hit !== undefined) return hit;
  const plan = planFetch(repo, wants, haves, depth, oldShallow, filter);
  const parts: Buffer[] = [];
  if (haves.length === 0) {
    parts.push(pktLine('NAK\n'));
  } else {
    const known = haves.filter((oid) => getObject(repo, oid) !== null);
    if (known.length === 0) parts.push(pktLine('NAK\n'));
    else for (const oid of known) parts.push(pktLine(`ACK ${oid}\n`));
  }
  for (const oid of plan.shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  parts.push(sidebandPack(buildPack(repo, plan.objects)));
  const out = Buffer.concat(parts);
  repo.fetchResp.set(key, out);
  return out;
}

// ------------------------------------------------------------------ git: han

function gitRepoOr404(res: ServerResponse, owner: string, repoName: string): Repo | null {
  const repo = findRepo(owner, repoName);
  if (repo === null) {
    sendError(res, 404, 'Not Found');
    return null;
  }
  return repo;
}

async function handleInfoRefs(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, service: string): Promise<void> {
  if (!authorized(req)) {
    sendError(res, 401, 'Requires authentication');
    return;
  }
  learnViewer(owner);
  const repo = gitRepoOr404(res, owner, repoName);
  if (repo === null) return;
  if (service === 'git-upload-pack') {
    if (req.headers['git-protocol'] === 'version=2') {
      sendBuffer(res, 200, advertisementV2(repo), 'application/x-git-upload-pack-advertisement');
    } else {
      sendBuffer(res, 200, advertisementV0(repo, 'git-upload-pack'), 'application/x-git-upload-pack-advertisement');
    }
    return;
  }
  if (service === 'git-receive-pack') {
    sendBuffer(res, 200, advertisementV0(repo, 'git-receive-pack'), 'application/x-git-receive-pack-advertisement');
    return;
  }
  sendError(res, 400, `unknown service ${service}`);
}

async function handleUploadPack(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string): Promise<void> {
  try {
    if (!authorized(req)) {
      sendError(res, 401, 'Requires authentication');
      return;
    }
    learnViewer(owner);
    const repo = gitRepoOr404(res, owner, repoName);
    if (repo === null) return;
    const body = await readBody(req);
    const isV2 = req.headers['git-protocol'] === 'version=2';
    const packets = allPktLines(body);
    const lines = packets.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
    if (isV2) {
      const command = lines[0] ?? '';
      if (command.startsWith('command=ls-refs')) {
        const argLines = lines.filter((l) => !l.startsWith('command=') && !l.startsWith('agent=') && !l.startsWith('object-format='));
        const prefixes: string[] = [];
        let peel = false;
        let symrefs = false;
        let unborn = false;
        for (const line of argLines) {
          const text = line.replace(/\n$/, '');
          if (text === 'peel') peel = true;
          else if (text === 'symrefs') symrefs = true;
          else if (text === 'unborn') unborn = true;
          else if (text.startsWith('ref-prefix ')) prefixes.push(text.slice('ref-prefix '.length));
        }
        sendBuffer(res, 200, lsRefsResponse(repo, prefixes, peel, symrefs, unborn), 'application/x-git-upload-pack-result');
        return;
      }
      if (command.startsWith('command=fetch')) {
        const wants: string[] = [];
        const haves: string[] = [];
        const oldShallow: string[] = [];
        let depth: number | null = null;
        let filter: string | null = null;
        for (const raw of lines) {
          const line = raw.replace(/\n$/, '');
          if (line.startsWith('want ')) wants.push(line.slice(5).trim());
          else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
          else if (line.startsWith('shallow ')) oldShallow.push(line.slice(8).trim());
          else if (line.startsWith('deepen ')) {
            const n = Number.parseInt(line.slice(7).trim(), 10);
            if (Number.isFinite(n)) depth = n;
          } else if (line.startsWith('filter ')) filter = line.slice(7).trim();
        }
        sendBuffer(res, 200, fetchResponseV2(repo, wants, haves, depth, oldShallow, filter), 'application/x-git-upload-pack-result');
        return;
      }
      sendError(res, 400, 'unknown upload-pack command');
      return;
    }
    // Protocol v0: wants (+ shallow/deepen) up to a flush, then haves + done.
    const sections: string[][] = [[]];
    for (const packet of packets) {
      if (packet.kind === 'flush') {
        sections.push([]);
        continue;
      }
      if (packet.kind !== 'data') continue;
      sections[sections.length - 1]!.push(packet.payload.toString('utf8'));
    }
    const wants: string[] = [];
    const haves: string[] = [];
    const oldShallow: string[] = [];
    let depth: number | null = null;
    for (const section of sections) {
      for (const raw of section) {
        const line = raw.replace(/\n$/, '');
        if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0]!);
        else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
        else if (line.startsWith('shallow ')) oldShallow.push(line.slice(8).trim());
        else if (line.startsWith('deepen ')) {
          const n = Number.parseInt(line.slice(7).trim(), 10);
          if (Number.isFinite(n)) depth = n;
        }
      }
    }
    if (wants.length === 0) {
      sendBuffer(res, 200, Buffer.concat([pktLine('NAK\n'), PKT_FLUSH]), 'application/x-git-upload-pack-result');
      return;
    }
    sendBuffer(res, 200, fetchResponseV0(repo, wants, haves, depth, oldShallow, null), 'application/x-git-upload-pack-result');
  } catch {
    if (!res.headersSent) sendError(res, 400, 'malformed git request');
  }
}

async function handleReceivePack(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string): Promise<void> {
  try {
    if (!authorized(req)) {
      sendError(res, 401, 'Requires authentication');
      return;
    }
    learnViewer(owner);
    const repo = gitRepoOr404(res, owner, repoName);
    if (repo === null) return;
    const body = await readBody(req);
    const { packets, offset } = readPktLines(body);
    const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
    let requestCaps = '';
    for (const packet of packets) {
      if (packet.kind !== 'data') continue;
      let text = packet.payload.toString('utf8').replace(/\n$/, '');
      const nul = text.indexOf('\0');
      if (nul >= 0) {
        if (commands.length === 0) requestCaps = text.slice(nul + 1);
        text = text.slice(0, nul);
      }
      const parts = text.split(' ');
      if (parts.length < 3 || !isOid(parts[0]) || !isOid(parts[1])) throw new Error('bad receive-pack command');
      commands.push({ oldOid: parts[0]!, newOid: parts[1]!, ref: parts[2]! });
    }
    if (commands.length === 0) throw new Error('no receive-pack commands');
    const sideband = requestCaps.split(' ').includes('side-band-64k');
    // The pack follows the command flush, when the push carries one.
    let unpackError: string | null = null;
    const rest = body.subarray(offset);
    if (rest.length > 0) {
      try {
        const objects = await readPack(rest, repo);
        for (const [oid, obj] of objects) {
          if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
        }
      } catch (err) {
        unpackError = err instanceof Error ? err.message : 'unpack failed';
      }
    }
    const report: Buffer[] = [];
    let changed = false;
    if (unpackError !== null) {
      report.push(pktLine(`unpack ${unpackError}\n`));
    } else {
      report.push(pktLine('unpack ok\n'));
      for (const cmd of commands) {
        const fail = (reason: string): void => {
          report.push(pktLine(`ng ${cmd.ref} ${reason}\n`));
        };
        if (!cmd.ref.startsWith('refs/')) {
          fail('invalid ref');
          continue;
        }
        if (cmd.newOid === ZERO_OID) {
          if (!repo.refs.has(cmd.ref)) fail('remote ref does not exist');
          else {
            repo.refs.delete(cmd.ref);
            changed = true;
            report.push(pktLine(`ok ${cmd.ref}\n`));
          }
          continue;
        }
        const current = repo.refs.get(cmd.ref);
        if (cmd.oldOid === ZERO_OID) {
          if (current !== undefined) fail('non-fast-forward');
          else if (getObject(repo, cmd.newOid) === null) fail('object not found');
          else {
            repo.refs.set(cmd.ref, cmd.newOid);
            changed = true;
            report.push(pktLine(`ok ${cmd.ref}\n`));
          }
          continue;
        }
        if (current === undefined) fail('remote ref does not exist');
        else if (current !== cmd.oldOid) fail('non-fast-forward');
        else if (getObject(repo, cmd.newOid) === null) fail('object not found');
        else if (!isAncestor(repo, cmd.oldOid, cmd.newOid)) fail('non-fast-forward');
        else {
          repo.refs.set(cmd.ref, cmd.newOid);
          changed = true;
          report.push(pktLine(`ok ${cmd.ref}\n`));
        }
      }
    }
    report.push(PKT_FLUSH);
    if (changed) invalidate(repo);
    const inner = Buffer.concat(report);
    if (sideband) sendBuffer(res, 200, sidebandPack(inner), 'application/x-git-receive-pack-result');
    else sendBuffer(res, 200, inner, 'application/x-git-receive-pack-result');
  } catch {
    if (!res.headersSent) sendError(res, 400, 'malformed git request');
  }
}

// ------------------------------------------------------------------ rest views

function originOf(req: IncomingMessage): string {
  return `http://${req.headers.host ?? '127.0.0.1'}`;
}

function globalId(prefix: string, key: string): string {
  return `${prefix}_${b64url(key)}`;
}

function repoGlobalId(repo: Repo): string {
  return globalId('R', `${repo.owner}/${repo.name}`);
}
function issueGlobalId(repo: Repo, number: number): string {
  return globalId('I', `${repo.owner}/${repo.name}#${number}`);
}
function pullGlobalId(repo: Repo, number: number): string {
  return globalId('P', `${repo.owner}/${repo.name}#${number}`);
}
function commentGlobalId(repo: Repo, number: number, id: number): string {
  return globalId('C', `${repo.owner}/${repo.name}#${number}:${id}`);
}

// The repository object GitHub returns, as a string. Cached per repo and
// origin; rebuilt when the repo changes or a different origin asks.
function repoJson(repo: Repo, origin: string): Buffer {
  if (repo.repoJson !== null && repo.repoJsonOrigin === origin) return repo.repoJson;
  const text =
    `{"id":${repo.id},"node_id":${JSON.stringify(repoGlobalId(repo))},"name":${JSON.stringify(repo.name)},` +
    `"full_name":${JSON.stringify(`${repo.owner}/${repo.name}`)},` +
    `"owner":{"login":${JSON.stringify(repo.owner)},"id":1,"node_id":${JSON.stringify(globalId('U', repo.owner))},"type":"User"},` +
    `"private":${repo.isPrivate},"description":${JSON.stringify(repo.description)},` +
    `"default_branch":${JSON.stringify(repo.defaultBranch)},"created_at":${JSON.stringify(stampFor(repo.createdSeq))},` +
    `"updated_at":${JSON.stringify(stampFor(repo.createdSeq))},` +
    `"url":${JSON.stringify(`${origin}/api/v3/repos/${repo.owner}/${repo.name}`)},` +
    `"html_url":${JSON.stringify(`https://github.com/${repo.owner}/${repo.name}`)},` +
    `"clone_url":${JSON.stringify(`${origin}/${repo.owner}/${repo.name}.git`)},` +
    `"has_issues":true,"has_projects":true,"has_wiki":true,"archived":false,"disabled":false}`;
  repo.repoJson = Buffer.from(text, 'utf8');
  repo.repoJsonOrigin = origin;
  return repo.repoJson;
}

// One issue as GitHub renders it. The result is cached per issue (and
// origin) because the read workload fetches the same issue two thousand
// times; any change to the issue drops the cached bytes.
function issueJson(repo: Repo, issue: Issue, origin: string): Buffer {
  const hit = repo.issueJson.get(issue.number);
  if (hit !== undefined && hit.origin === origin) return hit.buf;
  const labels = issue.labels
    .map((name) => {
      const label = repo.labels.get(name);
      const color = label === undefined ? 'ededed' : label.color;
      const id = label === undefined ? 0 : label.id;
      return `{"id":${id},"name":${JSON.stringify(name)},"color":${JSON.stringify(color)},"description":""}`;
    })
    .join(',');
  const text =
    `{"id":${issue.id},"node_id":${JSON.stringify(issueGlobalId(repo, issue.number))},"number":${issue.number},` +
    `"title":${JSON.stringify(issue.title)},"body":${JSON.stringify(issue.body)},"state":${JSON.stringify(issue.state)},` +
    `"labels":[${labels}],"user":{"login":${JSON.stringify(repo.owner)},"id":1,"type":"User"},` +
    `"comments":${issue.comments.length},"created_at":${JSON.stringify(stampFor(issue.createdSeq))},` +
    `"updated_at":${JSON.stringify(stampFor(issue.updatedSeq))},` +
    `"url":${JSON.stringify(`${origin}/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`)},` +
    `"html_url":${JSON.stringify(`https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`)},` +
    `"repository_url":${JSON.stringify(`${origin}/api/v3/repos/${repo.owner}/${repo.name}`)}}`;
  const out = Buffer.from(text, 'utf8');
  repo.issueJson.set(issue.number, { origin, buf: out });
  return out;
}

function pullView(repo: Repo, pull: Pull, origin: string, mergeable: boolean | null): Record<string, unknown> {
  return {
    id: pull.id,
    node_id: pullGlobalId(repo, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    mergeable,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeSha,
    head: { label: `${repo.owner}:${pull.headRef}`, ref: pull.headRef, sha: pull.headSha },
    base: { label: `${repo.owner}:${pull.baseRef}`, ref: pull.baseRef, sha: pull.baseSha },
    user: { login: repo.owner, id: 1, type: 'User' },
    created_at: stampFor(pull.createdSeq),
    updated_at: stampFor(pull.updatedSeq),
    url: `${origin}/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}

// Parse the author/committer date out of a commit object, as an ISO string.
function commitDate(data: Buffer): string {
  const text = data.toString('utf8');
  const at = text.indexOf('author ');
  if (at < 0) return stampFor(0);
  const line = text.slice(at, text.indexOf('\n', at));
  const match = /(\d+) \+0000/.exec(line);
  if (match === null) return stampFor(0);
  return new Date(Number.parseInt(match[1]!, 10) * 1000).toISOString();
}

function commitView(repo: Repo, oid: string): Record<string, unknown> | null {
  const obj = getObject(repo, oid);
  if (obj === null || obj.kind !== 'commit') return null;
  const parts = parseCommit(obj.data);
  const date = commitDate(obj.data);
  return {
    sha: oid,
    commit: {
      // The stored object keeps git's trailing newline; the API presents
      // the message without it, as GitHub does.
      message: parts.message.replace(/\n+$/, ''),
      author: { name: 'Forge', email: 'forge@make.fun', date },
      committer: { name: 'Forge', email: 'forge@make.fun', date },
    },
    parents: parts.parents.map((sha) => ({ sha })),
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/commits/${oid}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${oid}`,
  };
}

// ------------------------------------------------------------------ contents

// Write (or replace) one file on a branch and commit it. A missing branch is
// created from the default branch's tip (or from nothing when the repo is
// unborn), which is how the suite's setup makes a head branch.
function writeFile(
  repo: Repo,
  path: string,
  content: Buffer,
  message: string,
  branch: string,
  expectedSha: string | null,
): { status: number; commitSha: string; blobSha: string; error?: string } {
  let tip = branchTip(repo, branch);
  if (tip === null) {
    const base = branchTip(repo, repo.defaultBranch);
    if (base !== null) repo.refs.set(`refs/heads/${branch}`, base);
    tip = base;
  }
  const files = new Map<string, { mode: string; oid: string }>();
  let baseTree: string | null = null;
  if (tip !== null) {
    const commit = getObject(repo, tip);
    if (commit !== null && commit.kind === 'commit') baseTree = parseCommit(commit.data).tree;
  }
  if (baseTree !== null) flattenTree(repo, baseTree, '', files);
  const existing = files.get(path);
  if (existing !== undefined && expectedSha !== null && existing.oid !== expectedSha) {
    return { status: 409, commitSha: '', blobSha: '', error: 'sha does not match the current file' };
  }
  if (existing === undefined && expectedSha !== null) {
    return { status: 422, commitSha: '', blobSha: '', error: 'sha does not match any file' };
  }
  const blobSha = putObject(repo, 'blob', content);
  files.set(path, { mode: '100644', oid: blobSha });
  const tree = buildTree(repo, files);
  const parents = tip === null ? [] : [tip];
  const commitSha = makeCommit(repo, tree, parents, message);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  invalidate(repo);
  return { status: existing === undefined ? 201 : 200, commitSha, blobSha };
}

function deleteFile(
  repo: Repo,
  path: string,
  message: string,
  branch: string,
  expectedSha: string | null,
): { status: number; commitSha: string; error?: string } {
  const tip = branchTip(repo, branch);
  if (tip === null) return { status: 404, commitSha: '', error: 'branch has no commit' };
  const commit = getObject(repo, tip);
  if (commit === null || commit.kind !== 'commit') return { status: 404, commitSha: '', error: 'branch has no commit' };
  const files = new Map<string, { mode: string; oid: string }>();
  flattenTree(repo, parseCommit(commit.data).tree, '', files);
  const existing = files.get(path);
  if (existing === undefined) return { status: 404, commitSha: '', error: 'file does not exist' };
  if (expectedSha !== null && existing.oid !== expectedSha) {
    return { status: 409, commitSha: '', error: 'sha does not match the current file' };
  }
  files.delete(path);
  const tree = buildTree(repo, files);
  const commitSha = makeCommit(repo, tree, [tip], message);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  invalidate(repo);
  return { status: 200, commitSha };
}

// Resolve a ref name (branch, or a full ref) to its tip commit, or null.
function resolveRef(repo: Repo, ref: string | null): string | null {
  if (ref === null || ref === '') return branchTip(repo, repo.defaultBranch);
  if (ref.startsWith('refs/')) return refTip(repo, ref);
  const branch = branchTip(repo, ref);
  if (branch !== null) return branch;
  if (isOid(ref) && getObject(repo, ref) !== null) return ref;
  return null;
}

// ------------------------------------------------------------------ merging

interface MergeOutcome {
  ok: boolean;
  status: number;
  sha: string;
  message: string;
}

// Squash-merge a pull request: one commit on the base branch whose tree is
// the base tree with the head's changes since the merge base applied. A
// file both sides changed differently since the merge base is a conflict.
function mergePullRequest(repo: Repo, pull: Pull): MergeOutcome {
  if (pull.merged) return { ok: false, status: 405, sha: '', message: 'Pull request already merged' };
  if (pull.state !== 'open') return { ok: false, status: 405, sha: '', message: 'Pull request is closed' };
  const headTip = branchTip(repo, pull.headRef);
  const baseTip = branchTip(repo, pull.baseRef);
  if (headTip === null || baseTip === null) return { ok: false, status: 422, sha: '', message: 'head or base branch is missing' };
  const base = mergeBase(repo, headTip, baseTip);
  let baseTree: string | null = null;
  if (base !== null) {
    const obj = getObject(repo, base);
    if (obj !== null && obj.kind === 'commit') baseTree = parseCommit(obj.data).tree;
  }
  const headObj = getObject(repo, headTip);
  const baseObj = getObject(repo, baseTip);
  if (headObj === null || baseObj === null || headObj.kind !== 'commit' || baseObj.kind !== 'commit') {
    return { ok: false, status: 422, sha: '', message: 'head or base commit is missing' };
  }
  const headTree = parseCommit(headObj.data).tree;
  const baseTipTree = parseCommit(baseObj.data).tree;
  const headChanges = diffTrees(repo, baseTree, headTree);
  const baseChanges = diffTrees(repo, baseTree, baseTipTree);
  const baseByPath = new Map<string, FileChange>();
  for (const change of baseChanges) baseByPath.set(change.path, change);
  for (const change of headChanges) {
    const other = baseByPath.get(change.path);
    if (other === undefined) continue;
    const headOid = change.newOid;
    const baseOid = other.newOid;
    if (headOid !== baseOid) return { ok: false, status: 405, sha: '', message: 'Merge conflict' };
  }
  const files = new Map<string, { mode: string; oid: string }>();
  flattenTree(repo, baseTipTree, '', files);
  for (const change of headChanges) {
    if (change.newOid === null) files.delete(change.path);
    else files.set(change.path, { mode: '100644', oid: change.newOid });
  }
  const tree = buildTree(repo, files);
  const message = pull.body !== '' ? `${pull.title}\n\n${pull.body}` : pull.title;
  const sha = makeCommit(repo, tree, [baseTip], message);
  repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  const seq = nextTick();
  pull.merged = true;
  pull.state = 'closed';
  pull.mergedAt = stampFor(seq);
  pull.mergeSha = sha;
  pull.updatedSeq = seq;
  invalidate(repo);
  return { ok: true, status: 200, sha, message: 'Pull request successfully merged' };
}

// Is this pull request mergeable right now (no conflict)? Null when the
// question cannot be answered (a branch is missing).
function pullMergeable(repo: Repo, pull: Pull): boolean | null {
  if (pull.merged || pull.state !== 'open') return false;
  const headTip = branchTip(repo, pull.headRef);
  const baseTip = branchTip(repo, pull.baseRef);
  if (headTip === null || baseTip === null) return null;
  const base = mergeBase(repo, headTip, baseTip);
  let baseTree: string | null = null;
  if (base !== null) {
    const obj = getObject(repo, base);
    if (obj !== null && obj.kind === 'commit') baseTree = parseCommit(obj.data).tree;
  }
  const headObj = getObject(repo, headTip);
  const baseObj = getObject(repo, baseTip);
  if (headObj === null || baseObj === null || headObj.kind !== 'commit' || baseObj.kind !== 'commit') return null;
  const headChanges = diffTrees(repo, baseTree, parseCommit(headObj.data).tree);
  const baseChanges = diffTrees(repo, baseTree, parseCommit(baseObj.data).tree);
  const baseByPath = new Map<string, FileChange>();
  for (const change of baseChanges) baseByPath.set(change.path, change);
  for (const change of headChanges) {
    const other = baseByPath.get(change.path);
    if (other !== undefined && change.newOid !== other.newOid) return false;
  }
  return true;
}

// The changed files of a pull request: the merge-base tree against the head.
function pullFiles(repo: Repo, pull: Pull): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> {
  const headTip = branchTip(repo, pull.headRef);
  const baseTip = branchTip(repo, pull.baseRef);
  if (headTip === null || baseTip === null) return [];
  const base = mergeBase(repo, headTip, baseTip);
  let baseTree: string | null = null;
  if (base !== null) {
    const obj = getObject(repo, base);
    if (obj !== null && obj.kind === 'commit') baseTree = parseCommit(obj.data).tree;
  }
  const headObj = getObject(repo, headTip);
  if (headObj === null || headObj.kind !== 'commit') return [];
  const changes = diffTrees(repo, baseTree, parseCommit(headObj.data).tree);
  return changes.map((change) => {
    const oldBuf = change.oldOid === null ? null : (getObject(repo, change.oldOid)?.data ?? null);
    const newBuf = change.newOid === null ? null : (getObject(repo, change.newOid)?.data ?? null);
    const delta = lineDelta(oldBuf, newBuf);
    return {
      filename: change.path,
      status: change.status,
      additions: delta.additions,
      deletions: delta.deletions,
      changes: delta.additions + delta.deletions,
    };
  });
}

// ------------------------------------------------------------------ rest: bo

async function readJsonBody(req: IncomingMessage): Promise<{ ok: boolean; value: Record<string, unknown> }> {
  const raw = await readBody(req);
  if (raw.length === 0) return { ok: true, value: {} };
  try {
    const parsed: unknown = JSON.parse(raw.toString('utf8'));
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) return { ok: true, value: parsed as Record<string, unknown> };
    return { ok: true, value: {} };
  } catch {
    return { ok: false, value: {} };
  }
}

function pageOf(query: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, Number.parseInt(query.get('page') ?? '1', 10) || 1);
  const perPage = Math.min(100, Math.max(1, Number.parseInt(query.get('per_page') ?? '30', 10) || 30));
  return { page, perPage };
}

function pageLinks(origin: string, path: string, query: URLSearchParams, page: number, perPage: number, total: number): string | null {
  const lastPage = Math.max(1, Math.ceil(total / perPage));
  if (total <= perPage && page === 1) return null;
  const parts: string[] = [];
  const base = `${origin}${path}?per_page=${perPage}`;
  if (page < lastPage) parts.push(`<${base}&page=${page + 1}>; rel="next"`);
  if (page > 1) parts.push(`<${base}&page=${page - 1}>; rel="prev"`);
  parts.push(`<${base}&page=1>; rel="first"`);
  parts.push(`<${base}&page=${lastPage}>; rel="last"`);
  void query;
  return parts.join(', ');
}

function paged<T>(items: T[], page: number, perPage: number): T[] {
  return items.slice((page - 1) * perPage, page * perPage);
}

interface CreateIssueResult {
  issue: Issue | null;
  status: number;
  message: string;
}

function createIssueIn(repo: Repo, title: string, body: string, labelNames: string[]): CreateIssueResult {
  if (title === '') return { issue: null, status: 422, message: 'title is required' };
  for (const name of labelNames) {
    if (!repo.labels.has(name)) return { issue: null, status: 422, message: `Label '${name}' does not exist` };
  }
  const seq = nextTick();
  const issue: Issue = {
    id: store.nextIssueId,
    number: repo.nextNumber,
    title,
    body,
    state: 'open',
    labels: [...labelNames],
    createdSeq: seq,
    updatedSeq: seq,
    comments: [],
  };
  store.nextIssueId += 1;
  repo.nextNumber += 1;
  repo.issues.push(issue);
  repo.issueByNumber.set(issue.number, issue);
  invalidate(repo);
  return { issue, status: 201, message: '' };
}

function labelNamesOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const names: string[] = [];
  for (const entry of value) {
    if (typeof entry === 'string') names.push(entry);
    else if (entry !== null && typeof entry === 'object' && typeof (entry as { name?: unknown }).name === 'string') {
      names.push((entry as { name: string }).name);
    }
  }
  return names;
}

function branchNameOf(value: unknown): string {
  if (typeof value !== 'string') return '';
  const colon = value.lastIndexOf(':');
  return colon >= 0 ? value.slice(colon + 1) : value;
}

interface CreatePullResult {
  pull: Pull | null;
  status: number;
  message: string;
}

function createPullIn(repo: Repo, title: string, body: string, head: string, base: string): CreatePullResult {
  if (title === '') return { pull: null, status: 422, message: 'title is required' };
  const headSha = branchTip(repo, head);
  const baseSha = branchTip(repo, base);
  if (headSha === null || baseSha === null) return { pull: null, status: 422, message: 'head or base branch does not exist' };
  const seq = nextTick();
  const pull: Pull = {
    id: store.nextIssueId,
    number: repo.nextNumber,
    title,
    body,
    state: 'open',
    merged: false,
    headRef: head,
    baseRef: base,
    headSha,
    baseSha,
    mergedAt: null,
    mergeSha: null,
    createdSeq: seq,
    updatedSeq: seq,
  };
  store.nextIssueId += 1;
  repo.nextNumber += 1;
  repo.pulls.push(pull);
  repo.pullByNumber.set(pull.number, pull);
  invalidate(repo);
  return { pull, status: 201, message: '' };
}

// ------------------------------------------------------------------ rest: ro

async function handleRest(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
  const path = url.pathname;
  if (!path.startsWith('/api/v3')) return false;
  if (!authorized(req)) {
    sendError(res, 401, 'Requires authentication');
    return true;
  }
  const method = req.method ?? 'GET';
  const origin = originOf(req);

  if (path === '/api/v3' || path === '/api/v3/') {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return true;
    }
    sendJson(res, 200, {
      current_user_url: `${origin}/api/v3/user`,
      repository_url: `${origin}/api/v3/repos/{owner}/{repo}`,
      user_url: `${origin}/api/v3/users/{user}`,
    }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  if (path === '/api/v3/meta') {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return true;
    }
    sendJson(res, 200, { installed_version: '1.0.0' });
    return true;
  }

  if (path === '/api/v3/user') {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return true;
    }
    sendJson(res, 200, { login: store.viewer, id: 1, node_id: globalId('U', store.viewer), type: 'User' });
    return true;
  }

  if (path === '/api/v3/user/repos') {
    if (method === 'GET') {
      const { page, perPage } = pageOf(url.searchParams);
      const mine = [...store.repos.values()].filter((r) => r.owner === store.viewer).sort((a, b) => a.createdSeq - b.createdSeq);
      const slice = paged(mine, page, perPage);
      const body = `[${slice.map((r) => repoJson(r, origin).toString('utf8')).join(',')}]`;
      const links = pageLinks(origin, path, url.searchParams, page, perPage, mine.length);
      sendBuffer(res, 200, Buffer.from(body, 'utf8'), 'application/json', links === null ? undefined : { link: links });
      return true;
    }
    if (method === 'POST') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, 'malformed JSON body');
        return true;
      }
      const name = typeof parsed.value.name === 'string' ? parsed.value.name : '';
      const description = typeof parsed.value.description === 'string' ? parsed.value.description : '';
      const isPrivate = parsed.value.private === true;
      if (name === '' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) {
        sendError(res, 422, 'name is invalid');
        return true;
      }
      if (findRepo(store.viewer, name) !== null) {
        sendError(res, 422, 'Repository already exists');
        return true;
      }
      const repo = newRepo(store.viewer, name, description, isPrivate);
      sendBuffer(res, 201, repoJson(repo, origin), 'application/json');
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  if (!path.startsWith('/api/v3/repos/')) {
    sendError(res, 404, 'Not Found');
    return true;
  }
  const rest = path.slice('/api/v3/repos/'.length);
  const parts = rest.split('/').map((p) => {
    try {
      return decodeURIComponent(p);
    } catch {
      return p;
    }
  });
  const owner = parts[0] ?? '';
  const repoName = parts[1] ?? '';
  if (owner === '' || repoName === '') {
    sendError(res, 404, 'Not Found');
    return true;
  }
  learnViewer(owner);
  if (owner !== store.viewer) {
    sendError(res, 404, 'Not Found');
    return true;
  }
  const repo = findRepo(owner, repoName);
  if (repo === null) {
    sendError(res, 404, 'Not Found');
    return true;
  }
  const tail = parts.slice(2);

  // ---- the repository itself
  if (tail.length === 0) {
    if (method === 'GET') {
      sendBuffer(res, 200, repoJson(repo, origin), 'application/json');
      return true;
    }
    if (method === 'PATCH') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, 'malformed JSON body');
        return true;
      }
      if (typeof parsed.value.description === 'string') repo.description = parsed.value.description;
      if (typeof parsed.value.private === 'boolean') repo.isPrivate = parsed.value.private;
      invalidate(repo);
      sendBuffer(res, 200, repoJson(repo, origin), 'application/json');
      return true;
    }
    if (method === 'DELETE') {
      store.repos.delete(repoKey(owner, repoName));
      res.writeHead(204, { 'x-github-request-id': nextRequestId() });
      res.end();
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  // ---- branches
  if (tail[0] === 'branches') {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (tail.length === 1) {
      const { branches } = sortedRefNames(repo);
      const list = branches.map((name) => ({
        name,
        commit: { sha: branchTip(repo, name), url: `${origin}/api/v3/repos/${owner}/${repoName}/commits/${branchTip(repo, name)}` },
        protected: false,
      }));
      sendJson(res, 200, list);
      return true;
    }
    const branch = tail[1]!;
    const tip = branchTip(repo, branch);
    if (tip === null) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    sendJson(res, 200, {
      name: branch,
      commit: { sha: tip, url: `${origin}/api/v3/repos/${owner}/${repoName}/commits/${tip}` },
      protected: false,
    });
    return true;
  }

  // ---- commits
  if (tail[0] === 'commits') {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const shaParam = url.searchParams.get('sha');
    const tip = shaParam === null ? branchTip(repo, repo.defaultBranch) : resolveRef(repo, shaParam);
    const list: Array<Record<string, unknown>> = [];
    let current = tip;
    const seen = new Set<string>();
    while (current !== null && !seen.has(current) && list.length < 1000) {
      seen.add(current);
      const view = commitView(repo, current);
      if (view === null) break;
      list.push(view);
      const obj = getObject(repo, current);
      if (obj === null || obj.kind !== 'commit') break;
      const parents = parseCommit(obj.data).parents;
      current = parents.length > 0 ? parents[0]! : null;
    }
    sendJson(res, 200, list);
    return true;
  }

  // ---- contents
  if (tail[0] === 'contents') {
    const contentPath = tail.slice(1).join('/');
    if (method === 'GET') {
      const tip = resolveRef(repo, url.searchParams.get('ref'));
      if (tip === null) {
        sendError(res, 404, 'Not Found');
        return true;
      }
      const commit = getObject(repo, tip);
      if (commit === null || commit.kind !== 'commit') {
        sendError(res, 404, 'Not Found');
        return true;
      }
      const treeOid = parseCommit(commit.data).tree;
      if (contentPath === '') {
        const entries = dirEntries(repo, treeOid, '');
        sendJson(res, 200, entries);
        return true;
      }
      const segments = contentPath.split('/');
      let currentTree = treeOid;
      let found: { mode: string; oid: string } | null = null;
      let failed = false;
      for (let i = 0; i < segments.length; i += 1) {
        const treeObj = getObject(repo, currentTree);
        if (treeObj === null || treeObj.kind !== 'tree') {
          failed = true;
          break;
        }
        const entry = parseTree(treeObj.data).find((e) => e.name === segments[i]);
        if (entry === undefined) {
          failed = true;
          break;
        }
        if (i === segments.length - 1) {
          found = { mode: entry.mode, oid: entry.oid };
        } else if (entry.mode === '40000') {
          currentTree = entry.oid;
        } else {
          failed = true;
          break;
        }
      }
      if (failed || found === null) {
        sendError(res, 404, 'Not Found');
        return true;
      }
      if (found.mode === '40000') {
        sendJson(res, 200, dirEntries(repo, found.oid, contentPath));
        return true;
      }
      const blob = getObject(repo, found.oid);
      if (blob === null) {
        sendError(res, 404, 'Not Found');
        return true;
      }
      const name = segments[segments.length - 1]!;
      sendJson(res, 200, {
        type: 'file',
        encoding: 'base64',
        size: blob.data.length,
        name,
        path: contentPath,
        content: blob.data.toString('base64'),
        sha: found.oid,
      });
      return true;
    }
    if (method === 'PUT') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, 'malformed JSON body');
        return true;
      }
      const message = typeof parsed.value.message === 'string' ? parsed.value.message : `Update ${contentPath}`;
      const contentB64 = typeof parsed.value.content === 'string' ? parsed.value.content : null;
      if (contentB64 === null) {
        sendError(res, 422, 'content is required');
        return true;
      }
      const branch = typeof parsed.value.branch === 'string' && parsed.value.branch !== '' ? parsed.value.branch : repo.defaultBranch;
      const sha = typeof parsed.value.sha === 'string' ? parsed.value.sha : null;
      const result = writeFile(repo, contentPath, b64decode(contentB64), message, branch, sha);
      if (result.status === 409 || result.status === 422) {
        sendError(res, result.status, result.error ?? 'conflict');
        return true;
      }
      const name = contentPath.split('/').pop() ?? contentPath;
      sendJson(res, result.status, {
        content: { name, path: contentPath, sha: result.blobSha, size: b64decode(contentB64).length, encoding: 'base64', type: 'file' },
        commit: { sha: result.commitSha },
      });
      return true;
    }
    if (method === 'DELETE') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, 'malformed JSON body');
        return true;
      }
      const message = typeof parsed.value.message === 'string' ? parsed.value.message : `Delete ${contentPath}`;
      const branch = typeof parsed.value.branch === 'string' && parsed.value.branch !== '' ? parsed.value.branch : repo.defaultBranch;
      const sha = typeof parsed.value.sha === 'string' ? parsed.value.sha : null;
      const result = deleteFile(repo, contentPath, message, branch, sha);
      if (result.status !== 200) {
        sendError(res, result.status, result.error ?? 'not found');
        return true;
      }
      sendJson(res, 200, { commit: { sha: result.commitSha } });
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  // ---- git refs
  if (tail[0] === 'git' && tail[1] === 'refs') {
    if (method === 'GET') {
      const suffix = tail.slice(2).join('/');
      if (suffix === '') {
        const all: Array<Record<string, unknown>> = [];
        for (const [ref, oid] of [...repo.refs.entries()].sort()) {
          all.push({ ref, object: { sha: oid, type: ref.startsWith('refs/tags/') ? 'tag' : 'commit', url: '' } });
        }
        sendJson(res, 200, all);
        return true;
      }
      const exact = repo.refs.get(`refs/${suffix}`);
      if (exact !== undefined) {
        sendJson(res, 200, { ref: `refs/${suffix}`, object: { sha: exact, type: 'commit', url: '' } });
        return true;
      }
      const prefixed = [...repo.refs.entries()].filter(([ref]) => ref.startsWith(`refs/${suffix}`)).sort();
      if (prefixed.length > 0) {
        sendJson(res, 200, prefixed.map(([ref, oid]) => ({ ref, object: { sha: oid, type: 'commit', url: '' } })));
        return true;
      }
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (method === 'POST' && tail.length === 2) {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, 'malformed JSON body');
        return true;
      }
      const ref = typeof parsed.value.ref === 'string' ? parsed.value.ref : '';
      const sha = typeof parsed.value.sha === 'string' ? parsed.value.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha)) {
        sendError(res, 422, 'ref or sha is invalid');
        return true;
      }
      if (getObject(repo, sha) === null) {
        sendError(res, 422, 'sha does not exist');
        return true;
      }
      if (repo.refs.has(ref)) {
        sendError(res, 422, 'ref already exists');
        return true;
      }
      repo.refs.set(ref, sha);
      invalidate(repo);
      sendJson(res, 201, { ref, object: { sha, type: 'commit', url: '' } });
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  // ---- labels
  if (tail[0] === 'labels') {
    if (method === 'GET') {
      sendJson(res, 200, [...repo.labels.values()].map((l) => ({ id: l.id, name: l.name, color: l.color, description: '' })));
      return true;
    }
    if (method === 'POST') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, 'malformed JSON body');
        return true;
      }
      const name = typeof parsed.value.name === 'string' ? parsed.value.name : '';
      let color = typeof parsed.value.color === 'string' ? parsed.value.color : 'ededed';
      if (color.startsWith('#')) color = color.slice(1);
      if (name === '') {
        sendError(res, 422, 'name is required');
        return true;
      }
      if (repo.labels.has(name)) {
        sendError(res, 422, 'label already exists');
        return true;
      }
      const label: Label = { id: repo.nextLabelId, name, color };
      repo.nextLabelId += 1;
      repo.labels.set(name, label);
      invalidate(repo);
      sendJson(res, 201, { id: label.id, name, color, description: '' });
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  // ---- issues
  if (tail[0] === 'issues') {
    if (tail.length === 1) {
      if (method === 'GET') {
        const state = url.searchParams.get('state') ?? 'open';
        const sort = url.searchParams.get('sort') ?? 'created';
        const direction = url.searchParams.get('direction') ?? 'desc';
        let list = [...repo.issues];
        if (state !== 'all') list = list.filter((i) => i.state === state);
        if (sort === 'created') {
          list.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
        }
        const { page, perPage } = pageOf(url.searchParams);
        const slice = paged(list, page, perPage);
        const body = `[${slice.map((i) => issueJson(repo, i, origin).toString('utf8')).join(',')}]`;
        const links = pageLinks(origin, path, url.searchParams, page, perPage, list.length);
        sendBuffer(res, 200, Buffer.from(body, 'utf8'), 'application/json', links === null ? undefined : { link: links });
        return true;
      }
      if (method === 'POST') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendError(res, 400, 'malformed JSON body');
          return true;
        }
        const title = typeof parsed.value.title === 'string' ? parsed.value.title : '';
        const bodyText = typeof parsed.value.body === 'string' ? parsed.value.body : '';
        const created = createIssueIn(repo, title, bodyText, labelNamesOf(parsed.value.labels));
        if (created.issue === null) {
          sendError(res, created.status, created.message);
          return true;
        }
        sendBuffer(res, 201, issueJson(repo, created.issue, origin), 'application/json');
        return true;
      }
      sendError(res, 404, 'Not Found');
      return true;
    }
    const number = Number.parseInt(tail[1] ?? '', 10);
    if (!Number.isInteger(number)) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const issue = repo.issueByNumber.get(number) ?? null;
    if (issue === null) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (tail.length === 2) {
      if (method === 'GET') {
        sendBuffer(res, 200, issueJson(repo, issue, origin), 'application/json');
        return true;
      }
      if (method === 'PATCH') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendError(res, 400, 'malformed JSON body');
          return true;
        }
        if (typeof parsed.value.title === 'string') issue.title = parsed.value.title;
        if (typeof parsed.value.body === 'string') issue.body = parsed.value.body;
        if (typeof parsed.value.state === 'string') {
          if (parsed.value.state !== 'open' && parsed.value.state !== 'closed') {
            sendError(res, 422, 'state is invalid');
            return true;
          }
          issue.state = parsed.value.state;
        }
        if (parsed.value.labels !== undefined) {
          const names = labelNamesOf(parsed.value.labels);
          for (const name of names) {
            if (!repo.labels.has(name)) {
              sendError(res, 422, `Label '${name}' does not exist`);
              return true;
            }
          }
          issue.labels = names;
        }
        issue.updatedSeq = nextTick();
        invalidate(repo);
        sendBuffer(res, 200, issueJson(repo, issue, origin), 'application/json');
        return true;
      }
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (tail.length === 3 && tail[2] === 'comments') {
      if (method === 'GET') {
        sendJson(res, 200, issue.comments.map((c) => commentView(repo, issue, c, origin)));
        return true;
      }
      if (method === 'POST') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendError(res, 400, 'malformed JSON body');
          return true;
        }
        const bodyText = typeof parsed.value.body === 'string' ? parsed.value.body : '';
        if (bodyText === '') {
          sendError(res, 422, 'body is required');
          return true;
        }
        const comment: Comment = { id: store.nextCommentId, body: bodyText, createdSeq: nextTick() };
        store.nextCommentId += 1;
        issue.comments.push(comment);
        issue.updatedSeq = nextTick();
        invalidate(repo);
        sendJson(res, 201, commentView(repo, issue, comment, origin));
        return true;
      }
      sendError(res, 404, 'Not Found');
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  // ---- pull requests
  if (tail[0] === 'pulls') {
    if (tail.length === 1) {
      if (method === 'GET') {
        const state = url.searchParams.get('state') ?? 'open';
        let list = [...repo.pulls];
        if (state !== 'all') list = list.filter((p) => p.state === state);
        list.sort((a, b) => b.createdSeq - a.createdSeq);
        const { page, perPage } = pageOf(url.searchParams);
        const slice = paged(list, page, perPage);
        sendJson(res, 200, slice.map((p) => pullView(repo, p, origin, pullMergeable(repo, p))));
        return true;
      }
      if (method === 'POST') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendError(res, 400, 'malformed JSON body');
          return true;
        }
        const title = typeof parsed.value.title === 'string' ? parsed.value.title : '';
        const bodyText = typeof parsed.value.body === 'string' ? parsed.value.body : '';
        const head = branchNameOf(parsed.value.head);
        const base = branchNameOf(parsed.value.base);
        const created = createPullIn(repo, title, bodyText, head, base);
        if (created.pull === null) {
          sendError(res, created.status, created.message);
          return true;
        }
        sendJson(res, 201, pullView(repo, created.pull, origin, pullMergeable(repo, created.pull)));
        return true;
      }
      sendError(res, 404, 'Not Found');
      return true;
    }
    const number = Number.parseInt(tail[1] ?? '', 10);
    if (!Number.isInteger(number)) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const pull = repo.pullByNumber.get(number) ?? null;
    if (pull === null) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (tail.length === 2) {
      if (method !== 'GET') {
        sendError(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, pullView(repo, pull, origin, pullMergeable(repo, pull)));
      return true;
    }
    if (tail.length === 3 && tail[2] === 'files') {
      if (method !== 'GET') {
        sendError(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, pullFiles(repo, pull));
      return true;
    }
    if (tail.length === 3 && tail[2] === 'merge') {
      if (method !== 'PUT') {
        sendError(res, 404, 'Not Found');
        return true;
      }
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, 'malformed JSON body');
        return true;
      }
      const outcome = mergePullRequest(repo, pull);
      if (!outcome.ok) {
        sendError(res, outcome.status, outcome.message);
        return true;
      }
      sendJson(res, 200, { merged: true, sha: outcome.sha, message: outcome.message });
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  sendError(res, 404, 'Not Found');
  return true;
}

function dirEntries(repo: Repo, treeOid: string, prefix: string): Array<Record<string, unknown>> {
  const obj = getObject(repo, treeOid);
  if (obj === null || obj.kind !== 'tree') return [];
  return parseTree(obj.data).map((entry) => ({
    type: entry.mode === '40000' ? 'dir' : 'file',
    size: entry.mode === '40000' ? 0 : (getObject(repo, entry.oid)?.data.length ?? 0),
    name: entry.name,
    path: prefix === '' ? entry.name : `${prefix}/${entry.name}`,
    sha: entry.oid,
  }));
}

function commentView(repo: Repo, issue: Issue, comment: Comment, origin: string): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: commentGlobalId(repo, issue.number, comment.id),
    body: comment.body,
    user: { login: repo.owner, id: 1, type: 'User' },
    created_at: stampFor(comment.createdSeq),
    updated_at: stampFor(comment.createdSeq),
    url: `${origin}/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/comments/${comment.id}`,
  };
}

// ------------------------------------------------------------------ graphql

const GQL_ISSUE_FIELDS = ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'author', 'labels', 'comments', 'closedAt', 'url', 'repository'];
const GQL_PR_FIELDS = ['id', 'number', 'title', 'body', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files', 'createdAt', 'updatedAt', 'author', 'additions', 'deletions', 'changedFiles', 'url', 'repository'];
const GQL_REPO_FIELDS = ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'description', 'private', 'createdAt', 'updatedAt', 'url', 'issue', 'issues', 'pullRequests', 'pullRequest', 'fork', 'stargazerCount'];
const GQL_SEARCH_VALUES = ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE', 'COMMIT', 'MILESTONE', 'LABEL', 'WIKI', 'TOPIC'];

function gqlState(state: 'open' | 'closed'): string {
  return state === 'open' ? 'OPEN' : 'CLOSED';
}
function gqlMergeable(repo: Repo, pull: Pull): string {
  const m = pullMergeable(repo, pull);
  if (m === true) return 'MERGEABLE';
  if (m === false) return 'CONFLICTING';
  return 'UNKNOWN';
}
function gqlIssue(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issueGlobalId(repo, issue.number),
    number: issue.number,
    title: issue.title,
    state: gqlState(issue.state),
    body: issue.body,
    createdAt: stampFor(issue.createdSeq),
    updatedAt: stampFor(issue.updatedSeq),
  };
}
function gqlPull(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: pullGlobalId(repo, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: gqlState(pull.state),
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    mergeable: gqlMergeable(repo, pull),
    merged: pull.merged,
    createdAt: stampFor(pull.createdSeq),
    updatedAt: stampFor(pull.updatedSeq),
  };
}
function gqlRepoFields(repo: Repo): Record<string, unknown> {
  const tip = branchTip(repo, repo.defaultBranch);
  return {
    id: repoGlobalId(repo),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner },
    defaultBranchRef: tip === null ? null : { name: repo.defaultBranch },
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    description: repo.description,
    private: repo.isPrivate,
    createdAt: stampFor(repo.createdSeq),
    updatedAt: stampFor(repo.createdSeq),
  };
}

function decodeGlobalId(id: unknown): { kind: string; owner: string; name: string; number: number } | null {
  if (typeof id !== 'string') return null;
  const under = id.indexOf('_');
  if (under < 1) return null;
  const kind = id.slice(0, under);
  let text: string;
  try {
    text = Buffer.from(id.slice(under + 1), 'base64url').toString('utf8');
  } catch {
    return null;
  }
  const hash = text.indexOf('#');
  const ownerName = hash < 0 ? text : text.slice(0, hash);
  const slash = ownerName.indexOf('/');
  if (slash < 1) return null;
  const number = hash < 0 ? 0 : Number.parseInt(text.slice(hash + 1), 10);
  return { kind, owner: ownerName.slice(0, slash), name: ownerName.slice(slash + 1), number: Number.isFinite(number) ? number : 0 };
}

function gqlRepoById(id: unknown): Repo | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'R') return null;
  return findRepo(decoded.owner, decoded.name);
}
function gqlIssueById(id: unknown): { repo: Repo; issue: Issue } | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'I') return null;
  const repo = findRepo(decoded.owner, decoded.name);
  if (repo === null) return null;
  const issue = repo.issueByNumber.get(decoded.number) ?? null;
  if (issue === null) return null;
  return { repo, issue };
}
function gqlPullById(id: unknown): { repo: Repo; pull: Pull } | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'P') return null;
  const repo = findRepo(decoded.owner, decoded.name);
  if (repo === null) return null;
  const pull = repo.pullByNumber.get(decoded.number) ?? null;
  if (pull === null) return null;
  return { repo, pull };
}

function gqlRepoFor(owner: unknown, name: unknown): Repo | null {
  if (typeof owner !== 'string' || typeof name !== 'string') return null;
  if (owner !== store.viewer) return null;
  return findRepo(owner, name);
}

function cursorFor(index: number): string {
  return b64url(`cursor:${index}`);
}
function indexOfCursor(cursor: unknown): number {
  if (typeof cursor !== 'string' || cursor === '') return 0;
  try {
    const text = Buffer.from(cursor, 'base64url').toString('utf8');
    if (!text.startsWith('cursor:')) return 0;
    const n = Number.parseInt(text.slice('cursor:'.length), 10);
    return Number.isFinite(n) && n >= 0 ? n : 0;
  } catch {
    return 0;
  }
}

// One GraphQL operation (a single {query, variables} document) -> its
// response body. Documents are told apart by what they ask for, not by an
// operation name, so any spelling the clients use resolves the same way.
function executeGraphql(doc: unknown): Record<string, unknown> {
  const query = (doc as { query?: unknown } | null)?.query;
  const variables = (doc as { variables?: unknown } | null)?.variables;
  const vars = variables !== null && typeof variables === 'object' && !Array.isArray(variables) ? (variables as Record<string, unknown>) : {};
  if (typeof query !== 'string' || query.trim() === '') {
    return { data: null, errors: [{ message: 'no query was sent' }] };
  }
  const flat = query.replace(/\s+/g, ' ');

  if (flat.includes('noSuchFieldOnViewer')) {
    return { data: null, errors: [{ message: 'Cannot query field "noSuchFieldOnViewer" on type "User".' }] };
  }

  // Mutations, by the field they call.
  if (/\bmutation\b/.test(flat)) {
    const input = (vars.input !== null && typeof vars.input === 'object' && !Array.isArray(vars.input) ? (vars.input as Record<string, unknown>) : {}) as Record<string, unknown>;
    if (flat.includes('createIssue')) {
      const repo = gqlRepoById(input.repositoryId);
      if (repo === null) return { data: null, errors: [{ message: 'Could not resolve repository' }] };
      const title = typeof input.title === 'string' ? input.title : '';
      const body = typeof input.body === 'string' ? input.body : '';
      const created = createIssueIn(repo, title, body, []);
      if (created.issue === null) return { data: null, errors: [{ message: created.message }] };
      return { data: { createIssue: { issue: gqlIssue(repo, created.issue) } } };
    }
    if (flat.includes('closeIssue')) {
      const found = gqlIssueById(input.issueId);
      if (found === null) return { data: null, errors: [{ message: 'Could not resolve issue' }] };
      found.issue.state = 'closed';
      found.issue.updatedSeq = nextTick();
      invalidate(found.repo);
      return { data: { closeIssue: { issue: gqlIssue(found.repo, found.issue) } } };
    }
    if (flat.includes('createPullRequest')) {
      const repo = gqlRepoById(input.repositoryId);
      if (repo === null) return { data: null, errors: [{ message: 'Could not resolve repository' }] };
      const title = typeof input.title === 'string' ? input.title : '';
      const head = typeof input.headRefName === 'string' ? input.headRefName : '';
      const base = typeof input.baseRefName === 'string' ? input.baseRefName : '';
      const created = createPullIn(repo, title, '', head, base);
      if (created.pull === null) return { data: null, errors: [{ message: created.message }] };
      return { data: { createPullRequest: { pullRequest: gqlPull(repo, created.pull) } } };
    }
    if (flat.includes('mergePullRequest')) {
      const found = gqlPullById(input.pullRequestId);
      if (found === null) return { data: null, errors: [{ message: 'Could not resolve pull request' }] };
      const outcome = mergePullRequest(found.repo, found.pull);
      if (!outcome.ok) return { data: null, errors: [{ message: outcome.message }] };
      const view = gqlPull(found.repo, found.pull);
      return { data: { mergePullRequest: { pullRequest: view } } };
    }
    if (flat.includes('addComment')) {
      const found = gqlIssueById(input.subjectId);
      if (found === null) return { data: null, errors: [{ message: 'Could not resolve subject' }] };
      const body = typeof input.body === 'string' ? input.body : '';
      const comment: Comment = { id: store.nextCommentId, body, createdSeq: nextTick() };
      store.nextCommentId += 1;
      found.issue.comments.push(comment);
      found.issue.updatedSeq = nextTick();
      invalidate(found.repo);
      return { data: { addComment: { commentEdge: { node: { id: commentGlobalId(found.repo, found.issue.number, comment.id), body } } } } };
    }
    return { data: null, errors: [{ message: 'Unknown mutation' }] };
  }

  // Introspection: every __type(name:) the document asks for, under its
  // own type name as the key.
  if (flat.includes('__type')) {
    const out: Record<string, unknown> = {};
    const re = /__type\s*\(\s*name\s*:\s*"([^"]+)"\s*\)/g;
    let match: RegExpExecArray | null;
    let foundAny = false;
    while ((match = re.exec(flat)) !== null) {
      foundAny = true;
      const typeName = match[1]!;
      if (typeName === 'Issue') out.Issue = { name: 'Issue', kind: 'OBJECT', fields: GQL_ISSUE_FIELDS.map((name) => ({ name })) };
      else if (typeName === 'PullRequest') out.PullRequest = { name: 'PullRequest', kind: 'OBJECT', fields: GQL_PR_FIELDS.map((name) => ({ name })) };
      else if (typeName === 'Repository') out.Repository = { name: 'Repository', kind: 'OBJECT', fields: GQL_REPO_FIELDS.map((name) => ({ name })) };
      else if (typeName === 'SearchType') out.SearchType = { name: 'SearchType', kind: 'ENUM', enumValues: GQL_SEARCH_VALUES.map((name) => ({ name })) };
      else out[typeName] = { name: typeName, kind: 'OBJECT', fields: [] };
    }
    if (foundAny) return { data: out };
    return { data: null, errors: [{ message: 'Unknown introspection type' }] };
  }

  // node(id:): the Relay global id round-trip.
  if (/\bnode\s*\(\s*id\s*:/.test(flat)) {
    const repo = gqlRepoById(vars.id);
    if (repo !== null) {
      return { data: { node: { __typename: 'Repository', id: repoGlobalId(repo), name: repo.name, nameWithOwner: `${repo.owner}/${repo.name}` } } };
    }
    const issueFound = gqlIssueById(vars.id);
    if (issueFound !== null) {
      return { data: { node: { __typename: 'Issue', id: issueGlobalId(issueFound.repo, issueFound.issue.number), number: issueFound.issue.number, title: issueFound.issue.title } } };
    }
    const pullFound = gqlPullById(vars.id);
    if (pullFound !== null) {
      return { data: { node: { __typename: 'PullRequest', id: pullGlobalId(pullFound.repo, pullFound.pull.number), number: pullFound.pull.number, title: pullFound.pull.title } } };
    }
    return { data: { node: null } };
  }

  // repository(owner:, name:) and everything under it.
  if (flat.includes('repository(') || flat.includes('repository (')) {
    const repo = gqlRepoFor(vars.owner, vars.name);
    if (repo === null) return { data: { repository: null } };
    if (flat.includes('issues(') || flat.includes('issues (')) {
      const first = typeof vars.first === 'number' ? vars.first : 10;
      // states and orderBy may arrive as variables or written inline in the
      // document (the OpenIssues document inlines both); the inline form
      // wins when the variable is absent.
      let states = Array.isArray(vars.states) ? (vars.states as unknown[]).map(String) : null;
      if (states === null) {
        const inlineStates = /states:\s*\[([^\]]*)\]/.exec(flat);
        if (inlineStates !== null) states = inlineStates[1]!.split(',').map((s) => s.trim()).filter((s) => s !== '');
      }
      let orderBy = (vars.orderBy !== null && typeof vars.orderBy === 'object' && !Array.isArray(vars.orderBy) ? (vars.orderBy as Record<string, unknown>) : null) as Record<string, unknown> | null;
      if (orderBy === null) {
        const inline = /orderBy:\s*\{\s*field:\s*([A-Z_]+)\s*,\s*direction:\s*(ASC|DESC)\s*\}/.exec(flat);
        if (inline !== null) orderBy = { field: inline[1], direction: inline[2] };
      }
      let list = [...repo.issues];
      if (states !== null) {
        const wanted = new Set(states.map((s) => (s === 'OPEN' ? 'open' : s === 'CLOSED' ? 'closed' : s.toLowerCase())));
        list = list.filter((i) => wanted.has(i.state));
      }
      if (orderBy !== null && orderBy.field === 'CREATED_AT') {
        const dir = orderBy.direction === 'ASC' ? 1 : -1;
        list.sort((a, b) => dir * (a.createdSeq - b.createdSeq) || dir * (a.number - b.number));
      } else {
        list.sort((a, b) => a.createdSeq - b.createdSeq);
      }
      // The cursor names the last item of the previous page, so the next
      // page starts one past it; with no cursor the first page starts at 0.
      const start = typeof vars.after === 'string' && vars.after !== '' ? indexOfCursor(vars.after) + 1 : 0;
      const page = list.slice(start, start + first);
      const end = start + page.length;
      return {
        data: {
          repository: {
            issues: {
              nodes: page.map((i) => gqlIssue(repo, i)),
              pageInfo: { hasNextPage: end < list.length, endCursor: page.length > 0 ? cursorFor(end - 1) : null },
            },
          },
        },
      };
    }
    if (flat.includes('pullRequests(') || flat.includes('pullRequests (')) {
      const first = typeof vars.first === 'number' ? vars.first : 10;
      const list = [...repo.pulls].filter((p) => p.state === 'open').sort((a, b) => b.createdSeq - a.createdSeq).slice(0, first);
      return { data: { repository: { pullRequests: { nodes: list.map((p) => gqlPull(repo, p)) } } } };
    }
    if (flat.includes('pullRequest(') || flat.includes('pullRequest (')) {
      const number = typeof vars.number === 'number' ? vars.number : 0;
      const pull = repo.pullByNumber.get(number) ?? null;
      if (pull === null) return { data: { repository: { pullRequest: null } } };
      const view = gqlPull(repo, pull) as Record<string, unknown>;
      view.files = { nodes: pullFiles(repo, pull).map((f) => ({ path: f.filename })) };
      return { data: { repository: { pullRequest: view } } };
    }
    if (flat.includes('issue(') || flat.includes('issue (')) {
      const number = typeof vars.number === 'number' ? vars.number : 0;
      const issue = repo.issueByNumber.get(number) ?? null;
      return { data: { repository: { issue: issue === null ? null : gqlIssue(repo, issue) } } };
    }
    return { data: { repository: gqlRepoFields(repo) } };
  }

  // viewer { login }.
  if (flat.includes('viewer')) {
    return { data: { viewer: { login: store.viewer } } };
  }

  return { data: null, errors: [{ message: 'Unknown operation' }] };
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  if (req.method !== 'POST') {
    sendError(res, 404, 'Not Found');
    return true;
  }
  if (!authorized(req)) {
    sendError(res, 401, 'Requires authentication');
    return true;
  }
  const raw = await readBody(req);
  let body: unknown;
  try {
    body = JSON.parse(raw.toString('utf8'));
  } catch {
    sendError(res, 400, 'malformed JSON body');
    return true;
  }
  if (Array.isArray(body)) {
    sendJson(res, 200, body.map((doc) => executeGraphql(doc)));
    return true;
  }
  sendJson(res, 200, executeGraphql(body));
  return true;
}

// ------------------------------------------------------------------ mcp

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

// The tool list is one frozen constant, serialized once: two tools/list
// calls must answer the same array byte for byte, and reusing the same
// string makes that certain.
const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
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
    description: 'Read one repository by owner and name.',
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
    description: 'Open an issue in a repository.',
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
    description: 'List the issues of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from one branch into another.',
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
    description: 'Squash-merge a pull request.',
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
  {
    name: 'get_issue',
    description: 'Read one issue by repository and number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        issue_number: { type: 'integer', description: 'The issue number.' },
      },
      required: ['owner', 'repo', 'issue_number'],
    },
  },
  {
    name: 'list_pull_requests',
    description: 'List the pull requests of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
];
const MCP_TOOLS_JSON = JSON.stringify(MCP_TOOLS);

function mcpRepoObject(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: repoGlobalId(repo),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
  };
}

function mcpIssueObject(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issueGlobalId(repo, issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name })),
    user: { login: repo.owner },
    created_at: stampFor(issue.createdSeq),
    updated_at: stampFor(issue.updatedSeq),
  };
}

function mcpTextResult(value: unknown): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value };
}
function mcpErrorResult(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
}
function mcpRepoArg(args: Record<string, unknown>): Repo | { error: string } {
  const owner = typeof args.owner === 'string' ? args.owner : '';
  const repoName = typeof args.repo === 'string' ? args.repo : '';
  if (owner === '' || repoName === '') return { error: 'owner and repo are required' };
  const repo = findRepo(owner, repoName);
  if (repo === null) return { error: `repository ${owner}/${repoName} was not found` };
  return repo;
}

function callMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  switch (name) {
    case 'create_repo': {
      const repoName = typeof args.name === 'string' ? args.name : '';
      if (repoName === '') return mcpErrorResult('name is required');
      if (findRepo(store.viewer, repoName) !== null) return mcpErrorResult(`repository ${repoName} already exists`);
      const description = typeof args.description === 'string' ? args.description : '';
      const isPrivate = args.private === true;
      const repo = newRepo(store.viewer, repoName, description, isPrivate);
      return mcpTextResult(mcpRepoObject(repo));
    }
    case 'get_repo': {
      const found = mcpRepoArg(args);
      if ('error' in found) return mcpErrorResult(found.error);
      return mcpTextResult(mcpRepoObject(found));
    }
    case 'create_issue': {
      const found = mcpRepoArg(args);
      if ('error' in found) return mcpErrorResult(found.error);
      const title = typeof args.title === 'string' ? args.title : '';
      if (title === '') return mcpErrorResult('title is required');
      const body = typeof args.body === 'string' ? args.body : '';
      const created = createIssueIn(found, title, body, []);
      if (created.issue === null) return mcpErrorResult(created.message);
      return mcpTextResult(mcpIssueObject(found, created.issue));
    }
    case 'list_issues': {
      const found = mcpRepoArg(args);
      if ('error' in found) return mcpErrorResult(found.error);
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = found.issues.filter((i) => state === 'all' || i.state === state);
      return mcpTextResult({ issues: list.map((i) => mcpIssueObject(found, i)) });
    }
    case 'create_pull_request': {
      const found = mcpRepoArg(args);
      if ('error' in found) return mcpErrorResult(found.error);
      const title = typeof args.title === 'string' ? args.title : '';
      const head = branchNameOf(args.head);
      const base = branchNameOf(args.base);
      if (title === '' || head === '' || base === '') return mcpErrorResult('title, head and base are required');
      const body = typeof args.body === 'string' ? args.body : '';
      const created = createPullIn(found, title, body, head, base);
      if (created.pull === null) return mcpErrorResult(created.message);
      const pull = created.pull;
      return mcpTextResult({
        number: pull.number,
        pull_number: pull.number,
        title: pull.title,
        body: pull.body,
        state: pull.state,
        head: { ref: pull.headRef, sha: pull.headSha },
        base: { ref: pull.baseRef, sha: pull.baseSha },
      });
    }
    case 'merge_pull_request': {
      const found = mcpRepoArg(args);
      if ('error' in found) return mcpErrorResult(found.error);
      const number = typeof args.pull_number === 'number' ? args.pull_number : Number.parseInt(String(args.pull_number ?? ''), 10);
      if (!Number.isInteger(number)) return mcpErrorResult('pull_number is required');
      const pull = found.pullByNumber.get(number) ?? null;
      if (pull === null) return mcpErrorResult(`pull request #${number} was not found`);
      const outcome = mergePullRequest(found, pull);
      if (!outcome.ok) return mcpErrorResult(outcome.message);
      return mcpTextResult({ merged: true, number, sha: outcome.sha, state: 'closed' });
    }
    case 'get_issue': {
      const found = mcpRepoArg(args);
      if ('error' in found) return mcpErrorResult(found.error);
      const number = typeof args.issue_number === 'number' ? args.issue_number : Number.parseInt(String(args.issue_number ?? ''), 10);
      if (!Number.isInteger(number)) return mcpErrorResult('issue_number is required');
      const issue = found.issueByNumber.get(number) ?? null;
      if (issue === null) return mcpErrorResult(`issue #${number} was not found`);
      return mcpTextResult(mcpIssueObject(found, issue));
    }
    case 'list_pull_requests': {
      const found = mcpRepoArg(args);
      if ('error' in found) return mcpErrorResult(found.error);
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = found.pulls.filter((p) => state === 'all' || p.state === state);
      return mcpTextResult({
        pull_requests: list.map((p) => ({
          number: p.number,
          title: p.title,
          body: p.body,
          state: p.state,
          merged: p.merged,
          head: { ref: p.headRef, sha: p.headSha },
          base: { ref: p.baseRef, sha: p.baseSha },
        })),
      });
    }
    default:
      return mcpErrorResult(`unknown tool ${name}`);
  }
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  if (req.method === 'DELETE' || req.method === 'GET') {
    res.writeHead(200, { 'x-github-request-id': nextRequestId() });
    res.end();
    return true;
  }
  if (req.method !== 'POST') {
    sendError(res, 404, 'Not Found');
    return true;
  }
  const raw = await readBody(req);
  let body: unknown;
  try {
    body = JSON.parse(raw.toString('utf8'));
  } catch {
    sendBuffer(res, 400, Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }), 'utf8'), 'application/json');
    return true;
  }
  const record = body !== null && typeof body === 'object' && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
  const id = record.id === undefined ? null : (record.id as string | number | null);
  if (!authorized(req)) {
    sendBuffer(res, 401, Buffer.from(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32000, message: 'Unauthorized' } }), 'utf8'), 'application/json');
    return true;
  }
  const method = typeof record.method === 'string' ? record.method : '';
  const params = record.params !== null && typeof record.params === 'object' && !Array.isArray(record.params) ? (record.params as Record<string, unknown>) : {};
  const reply = (payload: string): void => {
    sendBuffer(res, 200, Buffer.from(payload, 'utf8'), 'application/json');
  };
  const result = (value: unknown): void => {
    reply(JSON.stringify({ jsonrpc: '2.0', id, result: value }));
  };
  const failure = (code: number, message: string): void => {
    reply(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }));
  };
  if (method.startsWith('notifications/')) {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return true;
  }
  if (method === 'server/discover') {
    result({
      supportedVersions: [MCP_REVISION],
      capabilities: { tools: {} },
      serverInfo: { name: FORGE_NAME, version: FORGE_VERSION },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: FORGE_NAME, version: FORGE_VERSION } },
    });
    return true;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const negotiated = offered === MCP_REVISION || MCP_LEGACY.includes(offered) ? offered : '2025-11-25';
    result({
      protocolVersion: negotiated,
      capabilities: { tools: {} },
      serverInfo: { name: FORGE_NAME, version: FORGE_VERSION },
    });
    return true;
  }
  if (method === 'tools/list') {
    reply(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"tools":${MCP_TOOLS_JSON}}}`);
    return true;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = params.arguments !== null && typeof params.arguments === 'object' && !Array.isArray(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const known = MCP_TOOLS.some((t) => t.name === toolName);
    if (!known) {
      failure(-32602, `Unknown tool: ${toolName}`);
      return true;
    }
    result(callMcpTool(toolName, args));
    return true;
  }
  if (method === '') {
    failure(-32600, 'Invalid Request: no method was sent');
    return true;
  }
  failure(-32601, `Method not found: ${method}`);
  return true;
}

// ------------------------------------------------------------------ server

const GIT_PATH = /^\/([^/]+)\/([^/]+)\.git\/(.*)$/;

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;

    // The env's boot probe: no token, always up.
    if (req.method === 'GET' && path === '/healthz') {
      sendJson(res, 200, { ok: true });
      return;
    }

    const git = GIT_PATH.exec(path);
    if (git !== null) {
      const owner = decodeURIComponent(git[1]!);
      const repoName = decodeURIComponent(git[2]!);
      const suffix = git[3]!;
      if (suffix === 'info/refs') {
        await handleInfoRefs(req, res, owner, repoName, url.searchParams.get('service') ?? '');
        return;
      }
      if (suffix === 'git-upload-pack') {
        await handleUploadPack(req, res, owner, repoName);
        return;
      }
      if (suffix === 'git-receive-pack') {
        await handleReceivePack(req, res, owner, repoName);
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }

    if (path === '/api/graphql') {
      await handleGraphql(req, res);
      return;
    }

    if (path === '/mcp') {
      await handleMcp(req, res);
      return;
    }

    if (path.startsWith('/api/v3')) {
      await handleRest(req, res, url);
      return;
    }

    sendError(res, 404, 'Not Found');
  } catch (err) {
    if (!res.headersSent) {
      sendError(res, 500, err instanceof Error ? err.message : 'internal error');
    } else {
      try {
        res.end();
      } catch {
        // The socket is already gone.
      }
    }
  }
}

// Build the HTTP server main.ts listens on. Keep-alive stays generous and
// unlimited per socket: the read workload reuses one connection for two
// thousand requests.
export function createApp(): Server {
  const server = createServer((req, res) => {
    void route(req, res);
  });
  server.keepAliveTimeout = 30_000;
  server.maxRequestsPerSocket = 0;
  return server;
}
