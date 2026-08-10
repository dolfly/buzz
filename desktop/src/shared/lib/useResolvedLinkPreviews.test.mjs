import assert from "node:assert/strict";
import test from "node:test";

import {
  __linkPreviewMetadataTest,
  fetchBuzzEntityMetadata,
  isBuzzEntityPreview,
  resolveLinkPreview,
  withEntityFallbacks,
} from "./useResolvedLinkPreviews.ts";

const preview = {
  kind: "generic-link",
  href: "https://example.com/story",
  provider: "example.com",
  title: "example.com/story",
  typeLabel: "link",
};

function metadata(overrides = {}) {
  return {
    title: "A story",
    siteName: "Example",
    description: "Story description",
    imageDataUrl: null,
    imageDomain: null,
    imageFetchState: "none",
    imageRetryAfterMs: null,
    ...overrides,
  };
}

test("pending external metadata reserves the image treatment", () => {
  assert.deepEqual(resolveLinkPreview(preview, undefined), {
    ...preview,
    imageState: "pending",
  });
});

test("pending Buzz entity metadata remains image-less", () => {
  const entityPreview = {
    kind: "buzz-repository",
    href: `buzz://repo?owner=${"cd".repeat(32)}&d=buzz`,
    provider: "Buzz",
    title: "buzz",
    typeLabel: "repo",
  };
  assert.deepEqual(resolveLinkPreview(entityPreview, undefined), {
    ...entityPreview,
    imageState: "none",
  });
});

test("resolved image metadata keeps the reserved image treatment", () => {
  const resolved = resolveLinkPreview(preview, {
    title: "A story",
    siteName: "Example",
    imageDataUrl: "data:image/jpeg;base64,abc",
    imageDomain: "cdn.example.com",
  });

  assert.equal(resolved.imageState, "image");
  assert.equal(resolved.provider, "Example");
  assert.equal(resolved.imageDomain, "cdn.example.com");
});

test("resolved metadata without a complete image collapses to the compact treatment", () => {
  const resolved = resolveLinkPreview(preview, {
    title: "A story",
    siteName: "Example",
    imageDataUrl: null,
    imageDomain: null,
  });

  assert.equal(resolved.imageState, "none");
  assert.equal(resolved.imageDataUrl, null);
  assert.equal(resolved.imageDomain, null);
});

test("transient and rejected image fetches use the stable fallback treatment", () => {
  const transient = resolveLinkPreview(
    preview,
    metadata({
      imageFetchState: "transient_failure",
      imageRetryAfterMs: 900_000,
    }),
  );
  const rejected = resolveLinkPreview(
    preview,
    metadata({ imageFetchState: "rejected" }),
  );

  assert.equal(transient.imageState, "fallback");
  assert.equal(rejected.imageState, "fallback");
});

test("metadata cache keys deduplicate URL fragments", () => {
  assert.equal(
    __linkPreviewMetadataTest.metadataCacheKey(
      "https://github.com/block/buzz/pull/3834#issuecomment-1",
    ),
    "https://github.com/block/buzz/pull/3834",
  );
});

test("transient metadata expires at the server retry boundary", () => {
  assert.equal(
    __linkPreviewMetadataTest.metadataExpiry(
      metadata({
        imageFetchState: "transient_failure",
        imageRetryAfterMs: 900_000,
      }),
      1_000,
    ),
    901_000,
  );
});

test("metadata loader retries transient images after the server cooldown", async () => {
  let now = 1_000;
  let calls = 0;
  const loader = __linkPreviewMetadataTest.createMetadataLoader({
    fetcher: async () => {
      calls += 1;
      return calls === 1
        ? metadata({
            imageFetchState: "transient_failure",
            imageRetryAfterMs: 10_000,
          })
        : metadata({
            imageDataUrl: "data:image/jpeg;base64,abc",
            imageDomain: "images.example.com",
            imageFetchState: "image",
          });
    },
    now: () => now,
  });

  assert.equal(
    (await loader.load(preview.href)).metadata?.imageFetchState,
    "transient_failure",
  );
  assert.equal(calls, 1);

  now += 10_000;
  assert.equal(
    (await loader.load(preview.href)).metadata?.imageFetchState,
    "image",
  );
  assert.equal(calls, 2);
});

test("metadata loader retries rejected requests after the negative-cache TTL", async () => {
  let now = 1_000;
  let calls = 0;
  const loader = __linkPreviewMetadataTest.createMetadataLoader({
    fetcher: async () => {
      calls += 1;
      if (calls === 1) throw new Error("temporary failure");
      return metadata();
    },
    now: () => now,
  });

  assert.equal((await loader.load(preview.href)).metadata, null);
  assert.equal((await loader.load(preview.href)).metadata, null);
  assert.equal(calls, 1);

  now += 5 * 60_000;
  assert.deepEqual((await loader.load(preview.href)).metadata, metadata());
  assert.equal(calls, 2);
});

test("metadata loader coalesces fragment variants and bounds concurrency", async () => {
  let active = 0;
  let maxActive = 0;
  let calls = 0;
  const loader = __linkPreviewMetadataTest.createMetadataLoader({
    concurrency: 2,
    fetcher: async () => {
      calls += 1;
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setImmediate(resolve));
      active -= 1;
      return metadata();
    },
  });

  await Promise.all([
    loader.load("https://example.com/one#first"),
    loader.load("https://example.com/one#second"),
    loader.load("https://example.com/two"),
    loader.load("https://example.com/three"),
  ]);

  assert.equal(calls, 3);
  assert.equal(maxActive, 2);
});

test("withEntityFallbacks re-adds previews dropped by null metadata", () => {
  const entityPreview = {
    kind: "buzz-pull-request",
    href: `buzz://pr?id=${"ab".repeat(32)}&owner=${"cd".repeat(32)}&d=buzz`,
    provider: "Buzz",
    title: `buzz #${"ab".repeat(4)}`,
    typeLabel: "PR",
  };

  assert.deepEqual(withEntityFallbacks([entityPreview], []), [
    { ...entityPreview, imageState: "none" },
  ]);
});

test("withEntityFallbacks keeps resolved previews and preserves order", () => {
  const first = {
    kind: "buzz-repository",
    href: `buzz://repo?owner=${"cd".repeat(32)}&d=buzz`,
    provider: "Buzz",
    title: "buzz",
    typeLabel: "repo",
  };
  const second = {
    kind: "buzz-issue",
    href: `buzz://issue?id=${"ef".repeat(32)}&owner=${"cd".repeat(32)}&d=buzz`,
    provider: "Buzz",
    title: `buzz #${"ef".repeat(4)}`,
    typeLabel: "issue",
  };
  const resolvedSecond = {
    ...second,
    title: "Fix the preview cards",
    imageState: "none",
  };

  assert.deepEqual(withEntityFallbacks([first, second], [resolvedSecond]), [
    { ...first, imageState: "none" },
    resolvedSecond,
  ]);
});

test("entity fallback eligibility is kind-scoped", () => {
  assert.equal(
    isBuzzEntityPreview({
      ...preview,
      kind: "buzz-repository",
      href: `buzz://repo?owner=${"cd".repeat(32)}&d=buzz`,
    }),
    true,
  );
  assert.equal(
    isBuzzEntityPreview({ ...preview, href: "buzz://future?id=example" }),
    false,
  );
});

test("withEntityFallbacks still drops unresolved external links", () => {
  assert.deepEqual(withEntityFallbacks([preview], []), []);
  assert.deepEqual(
    withEntityFallbacks([{ ...preview, href: "buzz://future?id=example" }], []),
    [],
  );
});

function relayEvent({
  id,
  kind,
  pubkey,
  content = "",
  tags = [],
  createdAt = 1,
}) {
  return { id, kind, pubkey, created_at: createdAt, content, tags, sig: "" };
}

test("Buzz PR metadata includes repository identity and trusted root context", async () => {
  const owner = "cd".repeat(32);
  const attacker = "ef".repeat(32);
  const id = "ab".repeat(32);
  const repoAddress = `30617:${owner}:buzz`;
  const commit = "1234567".padEnd(40, "0");
  const events = [
    relayEvent({
      id: "01".repeat(32),
      kind: 30617,
      pubkey: owner,
      tags: [
        ["d", "buzz"],
        ["name", "Buzz Desktop"],
        ["default-branch", "main"],
      ],
    }),
    relayEvent({
      id,
      kind: 1618,
      pubkey: owner,
      content: "Body",
      tags: [
        ["a", repoAddress],
        ["subject", "Restore entity cards"],
        ["branch-name", "fix/cards"],
        ["target-branch", "release"],
        ["c", commit],
      ],
    }),
    relayEvent({
      id: "02".repeat(32),
      kind: 1633,
      pubkey: attacker,
      createdAt: 20,
      tags: [["e", id]],
    }),
    relayEvent({
      id: "03".repeat(32),
      kind: 1630,
      pubkey: owner,
      createdAt: 10,
      tags: [["e", id]],
    }),
    ...Array.from({ length: 25 }, (_, index) =>
      relayEvent({
        id: index.toString(16).padStart(64, "0"),
        kind: 1633,
        pubkey: owner,
        createdAt: 100 + index,
        tags: [["e", index.toString(16).padStart(64, "f")]],
      }),
    ),
  ];
  const fetchEvents = async (filter) =>
    events
      .filter(
        (event) =>
          (!filter.kinds || filter.kinds.includes(event.kind)) &&
          (!filter.ids || filter.ids.includes(event.id)) &&
          (!filter.authors || filter.authors.includes(event.pubkey)) &&
          (!filter["#d"] ||
            event.tags.some(
              (tag) => tag[0] === "d" && filter["#d"].includes(tag[1]),
            )) &&
          (!filter["#a"] ||
            event.tags.some(
              (tag) => tag[0] === "a" && filter["#a"].includes(tag[1]),
            )) &&
          (!filter["#e"] ||
            event.tags.some(
              (tag) => tag[0] === "e" && filter["#e"].includes(tag[1]),
            )),
      )
      .sort((left, right) => right.created_at - left.created_at)
      .slice(0, filter.limit);

  const result = await fetchBuzzEntityMetadata(
    `buzz://pr?id=${id}&owner=${owner}&d=buzz`,
    fetchEvents,
  );
  assert.equal(result?.siteName, "Buzz Desktop");
  assert.equal(result?.title, "Restore entity cards");
  assert.equal(result?.description, "Open · fix/cards → release · 1234567");
  assert.equal(result?.faviconDataUrl, null);
  assert.equal(result?.imageDataUrl, null);
});

test("Buzz entity roots reject ambiguous repository tags", async () => {
  const owner = "cd".repeat(32);
  const attacker = "ef".repeat(32);
  const targetAddress = `30617:${owner}:buzz`;
  const attackerAddress = `30617:${attacker}:other`;
  const repository = relayEvent({
    id: "01".repeat(32),
    kind: 30617,
    pubkey: owner,
    tags: [
      ["d", "buzz"],
      ["name", "Buzz Desktop"],
      ["default-branch", "main"],
    ],
  });

  for (const [type, kind] of [
    ["pr", 1618],
    ["issue", 1621],
  ]) {
    const id = (type === "pr" ? "ab" : "bc").repeat(32);
    const root = relayEvent({
      id,
      kind,
      pubkey: attacker,
      tags: [
        ["a", attackerAddress],
        ["a", targetAddress],
        ["subject", "Misbound entity"],
      ],
    });
    const result = await fetchBuzzEntityMetadata(
      `buzz://${type}?id=${id}&owner=${owner}&d=buzz`,
      async (filter) =>
        filter.kinds?.includes(30617)
          ? [repository]
          : filter.ids?.includes(id)
            ? [root]
            : [],
    );
    assert.equal(result, null, `${type} with multiple repository tags`);
  }
});

test("Buzz repository metadata stays image-less and exposes default branch", async () => {
  const owner = "cd".repeat(32);
  const result = await fetchBuzzEntityMetadata(
    `buzz://repo?owner=${owner}&d=relay-tools`,
    async () => [
      relayEvent({
        id: "01".repeat(32),
        kind: 30617,
        pubkey: owner,
        content: "Fallback description",
        tags: [
          ["d", "relay-tools"],
          ["name", "Relay Tools"],
          ["description", "Operator tooling for relays"],
          ["status", "active"],
          ["default-branch", "trunk"],
        ],
      }),
    ],
  );
  assert.equal(result?.siteName, "Relay Tools");
  assert.equal(result?.title, "Operator tooling for relays");
  assert.equal(result?.description, "active · default: trunk");
  assert.equal(result?.faviconDataUrl, null);
  assert.equal(result?.imageDataUrl, null);
  assert.equal(result?.imageDomain, null);
});

test("invalidateNegative drops a cached null miss so the next load refetches", async () => {
  // A URL freshly entering the composer clears a stale hard miss (null) so it
  // refetches, instead of riding the cached blank.
  const now = 1_000;
  let calls = 0;
  let nextResult = null;
  const loader = __linkPreviewMetadataTest.createMetadataLoader({
    fetcher: async () => {
      calls += 1;
      return nextResult;
    },
    now: () => now,
  });

  assert.equal((await loader.load(preview.href)).metadata, null);
  assert.equal(calls, 1);

  loader.invalidateNegative(preview.href);
  nextResult = metadata();
  assert.deepEqual((await loader.load(preview.href)).metadata, metadata());
  assert.equal(calls, 2);
});

test("invalidateNegative drops a cached transient failure so the next load refetches", async () => {
  // A transient image failure is a NEGATIVE by contract (option docs + the
  // loader's own retry boundary), so re-entering the composer must refetch it
  // — not reuse the cached transient entry. Regression for the leak where
  // invalidateNegative only cleared hard `null` misses. (PR #5510)
  const now = 1_000;
  let calls = 0;
  const loader = __linkPreviewMetadataTest.createMetadataLoader({
    fetcher: async () => {
      calls += 1;
      return calls === 1
        ? metadata({
            imageFetchState: "transient_failure",
            imageRetryAfterMs: 10_000,
          })
        : metadata({
            imageDataUrl: "data:image/jpeg;base64,abc",
            imageDomain: "images.example.com",
            imageFetchState: "image",
          });
    },
    now: () => now,
  });

  assert.equal(
    (await loader.load(preview.href)).metadata?.imageFetchState,
    "transient_failure",
  );
  assert.equal(calls, 1);

  // Bust well before the retry boundary (now is frozen); the cache-bust — not
  // the cooldown — is what forces the refetch.
  loader.invalidateNegative(preview.href);
  assert.equal(
    (await loader.load(preview.href)).metadata?.imageFetchState,
    "image",
  );
  assert.equal(calls, 2);
});

test("invalidateNegative leaves a healthy cached hit untouched", async () => {
  // A settled positive (instant card, no redundant fetch) must survive a bust
  // so passive scroll re-renders keep riding the cache.
  const now = 1_000;
  let calls = 0;
  const loader = __linkPreviewMetadataTest.createMetadataLoader({
    fetcher: async () => {
      calls += 1;
      return metadata();
    },
    now: () => now,
  });

  assert.deepEqual((await loader.load(preview.href)).metadata, metadata());
  assert.equal(calls, 1);

  loader.invalidateNegative(preview.href);
  assert.deepEqual((await loader.load(preview.href)).metadata, metadata());
  assert.equal(calls, 1);
});

test("invalidateNegative leaves an in-flight fetch untouched", async () => {
  // A fetch still in flight is cached as a Promise, not a resolved entry.
  // Busting mid-flight must not cancel or duplicate it: the pending load
  // resolves normally and no second fetch is started.
  const now = 1_000;
  let calls = 0;
  let releaseFetch;
  const loader = __linkPreviewMetadataTest.createMetadataLoader({
    fetcher: () => {
      calls += 1;
      return new Promise((resolve) => {
        releaseFetch = () => resolve(metadata());
      });
    },
    now: () => now,
  });

  const pending = loader.load(preview.href);
  assert.equal(calls, 1);

  // Bust while the fetch is still in flight — the Promise entry is left alone.
  loader.invalidateNegative(preview.href);
  assert.equal(calls, 1, "no redundant fetch started by the bust");

  releaseFetch();
  assert.deepEqual((await pending).metadata, metadata());
  assert.equal(calls, 1, "the original in-flight fetch resolved, not a retry");
});
