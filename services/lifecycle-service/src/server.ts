import Fastify, { type FastifyInstance } from "fastify";
import { z } from "zod";
import { registerHealth, registerMetrics, domainMetrics, recordOutcome } from "@vellar/service-kit";
import { buildCleanupSteps, buildMergeStep } from "./builder";
import type { AccountReader } from "./horizon";
import { buildCleanupPlan, isClassicAccountId } from "./planner";
import { paymentMiddleware, x402ResourceServer } from "@x402/fastify";
import { ExactStellarScheme } from "@x402/stellar/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { bazaarResourceServerExtension, declareDiscoveryExtension } from "@x402/extensions/bazaar";


// Lifecycle API (idea.md §11): inspect + plan. Execute/merge land with the
// signing-flow decision (see BUILD-PLAN — docs are ambiguous on who signs
// classic-account cleanup transactions in a passkey wallet).

const inspectBodySchema = z.object({
  accountId: z.string().min(1),
});

const planBodySchema = z.object({
  accountId: z.string().min(1),
  destination: z.string().min(1),
});

export interface LifecycleServiceDeps {
  reader: AccountReader;
  networkPassphrase?: string;
}

const TESTNET_PASSPHRASE = "Test SDF Network ; September 2015";

function validatePair(accountId: string, destination: string): string | undefined {
  if (!isClassicAccountId(accountId)) return "not_classic_account";
  if (!isClassicAccountId(destination)) return "invalid_destination";
  if (destination === accountId) return "invalid_destination";
  return undefined;
}

export function buildServer(deps: LifecycleServiceDeps): FastifyInstance {
  const app = Fastify({ logger: true });
  registerHealth(app, "lifecycle-service");
  registerMetrics(app, "lifecycle-service");

  app.post("/lifecycle/inspect", async (request, reply) => {
    const parsed = inspectBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_body", details: parsed.error.issues });
    }
    const { accountId } = parsed.data;
    if (!isClassicAccountId(accountId)) {
      return reply.code(400).send({
        error: "not_classic_account",
        message: "Cleanup applies to classic (G...) accounts; smart wallets cannot be merged",
      });
    }

    const account = await deps.reader.getAccount(accountId);
    if (!account) return reply.code(404).send({ error: "account_not_found" });
    return reply.send({ account });
  });

  app.post("/lifecycle/plan", async (request, reply) => {
    const parsed = planBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_body", details: parsed.error.issues });
    }
    const { accountId, destination } = parsed.data;
    if (!isClassicAccountId(accountId)) {
      return reply.code(400).send({
        error: "not_classic_account",
        message: "Cleanup applies to classic (G...) accounts; smart wallets cannot be merged",
      });
    }
    if (!isClassicAccountId(destination)) {
      return reply.code(400).send({
        error: "invalid_destination",
        message: "Merge destination must be a classic (G...) account",
      });
    }
    if (destination === accountId) {
      return reply.code(400).send({
        error: "invalid_destination",
        message: "Destination must differ from the account being closed",
      });
    }

    const account = await deps.reader.getAccount(accountId);
    if (!account) return reply.code(404).send({ error: "account_not_found" });
    return reply.send({ plan: buildCleanupPlan(account, destination) });
  });

  const passphrase = deps.networkPassphrase ?? TESTNET_PASSPHRASE;

  // Builds UNSIGNED cleanup transactions (decisions.md option A): the user
  // signs them in the wallet that holds the old account's key.
  // --- Vellar x402: payment gate for POST /lifecycle/execute ---
  // payTo is read from the "vellar-x402.payToAddress" VS Code setting at runtime.
  const PAYMENT_CONFIG = {
    payToAddress: "GBBA3HN2PNOAJGR6R5VY34SQFDFTZFQIGDPYATJB34UXXFUHVR4KZRAZ",
  };

  const x402FacilitatorClient = new HTTPFacilitatorClient({ url: "https://vellar-facilitator.onrender.com" });
  const x402Server = new x402ResourceServer(x402FacilitatorClient)
    .register("stellar:testnet", new ExactStellarScheme())
    .registerExtension(bazaarResourceServerExtension);

  const x402Routes = {
    "POST /lifecycle/execute": {
      accepts: {
        scheme: "exact" as const,
        price: "$0.05",
        network: "stellar:testnet" as const,
        payTo: PAYMENT_CONFIG.payToAddress,
      },
      description: "@vellar/lifecycle-service — /lifecycle/execute ($0.05 USDC)", // TODO: add the actual resource description
      serviceName: "@vellar/lifecycle-service",
      tags: ["api", "x402"],
      extensions: declareDiscoveryExtension({
        input: {
          // TODO: example values for this endpoint's query/body
          // parameters, e.g. { topic: "perseverance" }
        },
        inputSchema: {
          // TODO: JSON schema for those parameters, e.g.
          // { properties: { topic: { type: "string" } } }
        },
        output: {
          example: {
            // TODO: add a real example response object,
            // e.g. { result: "..." }
          },
        },
      }),
    },
  };
  // --- end Vellar x402 setup ---
  paymentMiddleware(app, x402Routes, x402Server); // Vellar x402: gate the route below
  app.post("/lifecycle/execute", async (request, reply) => {
    const parsed = planBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_body", details: parsed.error.issues });
    }
    const { accountId, destination } = parsed.data;
    const invalid = validatePair(accountId, destination);
    if (invalid) return reply.code(400).send({ error: invalid });

    const account = await deps.reader.getAccount(accountId);
    if (!account) return reply.code(404).send({ error: "account_not_found" });

    return reply.send({
      steps: buildCleanupSteps(account, destination, passphrase),
      plan: buildCleanupPlan(account, destination),
    });
  });

  // MergePreflightValidator (idea.md §6.4): re-inspects and refuses to build
  // the merge while any blocker remains.
  app.post("/lifecycle/merge", async (request, reply) => {
    const parsed = planBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_body", details: parsed.error.issues });
    }
    const { accountId, destination } = parsed.data;
    const invalid = validatePair(accountId, destination);
    if (invalid) return reply.code(400).send({ error: invalid });

    const account = await deps.reader.getAccount(accountId);
    if (!account) return reply.code(404).send({ error: "account_not_found" });

    const plan = buildCleanupPlan(account, destination);
    if (!plan.mergeReady) {
      // §13 alerting: abnormal cleanup failure rates. A merge refused because
      // the account still has blockers is a "not ready" outcome, not success.
      recordOutcome(domainMetrics.cleanupCompleted, "lifecycle-service", "failure");
      return reply.code(409).send({ error: "not_merge_ready", plan });
    }
    recordOutcome(domainMetrics.cleanupCompleted, "lifecycle-service", "success");
    return reply.send({ step: buildMergeStep(account, destination, passphrase) });
  });

  return app;
}
