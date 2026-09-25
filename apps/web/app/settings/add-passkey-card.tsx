"use client";

import { useEffect, useState } from "react";
import type { WalletSession } from "@vellar/types";
import { detectPasskeySupport, environmentFromWindow, isUserCancellation } from "@vellar/passkey";
import { Eyebrow, LpActionButton } from "@/app/landing/ui";
import { walletErrorMessage } from "@/lib/messages";
import { signerMutationErrorMessage } from "@/lib/signer-model";
import { useAddPasskey } from "@/lib/signers";
import { trackTransaction } from "@/lib/track";

// Add a second passkey (#401): the sanctioned recovery story. Two ceremonies,
// both explicit: the browser registers the NEW credential (no chain effect),
// then the EXISTING passkey approves the on-chain add_signer. The new passkey
// is a signer only once that transaction is confirmed — a successful browser
// registration on its own registers nothing.

type State =
  | { step: "idle" }
  | { step: "registering" }
  | { step: "approving" }
  | { step: "confirming"; hash: string }
  | { step: "done"; hash: string; keyId: string }
  | { step: "error"; message: string };

export function AddPasskeyCard({
  session,
  onAdded,
}: {
  session: WalletSession;
  onAdded?: () => void;
}) {
  const add = useAddPasskey(session.accountId, session.network, session.keyId);
  const [label, setLabel] = useState("");
  const [state, setState] = useState<State>({ step: "idle" });
  const [support, setSupport] = useState<"supported" | "unsupported" | "unknown">("unknown");

  useEffect(() => {
    setSupport(
      detectPasskeySupport(environmentFromWindow(window)).supported ? "supported" : "unsupported",
    );
  }, []);

  async function run() {
    setState({ step: "registering" });
    try {
      // Registration + approval happen inside one mutation so the existing
      // passkey's approval is never separable from the credential it approves.
      const result = await add.mutateAsync(label.trim() || "Recovery passkey");
      setState({ step: "confirming", hash: result.hash });
      const outcome = await trackTransaction(result.hash);
      if (outcome !== "success")
        throw new Error(`Transaction ${result.hash} failed on the network.`);
      setState({ step: "done", hash: result.hash, keyId: result.keyId });
      onAdded?.();
    } catch (err) {
      setState({ step: "error", message: describe(err) });
    }
  }

  const busy =
    state.step === "registering" || state.step === "approving" || state.step === "confirming";

  return (
    <section className="lpa-panel" aria-labelledby="add-passkey-heading">
      <Eyebrow id="add-passkey-heading">Add a second passkey</Eyebrow>
      <p className="mt-2! text-xs leading-relaxed text-[var(--lp-ink-faint)]">
        Register another passkey — typically your phone — as a full recovery signer for this
        account. You will complete two prompts: create the new passkey, then approve it with the
        passkey you are signed in with. Nothing changes on-chain until that approval is confirmed.
      </p>

      {support === "unsupported" && (
        <p role="alert" className="lpa-bad mt-3.5! text-sm">
          This browser doesn&apos;t support passkeys, so a second passkey can&apos;t be created
          here. Open this page in a browser with WebAuthn support.
        </p>
      )}

      {support === "supported" && state.step !== "done" && (
        <div className="mt-3.5 flex flex-col gap-3">
          <label className="lpa-field">
            <span className="flabel">Label for the new passkey (shown by your authenticator)</span>
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Phone"
              maxLength={64}
              disabled={busy}
            />
          </label>
          <p className="m-0! text-xs text-[var(--lp-ink-faint)]">
            Network: <strong className="uppercase">{session.network}</strong>.
          </p>
          <LpActionButton className="self-start" onClick={() => void run()} disabled={busy}>
            {state.step === "registering"
              ? "Create the new passkey…"
              : state.step === "approving"
                ? "Approve with your existing passkey…"
                : state.step === "confirming"
                  ? "Confirming on the network…"
                  : "Add passkey — approve with existing passkey"}
          </LpActionButton>
        </div>
      )}

      {state.step === "confirming" && (
        <p className="mt-2.5! break-all font-[family-name:var(--lp-mono)] text-xs text-[var(--lp-ink-faint)]">
          tx {state.hash}
        </p>
      )}

      {state.step === "done" && (
        <div className="mt-3.5 flex flex-col gap-2 text-sm">
          <span className="lpa-ok font-bold">✓ New passkey added on-chain</span>
          <p className="m-0! break-all font-[family-name:var(--lp-mono)] text-xs text-[var(--lp-ink-faint)]">
            credential {state.keyId} · tx {state.hash}
          </p>
          <p className="m-0! text-xs text-[var(--lp-ink-faint)]">
            It now appears in the signer list and can sign in and approve transactions on its own.
          </p>
          <LpActionButton
            variant="outline"
            size="sm"
            className="self-start"
            onClick={() => setState({ step: "idle" })}
          >
            Add another
          </LpActionButton>
        </div>
      )}

      {state.step === "error" && (
        <p role="alert" className="lpa-bad mt-2.5! text-sm">
          {state.message}
        </p>
      )}
    </section>
  );
}

function describe(err: unknown): string {
  if (isUserCancellation(err)) return "The passkey prompt was dismissed. Nothing was changed.";
  return signerMutationErrorMessage(err, walletErrorMessage(err));
}
