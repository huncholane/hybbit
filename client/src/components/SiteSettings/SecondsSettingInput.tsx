"use client";

import { useExtracted } from "next-intl";
import { useState } from "react";

import { Input } from "@/components/ui/input";

interface SecondsSettingInputProps {
  id: string;
  value: number;
  min: number;
  max: number;
  ariaLabel: string;
  disabled?: boolean;
  /** Persist the new value; reject to have the input put the saved value back */
  onSave: (seconds: number) => Promise<void>;
}

/**
 * Whole-seconds setting that saves on blur or Enter. Out-of-range entries are
 * clamped and an empty entry reverts, so the saved value is always valid.
 */
export function SecondsSettingInput({ id, value, min, max, ariaLabel, disabled = false, onSave }: SecondsSettingInputProps) {
  const t = useExtracted();
  const [draft, setDraft] = useState(String(value));
  const [saving, setSaving] = useState(false);

  const commit = async () => {
    const parsed = draft.trim() === "" ? NaN : Math.round(Number(draft));
    const next = Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : value;
    setDraft(String(next));
    if (next === value) return;

    setSaving(true);
    try {
      await onSave(next);
    } catch {
      setDraft(String(value));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <Input
        id={id}
        type="number"
        inputMode="numeric"
        min={min}
        max={max}
        value={draft}
        onChange={e => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={e => {
          if (e.key === "Enter") e.currentTarget.blur();
        }}
        disabled={disabled || saving}
        aria-label={ariaLabel}
        className="w-20"
      />
      <span className="text-xs text-muted-foreground">{t("seconds")}</span>
    </>
  );
}
