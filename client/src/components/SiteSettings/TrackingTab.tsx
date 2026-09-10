"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useExtracted } from "next-intl";
import { useState, useCallback, ReactNode } from "react";
import { toast } from "@/components/ui/sonner";

import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";

import { updateSiteConfig, SiteResponse } from "@/api/admin/endpoints";
import { useGetSitesFromOrg } from "@/api/admin/hooks/useSites";
import { planIncludesReplay } from "@/lib/subscription/planUtils";
import { useStripeSubscription } from "@/lib/subscription/useStripeSubscription";
import { Badge } from "@/components/ui/badge";
import { IS_CLOUD } from "@/lib/const";

import { SettingRow, SettingsSection, SettingsSections } from "./SettingsSection";

interface TrackingTabProps {
  siteMetadata: SiteResponse;
  disabled?: boolean;
  adminSubscription?: { planName: string; eventLimit?: number };
  adminMode?: boolean;
}

interface ToggleConfig {
  id: string;
  label: string;
  description: string;
  value: boolean;
  key: keyof SiteResponse;
  enabledMessage?: string;
  disabledMessage?: string;
  disabled?: boolean;
  badge?: ReactNode;
}

// Same bounds the server enforces on heartbeatInterval
const HEARTBEAT_MIN_SECONDS = 5;
const HEARTBEAT_MAX_SECONDS = 300;

export function TrackingTab({
  siteMetadata,
  disabled = false,
  adminSubscription,
  adminMode = false,
}: TrackingTabProps) {
  const t = useExtracted();
  const queryClient = useQueryClient();
  const { refetch } = useGetSitesFromOrg(siteMetadata?.organizationId ?? "", { enabled: !adminMode });
  const isMobileSite = siteMetadata.type === "mobile";

  const [toggleStates, setToggleStates] = useState({
    sessionReplay: siteMetadata.sessionReplay || false,
    webVitals: siteMetadata.webVitals || false,
    trackErrors: siteMetadata.trackErrors || false,
    trackOutbound: siteMetadata.trackOutbound ?? true,
    trackUrlParams: siteMetadata.trackUrlParams ?? true,
    trackInitialPageView: siteMetadata.trackInitialPageView ?? true,
    trackSpaNavigation: siteMetadata.trackSpaNavigation ?? true,
    trackButtonClicks: siteMetadata.trackButtonClicks ?? false,
    trackCopy: siteMetadata.trackCopy ?? false,
    trackFormInteractions: siteMetadata.trackFormInteractions ?? false,
    trackHeartbeat: siteMetadata.trackHeartbeat ?? false,
  });

  const [loadingStates, setLoadingStates] = useState<Record<string, boolean>>({});

  const refreshSiteQueries = useCallback(() => {
    if (!adminMode) {
      refetch();
    } else {
      queryClient.invalidateQueries({ queryKey: ["admin-organizations"] });
    }
    // Prefix match so both string- and number-keyed useGetSite instances update
    queryClient.invalidateQueries({ queryKey: ["get-site"] });
  }, [adminMode, refetch, queryClient]);

  const handleToggle = useCallback(
    async (
      key: keyof typeof toggleStates,
      checked: boolean,
      successMessage?: { enabled: string; disabled: string }
    ) => {
      setLoadingStates(prev => ({ ...prev, [key]: true }));
      try {
        await updateSiteConfig(siteMetadata.siteId, { [key]: checked });
        setToggleStates(prev => ({ ...prev, [key]: checked }));
        const message = successMessage
          ? checked
            ? successMessage.enabled
            : successMessage.disabled
          : `${key.replace(/([A-Z])/g, " $1").toLowerCase()} ${checked ? "enabled" : "disabled"}`;
        toast.success(message);
        refreshSiteQueries();
      } catch (error) {
        console.error(`Error updating ${key}:`, error);
        toast.error(`Failed to update ${key.replace(/([A-Z])/g, " $1").toLowerCase()}`);
        setToggleStates(prev => ({ ...prev, [key]: !checked }));
      } finally {
        setLoadingStates(prev => ({ ...prev, [key]: false }));
      }
    },
    [siteMetadata.siteId, refreshSiteQueries]
  );

  const [heartbeatInterval, setHeartbeatInterval] = useState(siteMetadata.heartbeatInterval ?? 15);
  const [heartbeatIntervalDraft, setHeartbeatIntervalDraft] = useState(String(siteMetadata.heartbeatInterval ?? 15));

  const saveHeartbeatInterval = async () => {
    const parsed = heartbeatIntervalDraft.trim() === "" ? NaN : Math.round(Number(heartbeatIntervalDraft));
    const next = Number.isFinite(parsed)
      ? Math.min(HEARTBEAT_MAX_SECONDS, Math.max(HEARTBEAT_MIN_SECONDS, parsed))
      : heartbeatInterval;
    setHeartbeatIntervalDraft(String(next));
    if (next === heartbeatInterval) return;

    setLoadingStates(prev => ({ ...prev, heartbeatInterval: true }));
    try {
      await updateSiteConfig(siteMetadata.siteId, { heartbeatInterval: next });
      setHeartbeatInterval(next);
      toast.success(t("Heartbeat interval set to {seconds} seconds", { seconds: String(next) }));
      refreshSiteQueries();
    } catch (error) {
      console.error("Error updating heartbeatInterval:", error);
      toast.error(t("Failed to update heartbeat interval"));
      setHeartbeatIntervalDraft(String(heartbeatInterval));
    } finally {
      setLoadingStates(prev => ({ ...prev, heartbeatInterval: false }));
    }
  };

  const { data: subscription, isLoading: isSubscriptionLoading } = useStripeSubscription();
  const effectiveSubscription = adminSubscription ?? subscription;
  const subscriptionLoading = adminMode ? false : isSubscriptionLoading;

  const sessionReplayDisabled = !planIncludesReplay(effectiveSubscription) && IS_CLOUD;

  const standardFeaturesDisabled =
    !effectiveSubscription?.planName.includes("custom") &&
    !effectiveSubscription?.planName.includes("standard") &&
    !effectiveSubscription?.planName.includes("pro") &&
    !effectiveSubscription?.planName.includes("appsumo") &&
    IS_CLOUD;

  const analyticsToggles: ToggleConfig[] = [
    // Hide the replay toggle for AppSumo tiers without replays (1-3); tiers 4-7 include them
    ...(!isMobileSite &&
    !subscriptionLoading &&
    (!effectiveSubscription?.planName?.startsWith("appsumo") || planIncludesReplay(effectiveSubscription))
      ? [
          {
            id: "sessionReplay",
            label: t("Session Replay"),
            description: t("Record and replay user sessions to understand user behavior"),
            value: toggleStates.sessionReplay,
            key: "sessionReplay",
            enabledMessage: t("Session replay enabled"),
            disabledMessage: t("Session replay disabled"),
            disabled: sessionReplayDisabled,
            badge: <Badge variant="success">Pro</Badge>,
          } as ToggleConfig,
        ]
      : []),
    ...(IS_CLOUD && !isMobileSite
      ? [
          {
            id: "webVitals",
            label: t("Web Vitals"),
            description: t("Track Core Web Vitals metrics (LCP, CLS, INP, FCP, TTFB)"),
            value: toggleStates.webVitals,
            key: "webVitals" as keyof SiteResponse,
            enabledMessage: t("Web Vitals enabled"),
            disabledMessage: t("Web Vitals disabled"),
            disabled: standardFeaturesDisabled,
            badge: <Badge variant="success">Standard</Badge>,
          } as ToggleConfig,
        ]
      : []),
    ...(!isMobileSite
      ? [
          {
            id: "trackSpaNavigation",
            label: t("SPA Navigation"),
            description: t("Automatically track navigation in single-page applications"),
            value: toggleStates.trackSpaNavigation,
            key: "trackSpaNavigation",
            enabledMessage: t("SPA navigation tracking enabled"),
            disabledMessage: t("SPA navigation tracking disabled"),
          } as ToggleConfig,
          {
            id: "trackUrlParams",
            label: t("URL Parameters"),
            description: t("Include query string parameters in page tracking"),
            value: toggleStates.trackUrlParams,
            key: "trackUrlParams",
            enabledMessage: t("URL parameters tracking enabled"),
            disabledMessage: t("URL parameters tracking disabled"),
          } as ToggleConfig,
        ]
      : []),
    {
      id: "trackInitialPageView",
      label: isMobileSite ? t("Initial Screen View") : t("Initial Page View"),
      description: isMobileSite
        ? t("Automatically track the initial screen passed to the React Native SDK")
        : t("Automatically track the first page view when the script loads"),
      value: toggleStates.trackInitialPageView,
      key: "trackInitialPageView",
      enabledMessage: t("Initial page view tracking enabled"),
      disabledMessage: t("Initial page view tracking disabled"),
    },
  ];

  const autoCaptureToggles: ToggleConfig[] = [
    ...(!isMobileSite
      ? [
          {
            id: "trackOutbound",
            label: t("Outbound Links"),
            description: t("Track when users click on external links"),
            value: toggleStates.trackOutbound,
            key: "trackOutbound",
            enabledMessage: t("Outbound tracking enabled"),
            disabledMessage: t("Outbound tracking disabled"),
          } as ToggleConfig,
        ]
      : []),
    {
      id: "trackErrors",
      label: t("Error Tracking"),
      description: isMobileSite
        ? t("Allow error events sent by the React Native SDK")
        : t("Capture JavaScript errors and exceptions from your site"),
      value: toggleStates.trackErrors,
      key: "trackErrors",
      enabledMessage: t("Error tracking enabled"),
      disabledMessage: t("Error tracking disabled"),
      disabled: standardFeaturesDisabled,
      badge: <Badge variant="success">Standard</Badge>,
    },
    ...(!isMobileSite
      ? [
          {
            id: "trackButtonClicks",
            label: t("Button Clicks"),
            description: t("Automatically track clicks on all buttons"),
            value: toggleStates.trackButtonClicks,
            key: "trackButtonClicks",
            enabledMessage: t("Button click tracking enabled"),
            disabledMessage: t("Button click tracking disabled"),
            disabled: standardFeaturesDisabled,
            badge: <Badge variant="success">Standard</Badge>,
          } as ToggleConfig,
          {
            id: "trackCopy",
            label: t("Copy Events"),
            description: t("Track when users copy text from your site"),
            value: toggleStates.trackCopy,
            key: "trackCopy",
            enabledMessage: t("Copy tracking enabled"),
            disabledMessage: t("Copy tracking disabled"),
            disabled: standardFeaturesDisabled,
            badge: <Badge variant="success">Standard</Badge>,
          } as ToggleConfig,
          {
            id: "trackFormInteractions",
            label: t("Form Interactions"),
            description: t("Automatically track form submissions and input/select changes"),
            value: toggleStates.trackFormInteractions,
            key: "trackFormInteractions",
            enabledMessage: t("Form interaction tracking enabled"),
            disabledMessage: t("Form interaction tracking disabled"),
            disabled: standardFeaturesDisabled,
            badge: <Badge variant="success">Standard</Badge>,
          } as ToggleConfig,
        ]
      : []),
  ];

  const renderToggleSection = (toggles: ToggleConfig[], title: string, extra?: ReactNode) => (
    <SettingsSection title={title}>
      {toggles.map(toggle => (
        <SettingRow
          key={toggle.id}
          label={toggle.label}
          htmlFor={toggle.id}
          description={toggle.description}
          badge={IS_CLOUD ? toggle.badge : undefined}
        >
          <Switch
            id={toggle.id}
            checked={toggle.value}
            disabled={loadingStates[toggle.key] || disabled || toggle.disabled}
            onCheckedChange={checked =>
              handleToggle(
                toggle.key as keyof typeof toggleStates,
                checked,
                toggle.enabledMessage && toggle.disabledMessage
                  ? { enabled: toggle.enabledMessage, disabled: toggle.disabledMessage }
                  : undefined
              )
            }
          />
        </SettingRow>
      ))}
      {extra}
    </SettingsSection>
  );

  // Web only: the heartbeat runs in the tracking script, which apps don't load
  const heartbeatRow = !isMobileSite && (
    <SettingRow
      label={t("Heartbeat")}
      htmlFor="trackHeartbeat"
      description={t(
        "Measure time on site while the page is visible and in use. Pauses in background tabs and when the visitor is idle"
      )}
    >
      <Input
        id="heartbeatInterval"
        type="number"
        inputMode="numeric"
        min={HEARTBEAT_MIN_SECONDS}
        max={HEARTBEAT_MAX_SECONDS}
        value={heartbeatIntervalDraft}
        onChange={e => setHeartbeatIntervalDraft(e.target.value)}
        onBlur={saveHeartbeatInterval}
        onKeyDown={e => {
          if (e.key === "Enter") e.currentTarget.blur();
        }}
        disabled={!toggleStates.trackHeartbeat || loadingStates.heartbeatInterval || disabled}
        aria-label={t("Heartbeat interval in seconds")}
        className="w-20"
      />
      <span className="text-xs text-muted-foreground">{t("seconds")}</span>
      <Switch
        id="trackHeartbeat"
        checked={toggleStates.trackHeartbeat}
        disabled={loadingStates.trackHeartbeat || disabled}
        onCheckedChange={checked =>
          handleToggle("trackHeartbeat", checked, {
            enabled: t("Heartbeat enabled"),
            disabled: t("Heartbeat disabled"),
          })
        }
      />
    </SettingRow>
  );

  return (
    <SettingsSections>
      {renderToggleSection(analyticsToggles, t("Analytics Features"), heartbeatRow)}
      {renderToggleSection(autoCaptureToggles, t("Auto Capture"))}
    </SettingsSections>
  );
}
