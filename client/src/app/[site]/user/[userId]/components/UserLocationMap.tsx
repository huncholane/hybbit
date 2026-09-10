"use client";

import mapboxgl from "mapbox-gl";
import "mapbox-gl/dist/mapbox-gl.css";
import { useEffect, useRef } from "react";
import { useTheme } from "next-themes";
import { cn } from "../../../../../lib/utils";
import { useConfigs } from "../../../../../lib/configs";

interface UserLocationMapProps {
  lat: number;
  lon: number;
  className?: string;
}

// Plots the coordinates the IP lookup stored with the user's events rather than
// geocoding the location text: Mapbox resolves a bare country code like "NO"
// (Norway) to North Korea.
export function UserLocationMap({ lat, lon, className }: UserLocationMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<mapboxgl.Map | null>(null);
  const markerRef = useRef<mapboxgl.Marker | null>(null);
  const { configs } = useConfigs();
  const { resolvedTheme } = useTheme();

  const style = resolvedTheme === "dark" ? "mapbox://styles/mapbox/dark-v11" : "mapbox://styles/mapbox/light-v11";

  useEffect(() => {
    if (!containerRef.current || !configs?.mapboxToken) return;

    // Clean up previous map instance before creating a new one
    markerRef.current?.remove();
    markerRef.current = null;
    mapRef.current?.remove();
    mapRef.current = null;

    mapboxgl.accessToken = configs.mapboxToken;

    const map = new mapboxgl.Map({
      container: containerRef.current,
      style,
      center: [lon, lat],
      zoom: 4,
      pitch: 0,
      bearing: 0,
      antialias: true,
      attributionControl: false,
      // Static locator: panning/zooming a thumbnail this small only steals the
      // page's scroll wheel
      interactive: false,
    });

    map.on("error", event => console.error("[UserLocationMap] Mapbox error", event.error));

    mapRef.current = map;

    markerRef.current = new mapboxgl.Marker({ color: "#10b981" }).setLngLat([lon, lat]).addTo(map);

    return () => {
      markerRef.current?.remove();
      markerRef.current = null;
      mapRef.current?.remove();
      mapRef.current = null;
    };
  }, [configs?.mapboxToken, lat, lon, style]);

  return (
    <div
      ref={containerRef}
      className={cn(
        "w-full overflow-hidden rounded-md border border-neutral-100 dark:border-neutral-800",
        "[&_.mapboxgl-ctrl-bottom-left]:hidden! [&_.mapboxgl-ctrl-logo]:hidden! [&_.mapboxgl-ctrl-bottom-right]:hidden!",
        className
      )}
    />
  );
}
