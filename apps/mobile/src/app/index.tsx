// Temporary foundation smoke screen. Replace this route when product UI work starts.

import type {
  TunnetPlatformState,
  TunnetRuntimeSnapshotEvent,
} from "@tunnet-native/TunnetNative.types";
import TunnetNative from "@tunnet-native/TunnetNativeModule";
import { StatusBar } from "expo-status-bar";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Pressable, ScrollView, Text, TextInput, View } from "react-native";
import {
  Gesture,
  GestureDetector,
  GestureHandlerRootView,
} from "react-native-gesture-handler";
import Animated, {
  useAnimatedStyle,
  useSharedValue,
  withTiming,
} from "react-native-reanimated";
import { SafeAreaView } from "react-native-safe-area-context";
import {
  DataPlane,
  Lifecycle,
  type Snapshot,
} from "@/generated/tunnet/agent_pb";
import { decodeRuntimeSnapshot } from "@/lib/tunnet-runtime";
import { cn } from "@/lib/utils";

function enumName(enumType: Record<number, string | number>, value: number) {
  return enumType[value] ?? `UNKNOWN(${value})`;
}

export default function FoundationDiagnosticsScreen() {
  const [platformState, setPlatformState] =
    useState<TunnetPlatformState | null>(null);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [inviteCode, setInviteCode] = useState("");
  const [eventCount, setEventCount] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refreshPlatformState = useCallback(async () => {
    setPlatformState(await TunnetNative.getPlatformState());
  }, []);

  useEffect(() => {
    void TunnetNative.getPlatformState()
      .then(setPlatformState)
      .catch((cause) => {
        setError(cause instanceof Error ? cause.message : String(cause));
      });
    const subscription = TunnetNative.addListener(
      "onRuntimeSnapshot",
      (event: TunnetRuntimeSnapshotEvent) => {
        try {
          setSnapshot(decodeRuntimeSnapshot(event.snapshot));
          setEventCount((count) => count + 1);
          setError(null);
        } catch (cause) {
          setError(cause instanceof Error ? cause.message : String(cause));
        }
      },
    );

    return () => subscription.remove();
  }, []);

  const run = useCallback(
    async (operation: () => Promise<unknown>) => {
      setBusy(true);
      setError(null);
      try {
        await operation();
        await refreshPlatformState();
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        setBusy(false);
      }
    },
    [refreshPlatformState],
  );

  const diagnosticOffset = useSharedValue(0);
  const diagnosticGesture = useMemo(
    () =>
      Gesture.Pan()
        .onUpdate((event) => {
          // Reanimated worklets mutate shared values by design.
          // eslint-disable-next-line react-hooks/immutability
          diagnosticOffset.value = event.translationX;
        })
        .onEnd(() => {
          // eslint-disable-next-line react-hooks/immutability
          diagnosticOffset.value = withTiming(0, { duration: 150 });
        }),
    [diagnosticOffset],
  );
  const diagnosticStyle = useAnimatedStyle(() => ({
    transform: [{ translateX: diagnosticOffset.value }],
  }));

  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      {/* SafeAreaView is third-party, so Uniwind does not process its className prop. */}
      <SafeAreaView style={{ flex: 1 }}>
        <StatusBar style="auto" />
        <ScrollView
          className="flex-1 bg-background"
          contentContainerClassName="gap-4 px-5 pb-8 pt-4"
          contentContainerStyle={{ flexGrow: 1 }}
          keyboardShouldPersistTaps="handled"
        >
          <View className="gap-1">
            <Text className="text-2xl font-bold text-foreground">
              Tunnet foundation
            </Text>
            <Text className="text-sm text-muted-foreground">
              Temporary Expo, Uniwind, Reanimated, Gesture Handler, protobuf,
              and native bridge smoke test.
            </Text>
          </View>

          <View className="gap-1 rounded-lg border border-border bg-card p-4">
            <Text className="font-semibold text-foreground">Platform</Text>
            <Text className="font-mono text-xs text-muted-foreground">
              {platformState
                ? JSON.stringify(platformState, null, 2)
                : "Loading native module state…"}
            </Text>
          </View>

          <View className="gap-1 rounded-lg border border-border bg-card p-4">
            <Text className="font-semibold text-foreground">
              Runtime snapshot
            </Text>
            <Text className="font-mono text-xs text-muted-foreground">
              events: {eventCount}
              {"\n"}
              lifecycle:{" "}
              {snapshot ? enumName(Lifecycle, snapshot.lifecycle) : "waiting"}
              {"\n"}
              data plane:{" "}
              {snapshot ? enumName(DataPlane, snapshot.dataPlane) : "waiting"}
              {"\n"}
              hostname: {snapshot?.hostname || "waiting"}
              {"\n"}
              networks / peers:{" "}
              {snapshot
                ? `${snapshot.networks.length} / ${snapshot.peers.length}`
                : "waiting"}
            </Text>
          </View>

          <GestureDetector gesture={diagnosticGesture}>
            <Animated.View
              className="h-12 items-center justify-center rounded-lg bg-primary"
              style={diagnosticStyle}
            >
              <Text className="text-sm font-semibold text-primary-foreground">
                Drag to verify Reanimated + Gesture Handler
              </Text>
            </Animated.View>
          </GestureDetector>

          <View className="gap-2">
            <Pressable
              accessibilityRole="button"
              className={cn(
                "items-center rounded-lg bg-primary px-4 py-3",
                busy && "opacity-50",
              )}
              disabled={busy}
              onPress={() =>
                void run(async () => {
                  await TunnetNative.requestNotificationPermission();
                  await TunnetNative.requestLocalNetworkPermission();
                  const vpnGranted = await TunnetNative.requestVpnPermission();
                  if (vpnGranted) await TunnetNative.start();
                })
              }
            >
              <Text className="font-semibold text-primary-foreground">
                Request permissions and start
              </Text>
            </Pressable>

            <Pressable
              accessibilityRole="button"
              className={cn(
                "items-center rounded-lg border border-border px-4 py-3",
                busy && "opacity-50",
              )}
              disabled={busy}
              onPress={() => void run(() => TunnetNative.stop())}
            >
              <Text className="font-semibold text-foreground">Stop</Text>
            </Pressable>
          </View>

          <View className="gap-2">
            <TextInput
              autoCapitalize="none"
              className="rounded-lg border border-border bg-card px-4 py-3 text-foreground placeholder:text-muted-foreground"
              onChangeText={setInviteCode}
              placeholder="Invite code"
              value={inviteCode}
            />
            <Pressable
              accessibilityRole="button"
              className={cn(
                "items-center rounded-lg border border-border px-4 py-3",
                (busy || inviteCode.trim().length === 0) && "opacity-50",
              )}
              disabled={busy || inviteCode.trim().length === 0}
              onPress={() =>
                void run(async () => {
                  await TunnetNative.joinNetwork(inviteCode.trim());
                  setInviteCode("");
                })
              }
            >
              <Text className="font-semibold text-foreground">
                Join network
              </Text>
            </Pressable>
          </View>

          {error ? (
            <Text
              accessibilityRole="alert"
              className="font-mono text-xs text-destructive"
            >
              {error}
            </Text>
          ) : null}
        </ScrollView>
      </SafeAreaView>
    </GestureHandlerRootView>
  );
}
