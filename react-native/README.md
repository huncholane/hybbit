# @hygo/react-native

React Native analytics SDK for Hygo.

## Install

```sh
npm install @hygo/react-native @react-native-async-storage/async-storage
```

## Usage

```ts
import AsyncStorage from "@react-native-async-storage/async-storage";
import hygo from "@hygo/react-native";

await hygo.init({
  analyticsHost: "https://app.hygo.ai/api",
  siteId: "your-site-id",
  appIdentifier: "com.example.app",
  storage: AsyncStorage,
  initialScreenName: "Home",
});

await hygo.event("signup_started", { plan: "pro" });
await hygo.identify("user_123", { plan: "pro" });
```

## React Navigation

```tsx
const navigationTracker = hygo.createNavigationTracker();

<NavigationContainer
  ref={navigationRef}
  onReady={() => navigationTracker.onReady(navigationRef.current)}
  onStateChange={() => navigationTracker.onStateChange(navigationRef.current)}
>
  {/* screens */}
</NavigationContainer>;
```

The SDK uses a generated anonymous install ID stored through the provided storage adapter. Pass AsyncStorage or a compatible storage object for persistence across app launches.
