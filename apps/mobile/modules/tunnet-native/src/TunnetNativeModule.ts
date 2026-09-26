import { requireNativeModule } from "expo";

import type { TunnetNativeModule } from "./TunnetNative.types";

export default requireNativeModule<TunnetNativeModule>("TunnetNative");
