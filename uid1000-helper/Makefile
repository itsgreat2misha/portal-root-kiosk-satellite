include ../android-env.mk

TOOLCHAIN ?= $(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)
CXX := $(TOOLCHAIN)/bin/aarch64-linux-android29-clang++
CC := $(TOOLCHAIN)/bin/aarch64-linux-android29-clang
OBJCOPY := $(TOOLCHAIN)/bin/llvm-objcopy
JAVAC ?= javac
BUILD := build
WATCH := $(BUILD)/portal-camera-led-watch
HOOK_OBJECT := $(BUILD)/portal-uid1000-hook.o
HOOK := $(BUILD)/portal-uid1000-hook.bin
ALOHA_WATCH := $(BUILD)/portal-camera-led-watch-aloha
ALOHA_LIBRARY := $(BUILD)/libportal-camera-led-watch-aloha.so
ALOHA_CLASS_DIR := $(BUILD)/aloha-java
ALOHA_CLASS := $(ALOHA_CLASS_DIR)/PortalUid1000Bootstrap.class
ALOHA_BOOTSTRAP := $(BUILD)/portal-uid1000-bootstrap.zip
ALOHA_HOOK_OBJECT := $(BUILD)/portal-uid1000-hook-aloha.o
ALOHA_HOOK := $(BUILD)/portal-uid1000-hook-aloha.bin
ALOHA_APK_STAGE := $(BUILD)/aloha-runtime-apk
ALOHA_APK_UNSIGNED := $(BUILD)/portal-uid1000-runtime-unsigned.apk
ALOHA_APK_ALIGNED := $(BUILD)/portal-uid1000-runtime-aligned.apk
ALOHA_APK := $(BUILD)/portal-uid1000-runtime.apk
ALOHA_DATA_DIRECTORY := /data/misc/adb/portal-uid1000

.PHONY: all aloha clean
all: $(WATCH) $(HOOK)
aloha: $(ALOHA_WATCH) $(ALOHA_HOOK) $(ALOHA_APK)

$(WATCH): native/portal_camera_led_watch.cpp
	mkdir -p $(BUILD)
	$(CXX) --target=aarch64-linux-android29 -std=c++17 -O2 -fPIE -pie \
		-fvisibility=hidden -Wl,--gc-sections -static-libstdc++ \
		$< -o $@ -ldl -llog

$(HOOK_OBJECT): native/boot_hook.S
	mkdir -p $(BUILD)
	$(CC) --target=aarch64-linux-android29 -c $< -o $@

$(HOOK): $(HOOK_OBJECT)
	$(OBJCOPY) --only-section=.text -O binary $< $@
	test "$$(wc -c < $@ | tr -d ' ')" -le 316

$(ALOHA_LIBRARY): native/portal_camera_led_watch.cpp native/portal_camera_led_jni.cpp
	mkdir -p $(BUILD)
	$(CXX) --target=aarch64-linux-android29 -std=c++17 -O2 -fPIC -shared \
		-fvisibility=hidden -Wl,--gc-sections -static-libstdc++ \
		-DPORTAL_WATCHDOG_LIBRARY=1 \
		-DPORTAL_UID1000_DATA_DIRECTORY=\"$(ALOHA_DATA_DIRECTORY)\" \
		$^ -o $@ -ldl -llog

$(ALOHA_CLASS): java/PortalUid1000Bootstrap.java
	mkdir -p $(ALOHA_CLASS_DIR)
	$(JAVAC) -source 8 -target 8 -d $(ALOHA_CLASS_DIR) $<

$(ALOHA_BOOTSTRAP): $(ALOHA_CLASS)
	rm -f $@
	$(D8) --min-api 28 --output $@ $<

$(ALOHA_WATCH): $(ALOHA_LIBRARY) $(ALOHA_BOOTSTRAP) pack_runtime.py
	python3 pack_runtime.py $(ALOHA_LIBRARY) $(ALOHA_BOOTSTRAP) $@

$(ALOHA_HOOK_OBJECT): native/boot_hook_runtime.S
	mkdir -p $(BUILD)
	$(CC) --target=aarch64-linux-android29 \
		-c $< -o $@

$(ALOHA_HOOK): $(ALOHA_HOOK_OBJECT)
	$(OBJCOPY) --only-section=.text -O binary $< $@
	test "$$(wc -c < $@ | tr -d ' ')" -le 32768

$(ALOHA_APK): AndroidManifest.xml $(ALOHA_LIBRARY) $(ALOHA_BOOTSTRAP) $(KEYSTORE)
	rm -rf $(ALOHA_APK_STAGE) $(ALOHA_APK_UNSIGNED) $(ALOHA_APK_ALIGNED) $@
	mkdir -p $(ALOHA_APK_STAGE)/lib/arm64-v8a
	unzip -p $(ALOHA_BOOTSTRAP) classes.dex > $(ALOHA_APK_STAGE)/classes.dex
	cp $(ALOHA_LIBRARY) \
		$(ALOHA_APK_STAGE)/lib/arm64-v8a/libportal_uid1000_watch.so
	$(BUILD_TOOLS)/aapt package -f -M AndroidManifest.xml \
		-I $(ANDROID_JAR) -F $(ALOHA_APK_UNSIGNED)
	cd $(ALOHA_APK_STAGE) && $(BUILD_TOOLS)/aapt add \
		../portal-uid1000-runtime-unsigned.apk classes.dex \
		lib/arm64-v8a/libportal_uid1000_watch.so
	$(BUILD_TOOLS)/zipalign -f 4 $(ALOHA_APK_UNSIGNED) $(ALOHA_APK_ALIGNED)
	$(BUILD_TOOLS)/apksigner sign --ks $(KEYSTORE) --ks-pass pass:android \
		--key-pass pass:android --out $@ $(ALOHA_APK_ALIGNED)
	$(BUILD_TOOLS)/apksigner verify --verbose $@

clean:
	rm -rf $(BUILD)
