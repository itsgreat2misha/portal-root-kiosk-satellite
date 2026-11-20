include ../android-env.mk

TOOLCHAIN ?= $(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)
NATIVE_CC := $(TOOLCHAIN)/bin/armv7a-linux-androideabi29-clang
NATIVE_CC_API28 := $(TOOLCHAIN)/bin/armv7a-linux-androideabi28-clang
BUILD := build
CLASSES := $(BUILD)/classes
DEX := $(BUILD)/dex
UNSIGNED := $(BUILD)/portal-audio-helper-unsigned.apk
ALIGNED := $(BUILD)/portal-audio-helper-aligned.apk
APK := $(BUILD)/portal-audio-helper.apk
PERSIST_SO := $(BUILD)/libportal_audio_persist.so
PERSIST_JAVA_SO := $(BUILD)/libportal_audio_persist_java.so
SOURCES := $(shell find src -name '*.java' -type f)

.PHONY: all clean native native-java
all: $(APK) $(PERSIST_SO)

native: $(PERSIST_SO)

native-java: $(PERSIST_JAVA_SO)

$(PERSIST_SO): native/portal_audio_persist.c
	mkdir -p $(BUILD)
	$(NATIVE_CC) --target=armv7a-linux-androideabi29 \
		--sysroot=$(TOOLCHAIN)/sysroot -O2 -fPIC -fvisibility=hidden \
		-shared -Wl,-soname,libpa.so -Wl,--gc-sections \
		$< -o $@ -pthread -lbinder_ndk -llog -ldl

$(PERSIST_JAVA_SO): native/portal_audio_persist_java.c
	mkdir -p $(BUILD)
	$(NATIVE_CC_API28) --target=armv7a-linux-androideabi28 \
		--sysroot=$(TOOLCHAIN)/sysroot -O2 -fPIC -fvisibility=hidden \
		-shared -Wl,-soname,libpa.so -Wl,--gc-sections \
		$< -o $@ -pthread -llog

$(APK): AndroidManifest.xml $(SOURCES)
	mkdir -p $(BUILD) $(CLASSES) $(DEX)
	$(BUILD_TOOLS)/aapt package -f -M AndroidManifest.xml \
		-I $(ANDROID_JAR) -F $(UNSIGNED)
	javac -source 8 -target 8 -cp $(ANDROID_JAR) -d $(CLASSES) $(SOURCES)
	cd $(CLASSES) && jar cf ../portal-audio-helper-classes.jar .
	$(BUILD_TOOLS)/d8 --min-api 24 --output $(DEX) \
		$(BUILD)/portal-audio-helper-classes.jar
	cd $(DEX) && $(BUILD_TOOLS)/aapt add ../portal-audio-helper-unsigned.apk classes.dex
	$(BUILD_TOOLS)/zipalign -f 4 $(UNSIGNED) $(ALIGNED)
	$(BUILD_TOOLS)/apksigner sign --ks $(KEYSTORE) --ks-pass pass:android \
		--key-pass pass:android --out $(APK) $(ALIGNED)
	$(BUILD_TOOLS)/apksigner verify --verbose $(APK)

clean:
	rm -rf $(BUILD)
