include ../android-env.mk

BUILD := build
CLASSES := $(BUILD)/classes
DEX := $(BUILD)/dex
UNSIGNED := $(BUILD)/portal-autoroot-helper-unsigned.apk
ALIGNED := $(BUILD)/portal-autoroot-helper-aligned.apk
APK := $(BUILD)/portal-autoroot-helper.apk
SOURCES := $(shell find src -name '*.java' -type f)

.PHONY: all clean
all: $(APK)

$(APK): AndroidManifest.xml $(SOURCES) $(KEYSTORE)
	mkdir -p $(BUILD) $(CLASSES) $(DEX)
	$(BUILD_TOOLS)/aapt package -f -M AndroidManifest.xml \
		-I $(ANDROID_JAR) -F $(UNSIGNED)
	javac -source 8 -target 8 -cp $(ANDROID_JAR) -d $(CLASSES) $(SOURCES)
	cd $(CLASSES) && jar cf ../portal-autoroot-helper-classes.jar .
	$(BUILD_TOOLS)/d8 --min-api 24 --output $(DEX) \
		$(BUILD)/portal-autoroot-helper-classes.jar
	cd $(DEX) && $(BUILD_TOOLS)/aapt add ../portal-autoroot-helper-unsigned.apk classes.dex
	$(BUILD_TOOLS)/zipalign -f 4 $(UNSIGNED) $(ALIGNED)
	$(BUILD_TOOLS)/apksigner sign --ks $(KEYSTORE) --ks-pass pass:android \
		--key-pass pass:android --out $(APK) $(ALIGNED)
	$(BUILD_TOOLS)/apksigner verify --verbose $(APK)

$(KEYSTORE):
	mkdir -p $(dir $(KEYSTORE))
	keytool -genkeypair -keystore $(KEYSTORE) -storepass android \
		-alias androiddebugkey -keypass android -dname "CN=Android Debug,O=Android,C=US" \
		-keyalg RSA -keysize 2048 -validity 10000
	chmod 0600 $(KEYSTORE)

clean:
	rm -rf $(BUILD)
