# Shared Android build paths. Explicit make variables take precedence, followed
# by the standard Android environment variables and per-user SDK location.
SDK ?= $(if $(ANDROID_SDK_ROOT),$(ANDROID_SDK_ROOT),$(if $(ANDROID_HOME),$(ANDROID_HOME),$(if $(wildcard $(HOME)/Android/Sdk),$(HOME)/Android/Sdk,$(if $(wildcard $(HOME)/Library/Android/sdk),$(HOME)/Library/Android/sdk,$(HOME)/android-sdk))))
# NDK prebuilt toolchain host tag: the NDK ships linux-x86_64,
# darwin-x86_64 and windows-x86_64 prebuilts. Pick by host kernel;
# override NDK_HOST_TAG explicitly for any other host.
NDK_HOST_TAG ?= $(if $(filter Darwin,$(shell uname -s 2>/dev/null)),darwin-x86_64,linux-x86_64)
NDK ?= $(if $(ANDROID_NDK_HOME),$(ANDROID_NDK_HOME),$(if $(ANDROID_NDK_ROOT),$(ANDROID_NDK_ROOT),$(SDK)/ndk/28.2.13676358))
BUILD_TOOLS ?= $(SDK)/build-tools/37.0.0
ANDROID_JAR ?= $(SDK)/platforms/android-36/android.jar
D8 ?= $(BUILD_TOOLS)/d8
# The project debug keystore is committed at the repository root so every
# build signs with the same key; the per-user keystore is only a fallback
# for a tree that does not carry it.
KEYSTORE ?= $(if $(wildcard $(abspath ../debug.keystore)),$(abspath ../debug.keystore),$(HOME)/.android/debug.keystore)
