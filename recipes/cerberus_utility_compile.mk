# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.


LIB_SRCS := $(filter-out $(FILTER_LIB_FILES), $(LIB_SRCS))
lib_names := $(notdir $(LIB_SRCS))
lib_objs := $(addprefix $(BUILD_OUT_DIR), $(lib_names:%.c=%.o))

UTILITY_APP_SRCS := $(filter-out $(FILTER_APP_FILES), $(UTILITY_APP_SRCS))
utility_app_names := $(notdir $(UTILITY_APP_SRCS))
utility_app_objs := $(addprefix $(BUILD_OUT_DIR), $(utility_app_names:%.c=%.o))

link_ext_libs := $(addprefix -l, $(EXTERNAL_DEPLIB))
link_std_libs := $(addprefix -l, $(STANDARD_DEPLIB))

LIB_SO_MAJOR ?= libcerberus_utility.so.0
LIB_SO_MAJ_MIN ?= libcerberus_utility.so.0.0
LIB_SO_MAJ_MIN_BUILD ?= libcerberus_utility.0.0.0

creatdir := .create
arscript := merge.ar

.PHONY: all

all: $(UTILITY_APP_OUT) $(UTILITY_APP_SO_OUT) $(LIB_STATIC_TARGET) $(LIB_SO_TARGET)
app_so: $(UTILITY_APP_SO_OUT)
so_target: $(LIB_SO_TARGET)
cerberus_util_lib: clean $(LIB_STATIC_TARGET) $(LIB_SO_TARGET)

$(UTILITY_APP_OUT): $(APP_OUT_DIR)$(creatdir) $(LIB_STATIC_TARGET_TMP) $(utility_app_objs)
	@echo "Building utility standalone app target: $(UTILITY_APP_OUT)"
	$(CC) $(CPPFLAGS) $(INC_FLAGS) $(CFLAGS) $(LDFLAGS) $(utility_app_objs) $(LIB_STATIC_TARGET_TMP) $(link_std_libs) -pthread -o $@

$(UTILITY_APP_SO_OUT): $(APP_OUT_DIR)$(creatdir) $(utility_app_objs) $(LIB_SO_TARGET) $(LIB_CERBERUS_UTILITY)
	@echo "Building utility standalone so_app target: $(UTILITY_APP_SO_OUT)"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -pthread -o $@ $(utility_app_objs) -l$(UTILITY_LIB_NAME) $(link_std_libs) $(link_ext_libs) -Wl,-rpath,.

$(LIB_CERBERUS_UTILITY): $(LIB_SO_TARGET) $(LIB_STATIC_TARGET)
	@echo "Creating Symlinks.."
	@ln -sf $(LIB_SO_MAJ_MIN_BUILD) $(LIB_OUT_DIR)$(LIB_SO_MAJOR)
	@ln -sf $(LIB_SO_MAJ_MIN_BUILD) $(LIB_OUT_DIR)$(LIB_SO_MAJ_MIN)
	@ln -sf $(LIB_SO_MAJOR) $(LIB_OUT_DIR)$(LIB_SO_NAME)

$(LIB_SO_TARGET): $(LIB_OUT_DIR)$(creatdir) $(lib_objs)
	@echo "Building shared lib target"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,$(LIB_SO_MAJOR) -pthread -o $@ $(lib_objs) $(link_ext_libs) -lrt

$(LIB_STATIC_TARGET): $(LIB_OUT_DIR)$(creatdir) $(lib_objs)
	@echo "Building static lib target"
	$(AR) rcs $@ $(lib_objs)

$(LIB_STATIC_TARGET_TMP): $(BUILD_OUT_DIR)$(creatdir) $(LIB_STATIC_TARGET)
	@echo "Creating temp archive file"
	@echo "CREATE $@" > $(BUILD_DIR)$(arscript)
	@echo "ADDLIB $(LIB_STATIC_TARGET)" >> $(BUILD_DIR)$(arscript)
ifneq ($(EXTERNAL_STATIC_LIBS), )
	@for f in $(EXTERNAL_STATIC_LIBS); do (echo "$$f"); done
	@for f in $(EXTERNAL_STATIC_LIBS); do (echo "ADDLIB $$f">> $(BUILD_DIR)$(arscript)); done
endif
	@echo "SAVE" >> $(BUILD_DIR)$(arscript)
	@echo "END" >> $(BUILD_DIR)$(arscript)
	$(AR) -M < $(BUILD_DIR)$(arscript)

echo:
	@echo $(lib_objs)

.PHONY: clean
clean:
	rm -rf $(BUILD_OUT_DIR) $(APP_OUT_DIR) $(LIB_OUT_DIR)


$(BUILD_OUT_DIR)%.o: %.c
	@echo "CC $<"
	$(CC) $(CPPFLAGS) $(INC_FLAGS) $(CFLAGS) -c -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o $@ $<

$(lib_objs): $(BUILD_OUT_DIR)$(creatdir)
$(utility_app_objs): $(BUILD_OUT_DIR)$(creatdir)

.PRECIOUS: %/$(creatdir)
%/$(creatdir):
	mkdir -p $(@D)
	touch $@
