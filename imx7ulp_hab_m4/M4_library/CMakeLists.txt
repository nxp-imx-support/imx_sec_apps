INCLUDE(CMakeForceCompiler)

# CROSS COMPILER SETTING
SET(CMAKE_SYSTEM_NAME Generic)
CMAKE_MINIMUM_REQUIRED (VERSION 2.6)

# THE VERSION NUMBER
SET (Tutorial_VERSION_MAJOR 1)
SET (Tutorial_VERSION_MINOR 0)

# ENABLE ASM
ENABLE_LANGUAGE(ASM)

SET(CMAKE_STATIC_LIBRARY_PREFIX)
SET(CMAKE_STATIC_LIBRARY_SUFFIX)

SET(CMAKE_EXECUTABLE_LIBRARY_PREFIX)
SET(CMAKE_EXECUTABLE_LIBRARY_SUFFIX)

 
# CURRENT DIRECTORY
SET(ProjDirPath ${CMAKE_CURRENT_SOURCE_DIR})


SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -DDEBUG")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -D__STARTUP_CLEAR_BSS")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -g")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -Wall")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -fno-common")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -ffunction-sections")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -fdata-sections")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -ffreestanding")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -fno-builtin")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -mthumb")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -mapcs")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -std=gnu99")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -mfloat-abi=hard")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -DNDEBUG")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -D__STARTUP_CLEAR_BSS")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -Wall")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -fno-common")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -ffunction-sections")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -fdata-sections")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -ffreestanding")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -fno-builtin")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -mthumb")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -mapcs")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -std=gnu99")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -mfloat-abi=hard")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -mfpu=fpv4-sp-d16")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -DDEBUG")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -DFSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -DENABLE_RAM_VECTOR_TABLE")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -D__STARTUP_CLEAR_BSS")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -g")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -Wall")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -fno-common")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -ffunction-sections")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -fdata-sections")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -ffreestanding")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -fno-builtin")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -mthumb")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -mapcs")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -std=gnu99")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -mfloat-abi=hard")

SET(CMAKE_ASM_FLAGS_FLASH_DEBUG "${CMAKE_ASM_FLAGS_FLASH_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -DNDEBUG")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -DFSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -DENABLE_RAM_VECTOR_TABLE")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -D__STARTUP_CLEAR_BSS")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -Wall")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -fno-common")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -ffunction-sections")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -fdata-sections")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -ffreestanding")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -fno-builtin")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -mthumb")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -mapcs")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -std=gnu99")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -mfloat-abi=hard")

SET(CMAKE_ASM_FLAGS_FLASH_RELEASE "${CMAKE_ASM_FLAGS_FLASH_RELEASE} -mfpu=fpv4-sp-d16")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DCPU_MCIMX7U5CVP05")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DPRINTF_FLOAT_ENABLE=0")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DSCANF_FLOAT_ENABLE=0")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DPRINTF_ADVANCED_ENABLE=0")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DSCANF_ADVANCED_ENABLE=0")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-common")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ffunction-sections")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fdata-sections")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ffreestanding")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-builtin")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -mthumb")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -mapcs")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -std=gnu99")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -mfloat-abi=hard")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MMD")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MP")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DNDEBUG")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DCPU_MCIMX7U5CVP05")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DPRINTF_FLOAT_ENABLE=0")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DSCANF_FLOAT_ENABLE=0")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DPRINTF_ADVANCED_ENABLE=0")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DSCANF_ADVANCED_ENABLE=0")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Os")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fno-common")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffunction-sections")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fdata-sections")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffreestanding")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fno-builtin")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -mthumb")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -mapcs")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -std=gnu99")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -mfloat-abi=hard")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -mfpu=fpv4-sp-d16")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MMD")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MP")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -DDEBUG")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -DFSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -DENABLE_RAM_VECTOR_TABLE")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -DCPU_MCIMX7U5CVP05")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -DPRINTF_FLOAT_ENABLE=0")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -DSCANF_FLOAT_ENABLE=0")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -DPRINTF_ADVANCED_ENABLE=0")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -DSCANF_ADVANCED_ENABLE=0")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -g")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -O0")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -Wall")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -fno-common")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -ffunction-sections")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -fdata-sections")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -ffreestanding")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -fno-builtin")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -mthumb")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -mapcs")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -std=gnu99")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -mfloat-abi=hard")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -MMD")

SET(CMAKE_C_FLAGS_FLASH_DEBUG "${CMAKE_C_FLAGS_FLASH_DEBUG} -MP")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -DNDEBUG")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -DFSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -DENABLE_RAM_VECTOR_TABLE")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -DCPU_MCIMX7U5CVP05")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -DPRINTF_FLOAT_ENABLE=0")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -DSCANF_FLOAT_ENABLE=0")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -DPRINTF_ADVANCED_ENABLE=0")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -DSCANF_ADVANCED_ENABLE=0")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -Os")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -Wall")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -fno-common")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -ffunction-sections")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -fdata-sections")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -ffreestanding")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -fno-builtin")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -mthumb")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -mapcs")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -std=gnu99")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -mfloat-abi=hard")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -mfpu=fpv4-sp-d16")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -MMD")

SET(CMAKE_C_FLAGS_FLASH_RELEASE "${CMAKE_C_FLAGS_FLASH_RELEASE} -MP")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DCPU_MCIMX7U5CVP05")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-common")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ffunction-sections")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fdata-sections")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ffreestanding")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-builtin")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -mthumb")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -mapcs")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-rtti")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-exceptions")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -mfloat-abi=hard")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -MMD")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -MP")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DCPU_MCIMX7U5CVP05")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-common")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -ffunction-sections")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fdata-sections")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -ffreestanding")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-builtin")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mthumb")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mapcs")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-rtti")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-exceptions")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mfloat-abi=hard")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mfpu=fpv4-sp-d16")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -MMD")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -MP")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -DDEBUG")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -DFSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -DENABLE_RAM_VECTOR_TABLE")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -DCPU_MCIMX7U5CVP05")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -g")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -O0")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -Wall")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -fno-common")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -ffunction-sections")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -fdata-sections")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -ffreestanding")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -fno-builtin")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -mthumb")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -mapcs")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -fno-rtti")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -fno-exceptions")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -mfloat-abi=hard")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -MMD")

SET(CMAKE_CXX_FLAGS_FLASH_DEBUG "${CMAKE_CXX_FLAGS_FLASH_DEBUG} -MP")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -DNDEBUG")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -DFSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -DENABLE_RAM_VECTOR_TABLE")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -DCPU_MCIMX7U5CVP05")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -Os")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -Wall")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -fno-common")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -ffunction-sections")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -fdata-sections")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -ffreestanding")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -fno-builtin")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -mthumb")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -mapcs")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -fno-rtti")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -fno-exceptions")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -mfloat-abi=hard")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -mfpu=fpv4-sp-d16")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -MMD")

SET(CMAKE_CXX_FLAGS_FLASH_RELEASE "${CMAKE_CXX_FLAGS_FLASH_RELEASE} -MP")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -g")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} --specs=nano.specs")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} --specs=nosys.specs")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -Wall")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fno-common")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -ffunction-sections")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fdata-sections")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -ffreestanding")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fno-builtin")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -mthumb")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -mapcs")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} --gc-sections")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -static")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -z")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} muldefs")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -mfloat-abi=hard")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} --specs=nano.specs")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} --specs=nosys.specs")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Wall")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fno-common")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -ffunction-sections")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fdata-sections")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -ffreestanding")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fno-builtin")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -mthumb")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -mapcs")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} --gc-sections")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -static")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -z")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} muldefs")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -mfloat-abi=hard")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -mfpu=fpv4-sp-d16")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -g")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} --specs=nano.specs")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} --specs=nosys.specs")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -Wall")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -fno-common")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -ffunction-sections")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -fdata-sections")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -ffreestanding")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -fno-builtin")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -mthumb")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -mapcs")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} --gc-sections")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -static")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -z")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} muldefs")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -mfloat-abi=hard")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG "${CMAKE_EXE_LINKER_FLAGS_FLASH_DEBUG} --defsym=__ram_vector_table__=1")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} --specs=nano.specs")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} --specs=nosys.specs")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -Wall")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -fno-common")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -ffunction-sections")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -fdata-sections")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -ffreestanding")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -fno-builtin")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -mthumb")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -mapcs")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} --gc-sections")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -static")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -z")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} muldefs")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -mfloat-abi=hard")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -mfpu=fpv4-sp-d16")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE "${CMAKE_EXE_LINKER_FLAGS_FLASH_RELEASE} --defsym=__ram_vector_table__=1")

include_directories(${ProjDirPath}/../../../../../CMSIS/Include)

include_directories(${ProjDirPath}/../../../../../devices)

include_directories(${ProjDirPath}/../../..)

include_directories(${ProjDirPath}/..)

include_directories(${ProjDirPath}/../../../../../devices/MCIMX7U5/drivers)

include_directories(${ProjDirPath}/../../../../../devices/MCIMX7U5)

include_directories(${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/io)

include_directories(${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/str)

include_directories(${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/log)

include_directories(${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities)

add_library(hello_world.a STATIC 
"${ProjDirPath}/../fsl_iomuxc.h"
"${ProjDirPath}/../board.c"
"${ProjDirPath}/../board.h"
"${ProjDirPath}/../clock_config.c"
"${ProjDirPath}/../clock_config.h"
"${ProjDirPath}/../hello_world.c"
"${ProjDirPath}/../pin_mux.c"
"${ProjDirPath}/../pin_mux.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/drivers/fsl_clock.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/drivers/fsl_clock.c"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/drivers/fsl_common.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/drivers/fsl_common.c"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/io/fsl_io.c"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/io/fsl_io.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/log/fsl_log.c"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/log/fsl_log.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/str/fsl_str.c"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/str/fsl_str.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/fsl_debug_console.c"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/fsl_debug_console.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/fsl_debug_console_conf.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/system_MCIMX7U5_cm4.c"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/system_MCIMX7U5_cm4.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/gcc/startup_MCIMX7U5_cm4.S"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/drivers/fsl_lpuart.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/drivers/fsl_lpuart.c"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/drivers/fsl_gpio.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/drivers/fsl_gpio.c"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/drivers/fsl_msmc.h"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/drivers/fsl_msmc.c"
"${ProjDirPath}/../../../../../devices/MCIMX7U5/utilities/fsl_assert.c"
)

