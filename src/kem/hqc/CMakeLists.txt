# SPDX-License-Identifier: MIT

# This file was generated by
# scripts/copy_from_pqclean/copy_from_pqclean.py

if(OQS_ENABLE_KEM_hqc_128_1_cca2)
    add_library(hqc_128_1_cca2_leaktime OBJECT kem_hqc_128_1_cca2.c pqclean_hqc-128-1-cca2_leaktime/bch.c pqclean_hqc-128-1-cca2_leaktime/fft.c pqclean_hqc-128-1-cca2_leaktime/gf.c pqclean_hqc-128-1-cca2_leaktime/gf2x.c pqclean_hqc-128-1-cca2_leaktime/hqc.c pqclean_hqc-128-1-cca2_leaktime/kem.c pqclean_hqc-128-1-cca2_leaktime/parsing.c pqclean_hqc-128-1-cca2_leaktime/repetition.c pqclean_hqc-128-1-cca2_leaktime/tensor.c pqclean_hqc-128-1-cca2_leaktime/util.c pqclean_hqc-128-1-cca2_leaktime/vector.c)
    target_include_directories(hqc_128_1_cca2_leaktime PRIVATE ${CMAKE_CURRENT_LIST_DIR}/pqclean_hqc-128-1-cca2_leaktime)
    target_include_directories(hqc_128_1_cca2_leaktime PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    set(_HQC_OBJS ${_HQC_OBJS} $<TARGET_OBJECTS:hqc_128_1_cca2_leaktime>)
endif()

if(OQS_ENABLE_KEM_hqc_192_1_cca2)
    add_library(hqc_192_1_cca2_leaktime OBJECT kem_hqc_192_1_cca2.c pqclean_hqc-192-1-cca2_leaktime/bch.c pqclean_hqc-192-1-cca2_leaktime/fft.c pqclean_hqc-192-1-cca2_leaktime/gf.c pqclean_hqc-192-1-cca2_leaktime/gf2x.c pqclean_hqc-192-1-cca2_leaktime/hqc.c pqclean_hqc-192-1-cca2_leaktime/kem.c pqclean_hqc-192-1-cca2_leaktime/parsing.c pqclean_hqc-192-1-cca2_leaktime/repetition.c pqclean_hqc-192-1-cca2_leaktime/tensor.c pqclean_hqc-192-1-cca2_leaktime/util.c pqclean_hqc-192-1-cca2_leaktime/vector.c)
    target_include_directories(hqc_192_1_cca2_leaktime PRIVATE ${CMAKE_CURRENT_LIST_DIR}/pqclean_hqc-192-1-cca2_leaktime)
    target_include_directories(hqc_192_1_cca2_leaktime PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    set(_HQC_OBJS ${_HQC_OBJS} $<TARGET_OBJECTS:hqc_192_1_cca2_leaktime>)
endif()

if(OQS_ENABLE_KEM_hqc_192_2_cca2)
    add_library(hqc_192_2_cca2_leaktime OBJECT kem_hqc_192_2_cca2.c pqclean_hqc-192-2-cca2_leaktime/bch.c pqclean_hqc-192-2-cca2_leaktime/fft.c pqclean_hqc-192-2-cca2_leaktime/gf.c pqclean_hqc-192-2-cca2_leaktime/gf2x.c pqclean_hqc-192-2-cca2_leaktime/hqc.c pqclean_hqc-192-2-cca2_leaktime/kem.c pqclean_hqc-192-2-cca2_leaktime/parsing.c pqclean_hqc-192-2-cca2_leaktime/repetition.c pqclean_hqc-192-2-cca2_leaktime/tensor.c pqclean_hqc-192-2-cca2_leaktime/util.c pqclean_hqc-192-2-cca2_leaktime/vector.c)
    target_include_directories(hqc_192_2_cca2_leaktime PRIVATE ${CMAKE_CURRENT_LIST_DIR}/pqclean_hqc-192-2-cca2_leaktime)
    target_include_directories(hqc_192_2_cca2_leaktime PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    set(_HQC_OBJS ${_HQC_OBJS} $<TARGET_OBJECTS:hqc_192_2_cca2_leaktime>)
endif()

if(OQS_ENABLE_KEM_hqc_256_1_cca2)
    add_library(hqc_256_1_cca2_leaktime OBJECT kem_hqc_256_1_cca2.c pqclean_hqc-256-1-cca2_leaktime/bch.c pqclean_hqc-256-1-cca2_leaktime/fft.c pqclean_hqc-256-1-cca2_leaktime/gf.c pqclean_hqc-256-1-cca2_leaktime/gf2x.c pqclean_hqc-256-1-cca2_leaktime/hqc.c pqclean_hqc-256-1-cca2_leaktime/kem.c pqclean_hqc-256-1-cca2_leaktime/parsing.c pqclean_hqc-256-1-cca2_leaktime/repetition.c pqclean_hqc-256-1-cca2_leaktime/tensor.c pqclean_hqc-256-1-cca2_leaktime/util.c pqclean_hqc-256-1-cca2_leaktime/vector.c)
    target_include_directories(hqc_256_1_cca2_leaktime PRIVATE ${CMAKE_CURRENT_LIST_DIR}/pqclean_hqc-256-1-cca2_leaktime)
    target_include_directories(hqc_256_1_cca2_leaktime PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    set(_HQC_OBJS ${_HQC_OBJS} $<TARGET_OBJECTS:hqc_256_1_cca2_leaktime>)
endif()

if(OQS_ENABLE_KEM_hqc_256_2_cca2)
    add_library(hqc_256_2_cca2_leaktime OBJECT kem_hqc_256_2_cca2.c pqclean_hqc-256-2-cca2_leaktime/bch.c pqclean_hqc-256-2-cca2_leaktime/fft.c pqclean_hqc-256-2-cca2_leaktime/gf.c pqclean_hqc-256-2-cca2_leaktime/gf2x.c pqclean_hqc-256-2-cca2_leaktime/hqc.c pqclean_hqc-256-2-cca2_leaktime/kem.c pqclean_hqc-256-2-cca2_leaktime/parsing.c pqclean_hqc-256-2-cca2_leaktime/repetition.c pqclean_hqc-256-2-cca2_leaktime/tensor.c pqclean_hqc-256-2-cca2_leaktime/util.c pqclean_hqc-256-2-cca2_leaktime/vector.c)
    target_include_directories(hqc_256_2_cca2_leaktime PRIVATE ${CMAKE_CURRENT_LIST_DIR}/pqclean_hqc-256-2-cca2_leaktime)
    target_include_directories(hqc_256_2_cca2_leaktime PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    set(_HQC_OBJS ${_HQC_OBJS} $<TARGET_OBJECTS:hqc_256_2_cca2_leaktime>)
endif()

if(OQS_ENABLE_KEM_hqc_256_3_cca2)
    add_library(hqc_256_3_cca2_leaktime OBJECT kem_hqc_256_3_cca2.c pqclean_hqc-256-3-cca2_leaktime/bch.c pqclean_hqc-256-3-cca2_leaktime/fft.c pqclean_hqc-256-3-cca2_leaktime/gf.c pqclean_hqc-256-3-cca2_leaktime/gf2x.c pqclean_hqc-256-3-cca2_leaktime/hqc.c pqclean_hqc-256-3-cca2_leaktime/kem.c pqclean_hqc-256-3-cca2_leaktime/parsing.c pqclean_hqc-256-3-cca2_leaktime/repetition.c pqclean_hqc-256-3-cca2_leaktime/tensor.c pqclean_hqc-256-3-cca2_leaktime/util.c pqclean_hqc-256-3-cca2_leaktime/vector.c)
    target_include_directories(hqc_256_3_cca2_leaktime PRIVATE ${CMAKE_CURRENT_LIST_DIR}/pqclean_hqc-256-3-cca2_leaktime)
    target_include_directories(hqc_256_3_cca2_leaktime PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    set(_HQC_OBJS ${_HQC_OBJS} $<TARGET_OBJECTS:hqc_256_3_cca2_leaktime>)
endif()

set(HQC_OBJS ${_HQC_OBJS} PARENT_SCOPE)
