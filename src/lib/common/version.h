/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2018-2020, 2022-2023 NXP
 */

#ifndef __VERSION_H
#define __VERSION_H
/*===========================================================================*/
/**
    @file    version.h

    @brief   Version of the tool to be set from build system.
 */

#ifdef VERSION

#define XSTRINGIFY(v) #v
#define STRINGIFY(v) XSTRINGIFY(v)

#define CST_VERSION STRINGIFY(VERSION)
#else
#define CST_VERSION "dev"
#endif

#endif /* __VERSION_H */
