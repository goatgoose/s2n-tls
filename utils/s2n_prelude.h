/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#pragma once

/* Define the POSIX API we are targeting */
#ifndef _POSIX_C_SOURCE
    #define _POSIX_C_SOURCE 200809L
#endif

/**
 * If we're building in release mode make sure _FORTIFY_SOURCE is set
 * See: https://www.gnu.org/software/libc/manual/html_node/Source-Fortification.html
 */
#if !defined(_FORTIFY_SOURCE) && defined(S2N_BUILD_RELEASE)
    #define _FORTIFY_SOURCE 2
#endif

#if ((__GNUC__ >= 4) || defined(__clang__)) && defined(S2N_EXPORTS)
    /**
     * Marks a function as belonging to the public s2n API.
     *
     * See: https://gcc.gnu.org/wiki/Visibility
     */
    #define S2N_API __attribute__((visibility("default")))
#endif
