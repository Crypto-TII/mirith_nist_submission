/*
 * Copyright 2023 Carlo Sanna, Javier Verbel, and Floyd Zweydinger.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CONFIG_H
#define CONFIG_H

#define MIRITH_MODE 12

/* Define this macro to run the implementation in SUPERCOP. */
/* #define MIRITH_SUPERCOP */

/* If this macro is defined, then the generation of random bytes is deterministic.
 * Otherwise, random bytes are generated by true randomness. */
#define MIRITH_DETERMINISTIC

#define CRYPTO_ALGNAME "MiRitH"

#ifdef MIRITH_SUPERCOP
#define MIRITH_NAMESPACETOP CRYPTO_NAMESPACETOP
#define MIRITH_NAMESPACE(s) CRYPTO_NAMESPACE(s)
#else
#define MIRITH_NAMESPACE(s) mirith_##s
#endif
#endif
