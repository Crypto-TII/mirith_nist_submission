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

#ifndef MATRIX_CONSTANTS_H
#define MATRIX_CONSTANTS_H

#include "params.h"

#if PAR_Q == 16

/* Matrices are stored in column-major order (which makes horizontal
 * concatenation and splitting faster). 
 * The finite field F_16 is identified with F_2[X] / (X^4 + X + 1), and
 * each element a_3 X^3 + a_2 X^2 + a_1 X + a_0 of F_16 is represented
 * by the 4-bits word a_3 | a_2 | a_1 | a_0 (LSB), 
 */

/* Type for an element of the finite field. */
typedef uint8_t ff_t;

const ff_t __gf16_mul[512] __attribute__((aligned(32))) = {
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 
0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f, 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f, 
0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e, 0x03,0x01,0x07,0x05,0x0b,0x09,0x0f,0x0d, 0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e, 0x03,0x01,0x07,0x05,0x0b,0x09,0x0f,0x0d, 
0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09, 0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02, 0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09, 0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02, 
0x00,0x04,0x08,0x0c,0x03,0x07,0x0b,0x0f, 0x06,0x02,0x0e,0x0a,0x05,0x01,0x0d,0x09, 0x00,0x04,0x08,0x0c,0x03,0x07,0x0b,0x0f, 0x06,0x02,0x0e,0x0a,0x05,0x01,0x0d,0x09, 
0x00,0x05,0x0a,0x0f,0x07,0x02,0x0d,0x08, 0x0e,0x0b,0x04,0x01,0x09,0x0c,0x03,0x06, 0x00,0x05,0x0a,0x0f,0x07,0x02,0x0d,0x08, 0x0e,0x0b,0x04,0x01,0x09,0x0c,0x03,0x06, 
0x00,0x06,0x0c,0x0a,0x0b,0x0d,0x07,0x01, 0x05,0x03,0x09,0x0f,0x0e,0x08,0x02,0x04, 0x00,0x06,0x0c,0x0a,0x0b,0x0d,0x07,0x01, 0x05,0x03,0x09,0x0f,0x0e,0x08,0x02,0x04, 
0x00,0x07,0x0e,0x09,0x0f,0x08,0x01,0x06, 0x0d,0x0a,0x03,0x04,0x02,0x05,0x0c,0x0b, 0x00,0x07,0x0e,0x09,0x0f,0x08,0x01,0x06, 0x0d,0x0a,0x03,0x04,0x02,0x05,0x0c,0x0b, 
0x00,0x08,0x03,0x0b,0x06,0x0e,0x05,0x0d, 0x0c,0x04,0x0f,0x07,0x0a,0x02,0x09,0x01, 0x00,0x08,0x03,0x0b,0x06,0x0e,0x05,0x0d, 0x0c,0x04,0x0f,0x07,0x0a,0x02,0x09,0x01, 
0x00,0x09,0x01,0x08,0x02,0x0b,0x03,0x0a, 0x04,0x0d,0x05,0x0c,0x06,0x0f,0x07,0x0e, 0x00,0x09,0x01,0x08,0x02,0x0b,0x03,0x0a, 0x04,0x0d,0x05,0x0c,0x06,0x0f,0x07,0x0e, 
0x00,0x0a,0x07,0x0d,0x0e,0x04,0x09,0x03, 0x0f,0x05,0x08,0x02,0x01,0x0b,0x06,0x0c, 0x00,0x0a,0x07,0x0d,0x0e,0x04,0x09,0x03, 0x0f,0x05,0x08,0x02,0x01,0x0b,0x06,0x0c, 
0x00,0x0b,0x05,0x0e,0x0a,0x01,0x0f,0x04, 0x07,0x0c,0x02,0x09,0x0d,0x06,0x08,0x03, 0x00,0x0b,0x05,0x0e,0x0a,0x01,0x0f,0x04, 0x07,0x0c,0x02,0x09,0x0d,0x06,0x08,0x03, 
0x00,0x0c,0x0b,0x07,0x05,0x09,0x0e,0x02, 0x0a,0x06,0x01,0x0d,0x0f,0x03,0x04,0x08, 0x00,0x0c,0x0b,0x07,0x05,0x09,0x0e,0x02, 0x0a,0x06,0x01,0x0d,0x0f,0x03,0x04,0x08, 
0x00,0x0d,0x09,0x04,0x01,0x0c,0x08,0x05, 0x02,0x0f,0x0b,0x06,0x03,0x0e,0x0a,0x07, 0x00,0x0d,0x09,0x04,0x01,0x0c,0x08,0x05, 0x02,0x0f,0x0b,0x06,0x03,0x0e,0x0a,0x07, 
0x00,0x0e,0x0f,0x01,0x0d,0x03,0x02,0x0c, 0x09,0x07,0x06,0x08,0x04,0x0a,0x0b,0x05, 0x00,0x0e,0x0f,0x01,0x0d,0x03,0x02,0x0c, 0x09,0x07,0x06,0x08,0x04,0x0a,0x0b,0x05, 
0x00,0x0f,0x0d,0x02,0x09,0x06,0x04,0x0b, 0x01,0x0e,0x0c,0x03,0x08,0x07,0x05,0x0a, 0x00,0x0f,0x0d,0x02,0x09,0x06,0x04,0x0b, 0x01,0x0e,0x0c,0x03,0x08,0x07,0x05,0x0a, 
};



const ff_t __gf16_mulbase[128] __attribute__((aligned(32))) = {
0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f, 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f, 
0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e, 0x03,0x01,0x07,0x05,0x0b,0x09,0x0f,0x0d, 0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e, 0x03,0x01,0x07,0x05,0x0b,0x09,0x0f,0x0d, 
0x00,0x04,0x08,0x0c,0x03,0x07,0x0b,0x0f, 0x06,0x02,0x0e,0x0a,0x05,0x01,0x0d,0x09, 0x00,0x04,0x08,0x0c,0x03,0x07,0x0b,0x0f, 0x06,0x02,0x0e,0x0a,0x05,0x01,0x0d,0x09, 
0x00,0x08,0x03,0x0b,0x06,0x0e,0x05,0x0d, 0x0c,0x04,0x0f,0x07,0x0a,0x02,0x09,0x01, 0x00,0x08,0x03,0x0b,0x06,0x0e,0x05,0x0d, 0x0c,0x04,0x0f,0x07,0x0a,0x02,0x09,0x01, 
};

#else

#error "Finite field not implemented!"

#endif

#endif
