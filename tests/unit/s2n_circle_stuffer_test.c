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

#include "stuffer/s2n_circle_stuffer.h"

#include "s2n_test.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_circle_stuffer_write tests */
    {
        uint8_t test_data[100] = { 0 };
        struct s2n_blob test_data_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
        EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

        for (int start_pos = 0; start_pos < sizeof(test_data); start_pos++) {
            for (int len = 0; len < sizeof(test_data); len++) {
                uint8_t stuffer_data[sizeof(test_data)] = { 0 };
                struct s2n_blob stuffer_blob = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&stuffer_blob, stuffer_data, sizeof(stuffer_data)));
                struct s2n_circle_stuffer stuffer = { 0 };
                EXPECT_OK(s2n_circle_stuffer_init(&stuffer, &stuffer_blob));

                struct s2n_blob test_blob = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&test_blob, test_data, len));

                /* TODO: skip read/write */
                stuffer.read_pos = start_pos;
                stuffer.write_pos = start_pos;

//                printf("\nstart_pos: %d\n", start_pos);
//                printf("len: %d\n", len);

                EXPECT_OK(s2n_circle_stuffer_write(&stuffer, &test_blob));

                uint32_t chunk_1_end_pos = MIN(len, sizeof(test_data) - start_pos);
                EXPECT_BYTEARRAY_EQUAL(stuffer_data + start_pos, test_data, chunk_1_end_pos);

                uint32_t chunk_2_end_pos = len - chunk_1_end_pos;
                if (chunk_2_end_pos > 0) {
                    EXPECT_BYTEARRAY_EQUAL(stuffer_data, test_data + chunk_1_end_pos, chunk_2_end_pos);
                }
            }
        }
    }

    END_TEST();
}