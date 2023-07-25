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

#include <openssl/hmac.h>

#define TEST_BUFFER_SIZE 64

int main()
{
    uint8_t buffer[TEST_BUFFER_SIZE] = { 0 };
    unsigned int out_len = TEST_BUFFER_SIZE;
    HMAC_CTX *ctx = NULL;

    HMAC_Init_ex(ctx, buffer, TEST_BUFFER_SIZE, EVP_sha1(), NULL);
    HMAC_Update(ctx, buffer, TEST_BUFFER_SIZE);
    HMAC_Final(ctx, buffer, &out_len);
    size_t size = HMAC_size(ctx);
    HMAC_CTX_copy_ex(ctx, ctx);
    HMAC_CTX_reset(ctx);
    HMAC_CTX_cleanup(ctx);

    return 0;
}