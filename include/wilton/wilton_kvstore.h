/*
 * Copyright 2019, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   wilton_kvstore.h
 * Author: alex
 *
 * Created on September 12, 2019, 10:03 AM
 */

#ifndef WILTON_KVSTORE_H
#define WILTON_KVSTORE_H

#ifdef __cplusplus
extern "C" {
#endif

struct wilton_KVStore;
typedef struct wilton_KVStore wilton_KVStore;

char* wilton_KVStore_create(
        wilton_KVStore** store_out,
        const char* file_path,
        int file_path_len);

char* wilton_KVStore_get(
        wilton_KVStore* store,
        const char* key,
        int key_len,
        char** value_json_out,
        int* value_json_len_out);

char* wilton_KVStore_get_batch(
        wilton_KVStore* store,
        const char* key_list_json,
        int key_list_json_len,
        char** value_json_out,
        int* value_json_len_out);

char* wilton_KVStore_put(
        wilton_KVStore* store,
        const char* key,
        int key_len,
        const char* value_json,
        int value_json_len,
        char** res_json_out,
        int* res_json_len_out);

char* wilton_KVStore_put_batch(
        wilton_KVStore* store,
        const char* object_json,
        int object_json_len,
        char** res_json_out,
        int* res_json_len_out);

char* wilton_KVStore_append(
        wilton_KVStore* store,
        const char* key,
        int key_len,
        const char* value_list_json,
        int value_list_json_len,
        int* key_existed_out);

char* wilton_KVStore_dequeue(
        wilton_KVStore* store,
        const char* key,
        int key_len,
        int count,
        int* dequeued_count_out);

char* wilton_KVStore_remove(
        wilton_KVStore* store,
        const char* key,
        int key_len,
        int* key_existed_out);

char* wilton_KVStore_remove_batch(
        wilton_KVStore* store,
        const char* key_list_json,
        int key_list_json_len,
        char** res_json_out,
        int* res_json_len_out);

char* wilton_KVStore_size(
        wilton_KVStore* store,
        int* size_out);

char* wilton_KVStore_keys(
        wilton_KVStore* store,
        char** keys_json_out,
        int* keys_json_len_out);

char* wilton_KVStore_entries(
        wilton_KVStore* store,
        char** entries_json_out,
        int* entries_json_len_out);

char* wilton_KVStore_persist(
        wilton_KVStore* store,
        int* entries_persisted_count_out);

char* wilton_KVStore_clear(
        wilton_KVStore* store,
        int* entries_removed_count_out);

char* wilton_KVStore_destroy(
        wilton_KVStore* store);

#ifdef __cplusplus
}
#endif

#endif /* WILTON_KVSTORE_H */

