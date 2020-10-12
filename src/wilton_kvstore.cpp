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
 * File:   wilton_kvstore.cpp
 * Author: alex
 *
 * Created on September 12, 2019, 9:59 AM
 */

#include <string>

#include "wilton/wilton_kvstore.h"

#include "wilton/support/logging.hpp"
#include "wilton/support/misc.hpp"

#include "kvstore.hpp"

namespace { // anonymous

const std::string logger = std::string("wilton.KVStore");

} // namespace

struct wilton_KVStore {
private:
    wilton::kvstore::kvstore store;

public:
    wilton_KVStore(wilton::kvstore::kvstore&& store) :
    store(std::move(store)) { }

    wilton::kvstore::kvstore& impl() {
        return store;
    }
};

char* wilton_KVStore_create(
        wilton_KVStore** store_out,
        const char* file_path,
        int file_path_len) /* noexcept */ {
    if (nullptr == store_out) return wilton::support::alloc_copy(TRACEMSG("Null 'store_out' parameter specified"));
    if (file_path_len > 0 && nullptr == file_path) return wilton::support::alloc_copy(TRACEMSG("Null 'file_path' parameter specified"));
    if (!sl::support::is_uint16(file_path_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'file_path_len' parameter specified: [" + sl::support::to_string(file_path_len) + "]"));
    try {
        auto file_path_str = file_path_len > 0 ? std::string(file_path, static_cast<uint16_t>(file_path_len)) : std::string();
        wilton::support::log_debug(logger, "Creating store, path: [" + file_path_str + "] ...");
        auto store = wilton::kvstore::kvstore(file_path_str);
        wilton_KVStore* store_ptr = new wilton_KVStore(std::move(store));
        wilton::support::log_debug(logger, std::string("Store created successfully,") +
                " handle: [" + wilton::support::strhandle(store_ptr) + "]," +
                " file path: [" + file_path_str + "]," +
                " entries loaded: [" + sl::support::to_string(store_ptr->impl().size()) + "]");
        *store_out = store_ptr;
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_get(
        wilton_KVStore* store,
        const char* key,
        int key_len,
        char** value_json_out,
        int* value_json_len_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == key) return wilton::support::alloc_copy(TRACEMSG("Null 'key' parameter specified"));
    if (!sl::support::is_uint16_positive(key_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'key_len' parameter specified: [" + sl::support::to_string(key_len) + "]"));
    if (nullptr == value_json_out) return wilton::support::alloc_copy(TRACEMSG("Null 'value_json_out' parameter specified"));
    if (nullptr == value_json_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'value_json_len_out' parameter specified"));
    try {
        auto key_str = std::string(key, static_cast<uint16_t>(key_len));
        auto val_json = store->impl().get(key_str);
        auto span = wilton::support::make_json_buffer(val_json);
        *value_json_out = span.data();
        *value_json_len_out = span.size_int();
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_get_batch(
        wilton_KVStore* store,
        const char* key_list_json,
        int key_list_json_len,
        char** value_json_out,
        int* value_json_len_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == key_list_json) return wilton::support::alloc_copy(TRACEMSG("Null 'key_list_json' parameter specified"));
    if (!sl::support::is_uint16_positive(key_list_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'key_list_json_len' parameter specified: [" + sl::support::to_string(key_list_json_len) + "]"));
    if (nullptr == value_json_out) return wilton::support::alloc_copy(TRACEMSG("Null 'value_json_out' parameter specified"));
    if (nullptr == value_json_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'value_json_len_out' parameter specified"));
    try {
        auto obj = sl::json::load({key_list_json, key_list_json_len});
        auto& vec = obj.as_array_or_throw("getBatch");
        auto res_vec = store->impl().get_batch(vec);
        auto res_json = sl::json::value(std::move(res_vec));
        auto span = wilton::support::make_json_buffer(res_json);
        *value_json_out = span.data();
        *value_json_len_out = span.size_int();
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_put(
        wilton_KVStore* store,
        const char* key,
        int key_len,
        const char* value_json,
        int value_json_len,
        char** res_json_out,
        int* res_json_len_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == key) return wilton::support::alloc_copy(TRACEMSG("Null 'key' parameter specified"));
    if (!sl::support::is_uint16_positive(key_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'key_len' parameter specified: [" + sl::support::to_string(key_len) + "]"));
    if (nullptr == value_json) return wilton::support::alloc_copy(TRACEMSG("Null 'value_json' parameter specified"));
    if (!sl::support::is_uint32_positive(value_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'value_json_len' parameter specified: [" + sl::support::to_string(value_json_len) + "]"));
    if (nullptr == res_json_out) return wilton::support::alloc_copy(TRACEMSG("Null 'res_json_out' parameter specified"));
    if (nullptr == res_json_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'res_json_len_out' parameter specified"));
    try {
        auto key_str = std::string(key, static_cast<uint16_t>(key_len));
        auto val = sl::json::load({value_json, value_json_len});
        auto res_json = store->impl().put(key_str, std::move(val));
        auto span = wilton::support::make_json_buffer(res_json);
        *res_json_out = span.data();
        *res_json_len_out = span.size_int();
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_put_batch(
        wilton_KVStore* store,
        const char* object_json,
        int object_json_len,
        char** res_json_out,
        int* res_json_len_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == object_json) return wilton::support::alloc_copy(TRACEMSG("Null 'object_json' parameter specified"));
    if (!sl::support::is_uint32_positive(object_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'object_json_len' parameter specified: [" + sl::support::to_string(object_json_len) + "]"));
    if (nullptr == res_json_out) return wilton::support::alloc_copy(TRACEMSG("Null 'res_json_out' parameter specified"));
    if (nullptr == res_json_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'res_json_len_out' parameter specified"));
    try {
        auto obj = sl::json::load({object_json, object_json_len});
        auto& vec = obj.as_object_or_throw("putBatch");
        auto res_vec = store->impl().put_batch(std::move(vec));
        auto res_json = sl::json::value(std::move(res_vec));
        auto span = wilton::support::make_json_buffer(res_json);
        *res_json_out = span.data();
        *res_json_len_out = span.size_int();
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_append(
        wilton_KVStore* store,
        const char* key,
        int key_len,
        const char* value_list_json,
        int value_list_json_len,
        int* key_existed_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == key) return wilton::support::alloc_copy(TRACEMSG("Null 'key' parameter specified"));
    if (!sl::support::is_uint16_positive(key_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'key_len' parameter specified: [" + sl::support::to_string(key_len) + "]"));
    if (nullptr == value_list_json) return wilton::support::alloc_copy(TRACEMSG("Null 'value_list_json' parameter specified"));
    if (!sl::support::is_uint32_positive(value_list_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'value_list_json_len' parameter specified: [" + sl::support::to_string(value_list_json_len) + "]"));
    if (nullptr == key_existed_out) return wilton::support::alloc_copy(TRACEMSG("Null 'key_existed_out' parameter specified"));
    try {
        auto key_str = std::string(key, static_cast<uint16_t>(key_len));
        auto val = sl::json::load({value_list_json, value_list_json_len});
        auto& vec = val.as_array_or_throw(key);
        auto key_existed = store->impl().append(key_str, std::move(vec));
        *key_existed_out = key_existed ? 1 : 0;
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_dequeue(
        wilton_KVStore* store,
        const char* key,
        int key_len,
        int count,
        int* dequeued_count_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == key) return wilton::support::alloc_copy(TRACEMSG("Null 'key' parameter specified"));
    if (!sl::support::is_uint16_positive(key_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'key_len' parameter specified: [" + sl::support::to_string(key_len) + "]"));
    if (!sl::support::is_uint32(count)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'count' parameter specified: [" + sl::support::to_string(count) + "]"));
    if (nullptr == dequeued_count_out) return wilton::support::alloc_copy(TRACEMSG("Null 'count_dequeued_out' parameter specified"));
    try {
        auto key_str = std::string(key, static_cast<uint16_t>(key_len));
        auto count_u32 = static_cast<uint32_t>(count);
        auto res = store->impl().dequeue(key, count_u32);
        *dequeued_count_out = static_cast<int>(res);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_remove(
        wilton_KVStore* store,
        const char* key,
        int key_len,
        int* key_existed_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == key) return wilton::support::alloc_copy(TRACEMSG("Null 'key' parameter specified"));
    if (!sl::support::is_uint16_positive(key_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'key_len' parameter specified: [" + sl::support::to_string(key_len) + "]"));
    if (nullptr == key_existed_out) return wilton::support::alloc_copy(TRACEMSG("Null 'key_existed_out' parameter specified"));
    try {
        auto key_str = std::string(key, static_cast<uint16_t>(key_len));
        auto removed = store->impl().remove(key_str);
        *key_existed_out = removed ? 1 : 0;
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_remove_batch(
        wilton_KVStore* store,
        const char* key_list_json,
        int key_list_json_len,
        char** res_json_out,
        int* res_json_len_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == key_list_json) return wilton::support::alloc_copy(TRACEMSG("Null 'key_list_json' parameter specified"));
    if (!sl::support::is_uint16_positive(key_list_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'key_list_json_len' parameter specified: [" + sl::support::to_string(key_list_json_len) + "]"));
    if (nullptr == res_json_out) return wilton::support::alloc_copy(TRACEMSG("Null 'res_json_out' parameter specified"));
    if (nullptr == res_json_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'res_json_len_out' parameter specified"));
    try {
        auto obj = sl::json::load({key_list_json, key_list_json_len});
        auto& vec = obj.as_array_or_throw("removeBatch");
        auto res_vec = store->impl().remove_batch(vec);
        auto res_json = sl::json::value(std::move(res_vec));
        auto span = wilton::support::make_json_buffer(res_json);
        *res_json_out = span.data();
        *res_json_len_out = span.size_int();
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_size(wilton_KVStore* store, int* size_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == size_out) return wilton::support::alloc_copy(TRACEMSG("Null 'size_out' parameter specified"));
    try {
        auto size = store->impl().size();
        *size_out = static_cast<int>(size);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_keys(
        wilton_KVStore* store,
        char** keys_json_out,
        int* keys_json_len_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == keys_json_out) return wilton::support::alloc_copy(TRACEMSG("Null 'keys_json_out' parameter specified"));
    if (nullptr == keys_json_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'keys_json_len_out' parameter specified"));
    try {
        auto res_vec = store->impl().keys();
        auto res_json = sl::json::value(std::move(res_vec));
        auto span = wilton::support::make_json_buffer(res_json);
        *keys_json_out = span.data();
        *keys_json_len_out = span.size_int();
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_entries(
        wilton_KVStore* store,
        char** entries_json_out,
        int* entries_json_len_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == entries_json_out) return wilton::support::alloc_copy(TRACEMSG("Null 'entries_json_out' parameter specified"));
    if (nullptr == entries_json_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'entries_json_len_out' parameter specified"));
    try {
        auto res_vec = store->impl().entries();
        auto res_json = sl::json::value(std::move(res_vec));
        auto span = wilton::support::make_json_buffer(res_json);
        *entries_json_out = span.data();
        *entries_json_len_out = span.size_int();
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_persist(wilton_KVStore* store, int* entries_persisted_count_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == entries_persisted_count_out) return wilton::support::alloc_copy(TRACEMSG("Null 'entries_persisted_count_out' parameter specified"));
    try {
        wilton::support::log_debug(logger, std::string("Is due to persist store,") +
                " handle: [" + wilton::support::strhandle(store) + "]," +
                " path: [" + store->impl().filepath() + "] ...");
        auto count = store->impl().persist();
        wilton::support::log_debug(logger, std::string("Store persisted successfully,") +
                " entries count: [" + sl::support::to_string(count) + "]");
        *entries_persisted_count_out = static_cast<int>(count);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_clear(wilton_KVStore* store,int* entries_removed_count_out) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    if (nullptr == entries_removed_count_out) return wilton::support::alloc_copy(TRACEMSG(
            "Null 'entries_removed_count_out' parameter specified"));
    try {
        wilton::support::log_debug(logger, std::string("Is due to clear store,") +
                " handle: [" + wilton::support::strhandle(store) + "]," +
                " path: [" + store->impl().filepath() + "] ...");
        auto count = store->impl().clear();
        wilton::support::log_debug(logger, std::string("Store cleared successfully,") +
                " entries removed: [" + sl::support::to_string(count) + "]");
        *entries_removed_count_out = static_cast<int>(count);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_KVStore_destroy(wilton_KVStore* store) /* noexcept */ {
    if (nullptr == store) return wilton::support::alloc_copy(TRACEMSG("Null 'store' parameter specified"));
    try {
        wilton::support::log_debug(logger, std::string("Is due to destory store,") +
                " handle: [" + wilton::support::strhandle(store) + "]," +
                " path: [" + store->impl().filepath() + "]," +
                " size: [" + sl::support::to_string(store->impl().size()) + "] ...");
        delete store;
        wilton::support::log_debug(logger, "Store destroyed successfully");
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}