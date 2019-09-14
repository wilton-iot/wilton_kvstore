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
 * File:   wiltoncall_kvstore.cpp
 * Author: alex
 *
 * Created on September 12, 2019, 9:59 AM
 */

#include <string>

#include "wilton/wilton_kvstore.h"

#include "staticlib/io.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/registrar.hpp"
#include "wilton/support/shared_handle_registry.hpp"

namespace wilton {
namespace kvstore {

namespace { //anonymous

// initialized from wilton_module_init
std::shared_ptr<support::shared_handle_registry<wilton_KVStore>> store_registry() {
    static auto registry = std::make_shared<support::shared_handle_registry<wilton_KVStore>>(
            [](wilton_KVStore* store) STATICLIB_NOEXCEPT {
                wilton_KVStore_destroy(store);
            });
    return registry;
}

} // namespace

support::buffer create(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rfpath = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("filePath" == name) {
            rfpath = fi.as_string_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    // optional
    const std::string& fpath = rfpath.get();
    wilton_KVStore* store;
    char* err = wilton_KVStore_create(std::addressof(store),
            fpath.c_str(), static_cast<int>(fpath.length()));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    auto reg = store_registry();
    int64_t handle = reg->put(store);
    return support::make_json_buffer({
        { "kvstoreHandle", handle}
    });
}

support::buffer get(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    auto rkey = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else if ("key" == name) {
            rkey = fi.as_string_nonempty_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    if (rkey.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'key' not specified"));
    const std::string& key = rkey.get();
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    char* out = nullptr;
    int out_len = -1;
    auto err = wilton_KVStore_get(store.get(),
            key.c_str(), static_cast<int>(key.length()),
            std::addressof(out), std::addressof(out_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::wrap_wilton_buffer(out, out_len);
}

support::buffer get_batch(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    auto key_list = std::string();
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else if ("keyList" == name) {
            key_list = fi.val().dumps();
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    if (key_list.empty()) throw support::exception(TRACEMSG(
            "Required parameter 'keyList' not specified"));
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    char* out = nullptr;
    int out_len = -1;
    auto err = wilton_KVStore_get_batch(store.get(),
            key_list.c_str(), static_cast<int>(key_list.length()),
            std::addressof(out), std::addressof(out_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::wrap_wilton_buffer(out, out_len);
}

support::buffer put(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    auto rkey = std::ref(sl::utils::empty_string());
    auto value = std::string();
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else if ("key" == name) {
            rkey = fi.as_string_nonempty_or_throw(name);
        } else if ("value" == name) {
            value = fi.val().dumps();
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    if (rkey.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'key' not specified"));
    if (value.empty()) throw support::exception(TRACEMSG(
            "Required parameter 'value' not specified"));
    const std::string& key = rkey.get();
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    char* out = nullptr;
    int out_len = -1;
    auto err = wilton_KVStore_put(store.get(),
            key.c_str(), static_cast<int>(key.length()),
            value.c_str(), static_cast<int>(value.length()),
            std::addressof(out), std::addressof(out_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::wrap_wilton_buffer(out, out_len);
}

support::buffer put_batch(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    auto object = std::string();
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else if ("object" == name) {
            object = fi.val().dumps();
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    if (object.empty()) throw support::exception(TRACEMSG(
            "Required parameter 'object' not specified"));
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    char* out = nullptr;
    int out_len = -1;
    auto err = wilton_KVStore_put_batch(store.get(),
            object.c_str(), static_cast<int>(object.length()),
            std::addressof(out), std::addressof(out_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::wrap_wilton_buffer(out, out_len);
}

support::buffer append(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    auto rkey = std::ref(sl::utils::empty_string());
    auto values = std::string();
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else if ("key" == name) {
            rkey = fi.as_string_nonempty_or_throw(name);
        } else if ("values" == name) {
            values = fi.val().dumps();
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    if (rkey.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'key' not specified"));
    if (values.empty()) throw support::exception(TRACEMSG(
            "Required parameter 'values' not specified"));
    const std::string& key = rkey.get();
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    int key_existed = -1;
    auto err = wilton_KVStore_append(store.get(),
            key.c_str(), static_cast<int>(key.length()),
            values.c_str(), static_cast<int>(values.length()),
            std::addressof(key_existed));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::make_json_buffer({
        { "keyExisted", 1 == key_existed }
    });
}

support::buffer remove(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    auto rkey = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else if ("key" == name) {
            rkey = fi.as_string_nonempty_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    if (rkey.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'key' not specified"));
    const std::string& key = rkey.get();
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    int key_existed = -1;
    auto err = wilton_KVStore_remove(store.get(),
            key.c_str(), static_cast<int>(key.length()),
            std::addressof(key_existed));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::make_json_buffer({
        { "keyExisted", 1 == key_existed }
    });
}

support::buffer remove_batch(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    auto key_list = std::string();
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else if ("keyList" == name) {
            key_list = fi.val().dumps();
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    if (key_list.empty()) throw support::exception(TRACEMSG(
            "Required parameter 'keyList' not specified"));
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    char* out = nullptr;
    int out_len = -1;
    auto err = wilton_KVStore_remove_batch(store.get(),
            key_list.c_str(), static_cast<int>(key_list.length()),
            std::addressof(out), std::addressof(out_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::wrap_wilton_buffer(out, out_len);
}

support::buffer size(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    int size_out = -1;
    auto err = wilton_KVStore_size(store.get(), std::addressof(size_out));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::make_json_buffer({
        { "size", size_out }
    });
}

support::buffer keys(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    char* out = nullptr;
    int out_len = -1;
    auto err = wilton_KVStore_keys(store.get(),
            std::addressof(out), std::addressof(out_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::wrap_wilton_buffer(out, out_len);
}

support::buffer entries(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    char* out = nullptr;
    int out_len = -1;
    auto err = wilton_KVStore_entries(store.get(),
            std::addressof(out), std::addressof(out_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::wrap_wilton_buffer(out, out_len);
}

support::buffer persist(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    int count = -1;
    auto err = wilton_KVStore_persist(store.get(), std::addressof(count));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::make_json_buffer({
        { "persistedCount", count }
    });
}

support::buffer clear(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    // get handle
    auto reg = store_registry();
    auto store = reg->peek(handle);
    if (nullptr == store.get()) throw support::exception(TRACEMSG(
            "Invalid 'kvstoreHandle' parameter specified"));
    // call wilton
    int count = -1;
    auto err = wilton_KVStore_clear(store.get(), std::addressof(count));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::make_json_buffer({
        { "removedCount", count }
    });
}

support::buffer destroy(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("kvstoreHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'kvstoreHandle' not specified"));
    // get handle
    auto reg = store_registry();
    auto store = reg->remove(handle);

    // deleter is called at this point
    // if no other threads use this obj

    return support::make_null_buffer();
}

} // namespace
}

extern "C" char* wilton_module_init() {
    try {
        wilton::kvstore::store_registry();
        wilton::support::register_wiltoncall("kvstore_create", wilton::kvstore::create);
        wilton::support::register_wiltoncall("kvstore_get", wilton::kvstore::get);
        wilton::support::register_wiltoncall("kvstore_get_batch", wilton::kvstore::get_batch);
        wilton::support::register_wiltoncall("kvstore_put", wilton::kvstore::put);
        wilton::support::register_wiltoncall("kvstore_put_batch", wilton::kvstore::put_batch);
        wilton::support::register_wiltoncall("kvstore_append", wilton::kvstore::append);
        wilton::support::register_wiltoncall("kvstore_remove", wilton::kvstore::remove);
        wilton::support::register_wiltoncall("kvstore_remove_batch", wilton::kvstore::remove_batch);
        wilton::support::register_wiltoncall("kvstore_size", wilton::kvstore::size);
        wilton::support::register_wiltoncall("kvstore_keys", wilton::kvstore::keys);
        wilton::support::register_wiltoncall("kvstore_entries", wilton::kvstore::entries);
        wilton::support::register_wiltoncall("kvstore_persist", wilton::kvstore::persist);
        wilton::support::register_wiltoncall("kvstore_clear", wilton::kvstore::clear);
        wilton::support::register_wiltoncall("kvstore_destroy", wilton::kvstore::destroy);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}