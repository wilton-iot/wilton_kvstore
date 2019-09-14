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
 * File:   kvstore.cpp
 * Author: alex
 *
 * Created on September 12, 2019, 7:19 PM
 */

#include "kvstore.hpp"

#include <iterator>
#include <limits>
#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>

#include "staticlib/io.hpp"
#include "staticlib/pimpl/forward_macros.hpp"
#include "staticlib/tinydir.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/exception.hpp"

namespace wilton {
namespace kvstore {

namespace { // anonymous

using entry_type = std::pair<sl::json::value, std::list<std::string>::iterator>;

} // namespace

class kvstore::impl : public staticlib::pimpl::object::impl {
    const std::string fpath;

    std::mutex mutex;
    std::unordered_map<std::string, entry_type> registry;
    std::list<std::string> key_registry;

public:
    impl(const std::string& file_path) :
    fpath(file_path.data(), file_path.length()) {
        if (!fpath.empty()) {
            auto path = sl::tinydir::path(fpath);
            if (path.exists()) {
                load_from_file();
            } else {
                // write empty file
                save_to_file();
            }
        }
    }

    ~impl() STATICLIB_NOEXCEPT {
        try {
            std::lock_guard<std::mutex> guard{mutex};
            save_to_file();
        } catch(...) {
            // ignore
        }
    }

    sl::json::value get(kvstore&, const std::string& key) {
        std::lock_guard<std::mutex> guard{mutex};
        auto it = registry.find(key);
        if (registry.end() != it) {
            auto& en = it->second;
            return en.first.clone();
        } else {
            return sl::json::value();
        }
    }

    std::vector<sl::json::field> get_batch(kvstore&, const std::vector<sl::json::value>& keys) {
        std::lock_guard<std::mutex> guard{mutex};
        auto res = std::vector<sl::json::field>();
        for (auto& en : keys) {
            auto& key = en.as_string_nonempty_or_throw();
            auto it = registry.find(key);
            if (registry.end() != it) {
                auto& en = it->second;
                res.emplace_back(key, en.first.clone());
            }
        }
        return res;
    }

    sl::json::value put(kvstore&, const std::string& key, sl::json::value value) {
        std::lock_guard<std::mutex> guard{mutex};
        return put_entry(key, std::move(value));
    }

    std::vector<sl::json::field> put_batch(kvstore&, std::vector<sl::json::field> entries) {
        std::lock_guard<std::mutex> guard{mutex};
        auto res = std::vector<sl::json::field>();
        for (auto& fi : entries) {
            auto prev = put_entry(fi.name(), std::move(fi.val()));
            if (sl::json::type::nullt != prev.json_type()) {
                res.emplace_back(fi.name(), std::move(prev));
            }
        }
        return res;
    }

    bool append(kvstore&, const std::string& key, std::vector<sl::json::value> values) {
        // perform append
        std::lock_guard<std::mutex> guard{mutex};
        auto it = registry.find(key);
        if (registry.end() != it) {
            auto& en = it->second;
            auto& el = en.first;
            auto& vec = el.as_array_or_throw(key);
            for (auto& val : values) {
                vec.emplace_back(std::move(val));
            }
            return true;
        } else {
            // key reg
            key_registry.push_back(key);
            auto key_it = key_registry.end();
            std::advance(key_it, -1);
            // reg
            auto val = sl::json::value(std::move(values));
            auto en = std::make_pair(std::move(val), key_it);
            registry.insert(std::make_pair(key, std::move(en)));
            return false;
        }
    }

    bool remove(kvstore&, const std::string& key) {
        std::lock_guard<std::mutex> guard{mutex};
        return remove_entry(key);
    }

    std::vector<sl::json::value> remove_batch(kvstore&, const std::vector<sl::json::value>& keys) {
        std::lock_guard<std::mutex> guard{mutex};
        auto res = std::vector<sl::json::value>();
        for (auto& el : keys) {
            auto key = el.as_string_nonempty_or_throw("removeBatch");
            auto existed = remove_entry(key);
            if (existed) {
                res.push_back(key);
            }
        }
        return res;
    }

    uint32_t size(kvstore&) {
        std::lock_guard<std::mutex> guard{mutex};
        return static_cast<uint32_t>(registry.size());
    }

    std::vector<sl::json::value> keys(kvstore&) {
        std::lock_guard<std::mutex> guard{mutex};
        auto res = std::vector<sl::json::value>();
        for (auto& key : key_registry) {
            res.emplace_back(key);
        }
        return res;
    }

    std::vector<sl::json::field> entries(kvstore&) {
        std::lock_guard<std::mutex> guard{mutex};
        auto res = std::vector<sl::json::field>();
        for (auto& key : key_registry) {
            // always there
            auto it = registry.find(key);
            auto& en = it->second;
            res.emplace_back(key, en.first.clone());
        }
        return res;
    }

    uint32_t persist(kvstore&) {
        std::lock_guard<std::mutex> guard{mutex};
        return save_to_file();
    }

    uint32_t clear(kvstore&) {
        std::lock_guard<std::mutex> guard{mutex};
        auto res = registry.size();
        registry.clear();
        key_registry.clear();
        if (!fpath.empty()) {
            save_to_file();
        }
        return static_cast<uint32_t>(res);
    }

    const std::string& filepath(const kvstore&) const {
        return fpath;
    }

private:
    sl::json::value put_entry(const std::string& key, sl::json::value value) {
        // check object or array
        if (!(sl::json::type::object == value.json_type() ||
                sl::json::type::array == value.json_type())) throw support::exception(TRACEMSG(
                "Invalid value, type must be 'Object' or 'Array'," +
                " key: [" + key + "]" +
                " specified type: [" + sl::json::stringify_json_type(value.json_type()) + "]"));
        // check size
        if (registry.size() >= std::numeric_limits<uint32_t>::max()) {
            throw support::exception(TRACEMSG("Store size limit exceeded," +
                    " size: [" + sl::support::to_string(registry.size()) + "]"));
        }
        // perform insertion
        auto it = registry.find(key);
        if (registry.end() == it) { // no existing el
            // key reg
            key_registry.push_back(key);
            auto key_it = key_registry.end();
            std::advance(key_it, -1);
            // reg
            auto en = std::make_pair(std::move(value), key_it);
            registry.insert(std::make_pair(key, std::move(en)));
            return sl::json::value();
        } else { // existing el
            auto pa = std::move(*it);
            registry.erase(it);
            auto& prev = pa.second;
            auto en = std::make_pair(std::move(value), prev.second);
            registry.insert(std::make_pair(key, std::move(en)));
            return std::move(prev.first);
        }
    }

    bool remove_entry(const std::string& key) {
        auto it = registry.find(key);
        if (registry.end() == it) { // no existing el
            return false;
        } else { // existing el
            auto pa = std::move(*it);
            auto& prev = pa.second;
            key_registry.erase(prev.second);
            registry.erase(it);
            return true;
        }
    }
    
    uint32_t save_to_file() {
        auto sink = sl::tinydir::file_sink(fpath, sl::tinydir::file_sink::open_mode::create);
        auto bufsink = sl::io::make_buffered_sink(sink);
        auto vec = std::vector<sl::json::field>();
        for (auto& key : key_registry) {
            // always there
            auto it = registry.find(key);
            auto& en = it->second;
            vec.emplace_back(key, en.first.clone());
        }
        auto count = vec.size();
        auto json = sl::json::value(std::move(vec));
        json.dump(bufsink);
        return static_cast<uint32_t>(count);
    }

    void load_from_file() {
        auto src = sl::tinydir::file_source(fpath);
        auto json = sl::json::load(src);
        auto& vec = json.as_object_or_throw(fpath);
        for (auto& fi : vec) {
            put_entry(fi.name(), std::move(fi.val()));
        }
    }
};
PIMPL_FORWARD_CONSTRUCTOR(kvstore, (const std::string&), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, sl::json::value, get, (const std::string&), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, std::vector<sl::json::field>, get_batch, (const std::vector<sl::json::value>&), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, sl::json::value, put, (const std::string&)(sl::json::value), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, std::vector<sl::json::field>, put_batch, (std::vector<sl::json::field>), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, bool, append, (const std::string&)(std::vector<sl::json::value>), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, bool, remove, (const std::string&), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, std::vector<sl::json::value>, remove_batch, (const std::vector<sl::json::value>&), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, uint32_t, size, (), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, std::vector<sl::json::value>, keys, (), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, std::vector<sl::json::field>, entries, (), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, uint32_t, persist, (), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, uint32_t, clear, (), (), support::exception)
PIMPL_FORWARD_METHOD(kvstore, const std::string&, filepath, (), (const), support::exception)

} // namespace
}

