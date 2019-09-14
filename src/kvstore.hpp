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
 * File:   kvstore.hpp
 * Author: alex
 *
 * Created on September 12, 2019, 7:19 PM
 */

#ifndef WILTON_KVSTORE_KVSTORE_HPP
#define WILTON_KVSTORE_KVSTORE_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "staticlib/io.hpp"
#include "staticlib/json.hpp"
#include "staticlib/pimpl.hpp"

#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"

namespace wilton {
namespace kvstore {

class kvstore : public sl::pimpl::object {
protected:
    /**
     * implementation class
     */
    class impl;
    
public:
    /**
     * PIMPL-specific constructor
     * 
     * @param pimpl impl object
     */
    PIMPL_CONSTRUCTOR(kvstore)

    kvstore(const std::string& file_path);

    sl::json::value get(const std::string& key);

    std::vector<sl::json::field> get_batch(const std::vector<sl::json::value>& keys);

    sl::json::value put(const std::string& key, sl::json::value value);

    std::vector<sl::json::field> put_batch(std::vector<sl::json::field> entries);

    bool append(const std::string& key, std::vector<sl::json::value> values);

    bool remove(const std::string& key);

    std::vector<sl::json::value> remove_batch(const std::vector<sl::json::value>& keys);

    uint32_t size();

    std::vector<sl::json::value> keys();

    std::vector<sl::json::field> entries();

    uint32_t persist();

    uint32_t clear();

    const std::string& filepath() const;

};

} // namespace
}

#endif /* WILTON_KVSTORE_KVSTORE_HPP */

