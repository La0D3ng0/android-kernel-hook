// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace art_hook {  // C++ public API

template <typename Key, typename Value, typename Hash = std::hash<Key>>
class LruCache final {
 public:
  using Destroy = std::function<void(Value&, void*)>;

  explicit LruCache(std::size_t capacity, Destroy destroy = {})
      : capacity_(capacity), destroy_(std::move(destroy)) {
    if (capacity_ == 0) {
      throw std::invalid_argument("LRU capacity must be greater than zero");
    }
  }

  ~LruCache() { Dispose(nullptr); }

  LruCache(const LruCache&) = delete;
  LruCache& operator=(const LruCache&) = delete;

  [[nodiscard]] std::optional<Value> Get(const Key& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = index_.find(key);
    if (found == index_.end()) {
      return std::nullopt;
    }
    items_.splice(items_.end(), items_, found->second);
    return found->second->second;
  }

  void Put(Key key, Value value, void* context = nullptr) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = index_.find(key);
    if (found != index_.end()) {
      DestroyValue(found->second->second, context);
      items_.erase(found->second);
      index_.erase(found);
    } else if (items_.size() == capacity_) {
      auto oldest = items_.begin();
      DestroyValue(oldest->second, context);
      index_.erase(oldest->first);
      items_.erase(oldest);
    }

    items_.emplace_back(std::move(key), std::move(value));
    auto inserted = std::prev(items_.end());
    index_.emplace(inserted->first, inserted);
  }

  void Dispose(void* context = nullptr) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& item : items_) {
      DestroyValue(item.second, context);
    }
    items_.clear();
    index_.clear();
  }

  [[nodiscard]] std::size_t size() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return items_.size();
  }

 private:
  using Item = std::pair<Key, Value>;
  using List = std::list<Item>;

  void DestroyValue(Value& value, void* context) noexcept {
    if (!destroy_) {
      return;
    }
    try {
      destroy_(value, context);
    } catch (...) {
      // Destruction must not unwind through cache replacement or teardown.
    }
  }

  std::size_t capacity_;
  Destroy destroy_;
  List items_;
  std::unordered_map<Key, typename List::iterator, Hash> index_;
  mutable std::mutex mutex_;
};

}  // namespace art_hook
