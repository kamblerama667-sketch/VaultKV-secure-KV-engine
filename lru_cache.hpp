#pragma once
// lru_cache.hpp
//
// Textbook O(1) LRU: std::list for recency order (splice is O(1) and
// doesn't invalidate iterators of untouched elements), std::unordered_map
// for O(1) key lookup, storing iterators into the list.
//
// DELIBERATELY NOT THREAD-SAFE ON ITS OWN. An earlier draft gave this its
// own internal mutex, which looks safer but isn't: a caller doing
// "update the source of truth, then update the cache" as two separate
// locked operations leaves a window where a concurrent reader can hit the
// cache and get a stale value, even though each individual operation was
// perfectly synchronized. The fix is for the *caller* to hold one lock
// across both the source-of-truth update and the cache update -- which is
// exactly what SegmentedKVEngine does with its own mutex_. This class
// assumes that discipline and enforces none of it itself.

#include <list>
#include <optional>
#include <unordered_map>
#include <utility>

template <typename K, typename V>
class LRUCache {
public:
    explicit LRUCache(size_t capacity) : capacity_(capacity) {}

    std::optional<V> get(const K& key) {
        auto it = index_.find(key);
        if (it == index_.end()) return std::nullopt;
        items_.splice(items_.begin(), items_, it->second); // move to front (most recently used)
        return it->second->second;
    }

    void put(const K& key, const V& value) {
        auto it = index_.find(key);
        if (it != index_.end()) {
            it->second->second = value;
            items_.splice(items_.begin(), items_, it->second);
            return;
        }
        items_.emplace_front(key, value);
        index_[key] = items_.begin();
        if (items_.size() > capacity_) {
            index_.erase(items_.back().first);
            items_.pop_back();
        }
    }

    void erase(const K& key) {
        auto it = index_.find(key);
        if (it == index_.end()) return;
        items_.erase(it->second);
        index_.erase(it);
    }

    size_t size() const { return items_.size(); }

private:
    size_t capacity_;
    std::list<std::pair<K, V>> items_; // front = most recently used
    std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator> index_;
};
