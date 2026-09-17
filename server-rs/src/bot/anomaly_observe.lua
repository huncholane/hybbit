
    local now = tonumber(ARGV[1])
    local results = {}
    for i = 1, #KEYS do
      local key = KEYS[i]
      local base = (i - 1) * 4 + 1
      local kind = ARGV[base + 1]
      local member = ARGV[base + 2]
      local windowMs = tonumber(ARGV[base + 3])
      local maxSize = tonumber(ARGV[base + 4])
      local out = (i - 1) * 3
      if kind == 'h' then
        -- Only admit a new field while under the cap; already-tracked fields keep
        -- counting, so a high-cardinality flood cannot grow the hash without bound.
        if maxSize <= 0 or redis.call('HEXISTS', key, member) == 1 or redis.call('HLEN', key) < maxSize then
          redis.call('HINCRBY', key, member, 1)
        end
        redis.call('PEXPIRE', key, windowMs)
        local total = 0
        local top = 0
        local values = redis.call('HVALS', key)
        for j = 1, #values do
          local value = tonumber(values[j])
          total = total + value
          if value > top then top = value end
        end
        results[out + 1] = total
        results[out + 2] = top
        results[out + 3] = #values
      elseif kind == 'c' then
        -- Plain monotonic counter inside the caller-encoded bucket; member unused.
        results[out + 1] = redis.call('INCR', key)
        redis.call('PEXPIRE', key, windowMs)
        results[out + 2] = 0
        results[out + 3] = 0
      elseif kind == 'p' then
        -- HyperLogLog: an approximate distinct count for dimensions whose true
        -- cardinality can reach tens of thousands (distinct paths, distinct
        -- actors), where a sorted set holding every member would be far too large.
        redis.call('PFADD', key, member)
        redis.call('PEXPIRE', key, windowMs)
        results[out + 1] = redis.call('PFCOUNT', key)
        results[out + 2] = 0
        results[out + 3] = 0
      else
        redis.call('ZADD', key, now, member)
        redis.call('ZREMRANGEBYSCORE', key, '-inf', '(' .. (now - windowMs))
        if maxSize > 0 then
          redis.call('ZREMRANGEBYRANK', key, 0, -maxSize - 1)
        end
        redis.call('PEXPIRE', key, windowMs)
        results[out + 1] = redis.call('ZCARD', key)
        results[out + 2] = 0
        results[out + 3] = 0
      end
    end
    return results
  