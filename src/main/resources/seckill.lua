
local voucherId = ARGV[1]
local userId = ARGV[2]
local orderId = ARGV[3]

local stockKey = "seckill:stock:" .. voucherId
local orderKey = "seckill:order:" .. voucherId

-- 判断库存是否充足（不足，返回 1）
if (tonumber(redis.call('GET', stockKey)) <= 0) then
return 1;
end;

-- 判断用户是否下单（重复下单，返回 2）
if (redis.call('SISMEMBER', orderKey, userId) == 1) then
return 2;
end;

-- 下单成功：扣减库存、保存用户。
redis.call('INCRBY', stockKey, -1);
redis.call('SADD', orderKey, userId);
-- 发送消息到 stream.orders 队列中（*：消息的唯一ID 由 Redis 自动生成）：XADD stream.orders * key field ...
redis.call('XADD', 'stream.orders', '*', 'userId', userId, 'voucherId', voucherId, 'id', orderId);
return 0;